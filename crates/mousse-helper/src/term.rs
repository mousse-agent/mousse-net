//! Terminal channels: a PTY on the host, its bytes over one interactive
//! stream labelled `terminal`.
//!
//! Frames on the stream are `[type u8][length u32 BE][payload]`:
//!
//! - 1 OPEN, caller to host, first frame: cols u16, rows u16, then the
//!   command as NUL-separated arguments (empty: the host user's shell).
//! - 2 DATA, both ways: terminal bytes.
//! - 3 RESIZE, caller to host: cols u16, rows u16.
//! - 4 EXIT, host to caller: the exit code (i32). The host finishes the
//!   stream after it.
//!
//! The command is killed and the PTY closed when the stream or its
//! connection goes away, for example when the host removes the caller's
//! grant, even if the caller already finished sending and the command is
//! silent.

use std::io::{IsTerminal, Read, Write};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::time::Duration;

use mousse_net_core::mux::PriorityClass;
use mousse_net_core::ErrorCode;
use mousse_net_io::{Connection, MuxStream, NetError};
use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

/// The stream label for terminal channels.
pub const LABEL: &str = "terminal";

const MAX_FRAME: usize = 1 << 20;
const OPEN: u8 = 1;
const DATA: u8 = 2;
const RESIZE: u8 = 3;
const EXIT: u8 = 4;

/// One terminal frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// Start the PTY.
    Open {
        cols: u16,
        rows: u16,
        argv: Vec<String>,
    },
    /// Terminal bytes.
    Data(Vec<u8>),
    /// New window size.
    Resize { cols: u16, rows: u16 },
    /// The command ended.
    Exit(i32),
}

impl Frame {
    /// The frame's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let (kind, payload) = match self {
            Frame::Open { cols, rows, argv } => {
                let mut p = Vec::new();
                p.extend_from_slice(&cols.to_be_bytes());
                p.extend_from_slice(&rows.to_be_bytes());
                p.extend_from_slice(argv.join("\0").as_bytes());
                (OPEN, p)
            }
            Frame::Data(bytes) => (DATA, bytes.clone()),
            Frame::Resize { cols, rows } => {
                let mut p = Vec::new();
                p.extend_from_slice(&cols.to_be_bytes());
                p.extend_from_slice(&rows.to_be_bytes());
                (RESIZE, p)
            }
            Frame::Exit(code) => (EXIT, code.to_be_bytes().to_vec()),
        };
        let mut out = Vec::with_capacity(5 + payload.len());
        out.push(kind);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }
}

fn size_pair(p: &[u8]) -> Result<(u16, u16), String> {
    if p.len() < 4 {
        return Err("short size".into());
    }
    Ok((
        u16::from_be_bytes([p[0], p[1]]),
        u16::from_be_bytes([p[2], p[3]]),
    ))
}

/// Splits stream bytes into frames.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    /// Add received bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next complete frame, if any.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, String> {
        if self.buf.len() < 5 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
        if len > MAX_FRAME {
            return Err("terminal frame too large".into());
        }
        if self.buf.len() < 5 + len {
            return Ok(None);
        }
        let kind = self.buf[0];
        let payload: Vec<u8> = self.buf[5..5 + len].to_vec();
        self.buf.drain(..5 + len);
        let frame = match kind {
            OPEN => {
                let (cols, rows) = size_pair(&payload)?;
                let text = std::str::from_utf8(&payload[4..])
                    .map_err(|_| "command is not UTF-8".to_string())?;
                let argv = if text.is_empty() {
                    Vec::new()
                } else {
                    text.split('\0').map(str::to_owned).collect()
                };
                Frame::Open { cols, rows, argv }
            }
            DATA => Frame::Data(payload),
            RESIZE => {
                let (cols, rows) = size_pair(&payload)?;
                Frame::Resize { cols, rows }
            }
            EXIT => {
                let bytes: [u8; 4] = payload
                    .as_slice()
                    .try_into()
                    .map_err(|_| "bad exit frame".to_string())?;
                Frame::Exit(i32::from_be_bytes(bytes))
            }
            other => return Err(format!("unknown terminal frame {other}")),
        };
        Ok(Some(frame))
    }
}

/// A size or count limit as a `usize`.
fn read_size(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

fn pty_size(cols: u16, rows: u16) -> PtySize {
    // `TERM_MAX_DIMENSION`, at most 4 000, so it fits.
    let max = u16::try_from(crate::limits::helper().term_max_dimension).unwrap_or(u16::MAX);
    PtySize {
        rows: rows.clamp(1, max),
        cols: cols.clamp(1, max),
        pixel_width: 0,
        pixel_height: 0,
    }
}

enum Out {
    Data(Vec<u8>),
    Eof,
    Exited(i32),
}

/// ConPTY asks the terminal for the cursor position once at start
/// (`ESC [ 6 n`) and waits for the answer. Answer that first request here,
/// so a caller without a real terminal (a script, a pipe) does not hang.
const CURSOR_QUERY: &[u8] = b"\x1b[6n";
const CURSOR_ANSWER: &[u8] = b"\x1b[1;1R";

fn take_first_cursor_query(chunk: &mut Vec<u8>) -> bool {
    if let Some(at) = chunk
        .windows(CURSOR_QUERY.len())
        .position(|w| w == CURSOR_QUERY)
    {
        chunk.drain(at..at + CURSOR_QUERY.len());
        return true;
    }
    false
}

type SharedMaster = Arc<Mutex<Option<Box<dyn MasterPty + Send>>>>;

struct Pty {
    master: SharedMaster,
    input: std_mpsc::Sender<Vec<u8>>,
    killer: Box<dyn ChildKiller + Send + Sync>,
}

fn spawn_pty(cols: u16, rows: u16, argv: &[String], out: mpsc::Sender<Out>) -> Result<Pty, String> {
    let pair = native_pty_system()
        .openpty(pty_size(cols, rows))
        .map_err(|e| e.to_string())?;
    let mut cmd = match argv.split_first() {
        None => CommandBuilder::new_default_prog(),
        Some((prog, args)) => {
            let mut c = CommandBuilder::new(prog);
            c.args(args);
            c
        }
    };
    if let Some(home) = home_dir() {
        cmd.cwd(home);
    }
    let mut child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    drop(pair.slave);
    let killer = child.clone_killer();
    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let mut writer = pair.master.take_writer().map_err(|e| e.to_string())?;
    let master: SharedMaster = Arc::new(Mutex::new(Some(pair.master)));

    let (input, input_rx) = std_mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(bytes) = input_rx.recv() {
            if writer
                .write_all(&bytes)
                .and_then(|_| writer.flush())
                .is_err()
            {
                return;
            }
        }
    });

    let answer = input.clone();
    let out_reader = out.clone();
    std::thread::spawn(move || {
        let mut answered = !cfg!(windows);
        let mut buf = vec![0u8; read_size(crate::limits::helper().term_pty_read_bytes)];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut chunk = buf[..n].to_vec();
                    if !answered && take_first_cursor_query(&mut chunk) {
                        answered = true;
                        let _ = answer.send(CURSOR_ANSWER.to_vec());
                    }
                    if !chunk.is_empty() && out_reader.blocking_send(Out::Data(chunk)).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = out_reader.blocking_send(Out::Eof);
    });

    std::thread::spawn(move || {
        let code = match child.wait() {
            Ok(status) => status.exit_code() as i32,
            Err(_) => -1,
        };
        let _ = out.blocking_send(Out::Exited(code));
    });

    Ok(Pty {
        master,
        input,
        killer,
    })
}

fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(Into::into)
}

/// Close the PTY. On Windows this ends the reader; it can block until the
/// output is drained, so it runs off the async threads.
fn close_master(master: &SharedMaster) {
    let master = master.clone();
    tokio::task::spawn_blocking(move || {
        if let Ok(mut slot) = master.lock() {
            slot.take();
        }
    });
}

async fn read_open(stream: &mut MuxStream, dec: &mut Decoder) -> Option<Frame> {
    loop {
        match dec.next_frame() {
            Ok(Some(frame)) => return Some(frame),
            Ok(None) => {}
            Err(_) => return None,
        }
        match stream.reader.read().await {
            Ok(Some(bytes)) => dec.push(&bytes),
            _ => return None,
        }
    }
}

/// Host side: run one terminal channel to the end.
pub async fn serve(mut stream: MuxStream) {
    let mut dec = Decoder::default();
    let Some(Frame::Open { cols, rows, argv }) = read_open(&mut stream, &mut dec).await else {
        stream.writer.reset(ErrorCode::ProtocolError);
        return;
    };
    let (mut rd, wr) = stream.split();
    let (out_tx, mut out_rx) =
        mpsc::channel::<Out>(read_size(crate::limits::helper().term_output_queue));
    let pty = match spawn_pty(cols, rows, &argv, out_tx) {
        Ok(pty) => pty,
        Err(e) => {
            let msg = format!("cannot start the command: {e}\r\n");
            let _ = wr.write(&Frame::Data(msg.into_bytes()).encode()).await;
            let _ = wr.write(&Frame::Exit(127).encode()).await;
            wr.finish();
            return;
        }
    };
    let Pty {
        master,
        input,
        mut killer,
    } = pty;

    let mut exit_code: Option<i32> = None;
    let mut reader_done = false;
    let mut input_open = true;
    let mut grace: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
    loop {
        tokio::select! {
            out = out_rx.recv() => match out {
                Some(Out::Data(bytes)) => {
                    if wr.write(&Frame::Data(bytes).encode()).await.is_err() {
                        let _ = killer.kill();
                        break;
                    }
                }
                Some(Out::Eof) | None => {
                    reader_done = true;
                    if let Some(code) = exit_code {
                        let _ = wr.write(&Frame::Exit(code).encode()).await;
                        wr.finish();
                        break;
                    }
                }
                Some(Out::Exited(code)) => {
                    exit_code = Some(code);
                    if reader_done {
                        let _ = wr.write(&Frame::Exit(code).encode()).await;
                        wr.finish();
                        break;
                    }
                    // Let the last output through, then close the PTY so
                    // the reader ends; send EXIT even if it never does.
                    let limits = crate::limits::helper();
                    close_master_after(&master, crate::limits::ms(limits.term_close_delay_ms));
                    grace = Some(Box::pin(tokio::time::sleep(crate::limits::ms(
                        limits.term_exit_grace_ms,
                    ))));
                }
            },
            input_bytes = rd.read(), if input_open => match input_bytes {
                Ok(Some(bytes)) => {
                    dec.push(&bytes);
                    loop {
                        match dec.next_frame() {
                            Ok(Some(Frame::Data(data))) => {
                                let _ = input.send(data);
                            }
                            Ok(Some(Frame::Resize { cols, rows })) => {
                                if let Ok(slot) = master.lock() {
                                    if let Some(m) = slot.as_ref() {
                                        let _ = m.resize(pty_size(cols, rows));
                                    }
                                }
                            }
                            Ok(Some(_)) | Err(_) => {
                                let _ = killer.kill();
                                wr.reset(ErrorCode::ProtocolError);
                                close_master(&master);
                                return;
                            }
                            Ok(None) => break,
                        }
                    }
                }
                // The caller finished its side: no more input.
                Ok(None) => input_open = false,
                // Reset, or the connection closed (for example the grant
                // was removed): end the command.
                Err(_) => {
                    let _ = killer.kill();
                    close_master(&master);
                    return;
                }
            },
            // Access ended (grant removed or expired, connection closed):
            // end the command now. Reading alone would miss this once the
            // caller has finished its side of the stream.
            () = wr.closing() => {
                let _ = killer.kill();
                close_master(&master);
                return;
            }
            () = async { match grace.as_mut() { Some(s) => s.await, None => std::future::pending().await } } => {
                let code = exit_code.unwrap_or(-1);
                let _ = wr.write(&Frame::Exit(code).encode()).await;
                wr.finish();
                break;
            }
        }
    }
    close_master(&master);
}

fn close_master_after(master: &SharedMaster, delay: Duration) {
    let master = master.clone();
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        close_master(&master);
    });
}

/// How a caller-side terminal ended.
#[derive(Debug)]
pub enum ClientEnd {
    /// The command exited with this code.
    Exited(i32),
    /// The channel or connection closed first.
    Closed(NetError),
}

struct RawMode(bool);

impl RawMode {
    fn enable(on: bool) -> Self {
        Self(on && crossterm::terminal::enable_raw_mode().is_ok())
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if self.0 {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

/// Caller side: open a terminal on `conn` running `argv` (empty: the
/// host's shell), wire it to this process's stdin and stdout, and return
/// how it ended. Raw mode and resizes apply when stdin and stdout are a
/// terminal and no command was given.
pub async fn run_client(conn: &Connection, argv: Vec<String>) -> Result<ClientEnd, NetError> {
    let interactive =
        argv.is_empty() && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let (cols, rows) = if std::io::stdout().is_terminal() {
        crossterm::terminal::size().unwrap_or((80, 24))
    } else {
        (80, 24)
    };
    let stream = conn.open_stream(PriorityClass::Interactive, LABEL).await?;
    let (mut rd, wr) = stream.split();
    wr.write(&Frame::Open { cols, rows, argv }.encode()).await?;
    let _raw = RawMode::enable(interactive);

    let stdin_wr = wr.clone();
    let stdin_task = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; read_size(crate::limits::helper().term_stdin_read_bytes)];
        loop {
            match stdin.read(&mut buf).await {
                // No more input: finish our side; the command keeps running.
                Ok(0) => {
                    stdin_wr.finish();
                    return;
                }
                Err(_) => return,
                Ok(n) => {
                    if stdin_wr
                        .write(&Frame::Data(buf[..n].to_vec()).encode())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    });
    let resize_task = interactive.then(|| {
        let wr = wr.clone();
        tokio::spawn(async move {
            let mut last = (cols, rows);
            let poll = crate::limits::ms(crate::limits::helper().term_resize_poll_ms);
            loop {
                tokio::time::sleep(poll).await;
                if let Ok(now) = crossterm::terminal::size() {
                    if now != last {
                        last = now;
                        let frame = Frame::Resize {
                            cols: now.0,
                            rows: now.1,
                        };
                        if wr.write(&frame.encode()).await.is_err() {
                            return;
                        }
                    }
                }
            }
        })
    });

    let mut dec = Decoder::default();
    let mut stdout = std::io::stdout();
    let end = 'outer: loop {
        match rd.read().await {
            Ok(Some(bytes)) => {
                dec.push(&bytes);
                loop {
                    match dec.next_frame() {
                        Ok(Some(Frame::Data(data))) => {
                            let _ = stdout.write_all(&data);
                            let _ = stdout.flush();
                        }
                        Ok(Some(Frame::Exit(code))) => break 'outer ClientEnd::Exited(code),
                        Ok(Some(_)) | Err(_) => {
                            wr.reset(ErrorCode::ProtocolError);
                            break 'outer ClientEnd::Closed(NetError::Refused(
                                "bad terminal frame from the host".into(),
                            ));
                        }
                        Ok(None) => break,
                    }
                }
            }
            Ok(None) => break ClientEnd::Exited(-1),
            Err(e) => break ClientEnd::Closed(e),
        }
    };
    stdin_task.abort();
    if let Some(t) = resize_task {
        t.abort();
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_split_anywhere() {
        let frames = vec![
            Frame::Open {
                cols: 120,
                rows: 40,
                argv: vec!["uname".into(), "-a".into()],
            },
            Frame::Open {
                cols: 80,
                rows: 24,
                argv: vec![],
            },
            Frame::Data(b"ls\r".to_vec()),
            Frame::Resize { cols: 1, rows: 2 },
            Frame::Exit(-3),
        ];
        let bytes: Vec<u8> = frames.iter().flat_map(Frame::encode).collect();
        let mut dec = Decoder::default();
        let mut got = Vec::new();
        for b in bytes {
            dec.push(&[b]);
            while let Some(f) = dec.next_frame().unwrap() {
                got.push(f);
            }
        }
        assert_eq!(got, frames);
    }

    #[test]
    fn bad_frames_are_refused() {
        let mut dec = Decoder::default();
        dec.push(&[9, 0, 0, 0, 0]);
        assert!(dec.next_frame().is_err());
        let mut dec = Decoder::default();
        dec.push(&[DATA, 0xff, 0xff, 0xff, 0xff]);
        assert!(dec.next_frame().is_err());
        let mut dec = Decoder::default();
        dec.push(&[EXIT, 0, 0, 0, 1, 0]);
        assert!(dec.next_frame().is_err());
    }

    #[test]
    fn only_the_cursor_query_is_taken_out() {
        let mut chunk = b"a\x1b[6nb".to_vec();
        assert!(take_first_cursor_query(&mut chunk));
        assert_eq!(chunk, b"ab");
        let mut plain = b"no query".to_vec();
        assert!(!take_first_cursor_query(&mut plain));
    }
}
