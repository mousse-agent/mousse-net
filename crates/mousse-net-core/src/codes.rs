//! Wire error codes, carried in `RESET`, `GOAWAY` and `CODE_ABORT`.

/// A 16-bit error code. Values are fixed by the wire spec; never renumber.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ErrorCode {
    /// Normal close.
    NoError = 0,
    /// The peer broke a framing or message rule.
    ProtocolError = 1,
    /// A frame's length is above the limit.
    FrameTooLarge = 2,
    /// The peer sent more stream data than its credit allowed.
    FlowControl = 3,
    /// Data arrived for a stream that is already finished.
    StreamClosed = 4,
    /// Nothing was received for the idle timeout (45 s).
    IdleTimeout = 5,
    /// Step 2 found no live grant and no valid ticket proof, or the traffic
    /// is not allowed in the connection's state.
    NotAuthorized = 6,
    /// The grant that authorized this connection was removed, expired or
    /// overridden by a local denial.
    GrantRevoked = 7,
    /// The session reached its effective certificate deadline.
    CertExpired = 8,
    /// No common protocol version.
    UnsupportedVersion = 9,
    /// A code exchange attempt failed (wrong code or bad confirmation).
    PairingFailed = 10,
    /// The invitation is unknown, expired, consumed or cancelled, or the
    /// ticket proof is wrong. One code for all of these, on purpose.
    InvitationInvalid = 11,
    /// The attempt limit is used up; the invitation or code-entry flow ends.
    AttemptsExhausted = 12,
    /// The host owner declined an in-person request.
    PairingDeclined = 13,
    /// A newer path replaced this connection (path switch).
    PathReplaced = 14,
    /// The peer refused a new stream (too many open streams).
    RefusedStream = 15,
    /// The stream or operation was cancelled locally.
    Cancelled = 16,
    /// An internal failure on the sender.
    InternalError = 17,
}

impl ErrorCode {
    /// All codes, in numeric order.
    pub const ALL: [ErrorCode; 18] = [
        ErrorCode::NoError,
        ErrorCode::ProtocolError,
        ErrorCode::FrameTooLarge,
        ErrorCode::FlowControl,
        ErrorCode::StreamClosed,
        ErrorCode::IdleTimeout,
        ErrorCode::NotAuthorized,
        ErrorCode::GrantRevoked,
        ErrorCode::CertExpired,
        ErrorCode::UnsupportedVersion,
        ErrorCode::PairingFailed,
        ErrorCode::InvitationInvalid,
        ErrorCode::AttemptsExhausted,
        ErrorCode::PairingDeclined,
        ErrorCode::PathReplaced,
        ErrorCode::RefusedStream,
        ErrorCode::Cancelled,
        ErrorCode::InternalError,
    ];

    /// The numeric wire value.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Parse a wire value. Unknown values map to `None`; receivers treat an
    /// unknown code like [`ErrorCode::ProtocolError`] for display only.
    pub fn from_u16(value: u16) -> Option<Self> {
        Self::ALL.get(usize::from(value)).copied()
    }

    /// Stable snake_case name, used in test vectors and logs.
    pub const fn name(self) -> &'static str {
        match self {
            ErrorCode::NoError => "no_error",
            ErrorCode::ProtocolError => "protocol_error",
            ErrorCode::FrameTooLarge => "frame_too_large",
            ErrorCode::FlowControl => "flow_control",
            ErrorCode::StreamClosed => "stream_closed",
            ErrorCode::IdleTimeout => "idle_timeout",
            ErrorCode::NotAuthorized => "not_authorized",
            ErrorCode::GrantRevoked => "grant_revoked",
            ErrorCode::CertExpired => "cert_expired",
            ErrorCode::UnsupportedVersion => "unsupported_version",
            ErrorCode::PairingFailed => "pairing_failed",
            ErrorCode::InvitationInvalid => "invitation_invalid",
            ErrorCode::AttemptsExhausted => "attempts_exhausted",
            ErrorCode::PairingDeclined => "pairing_declined",
            ErrorCode::PathReplaced => "path_replaced",
            ErrorCode::RefusedStream => "refused_stream",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::InternalError => "internal_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_and_match_their_index() {
        for (index, code) in ErrorCode::ALL.iter().enumerate() {
            assert_eq!(usize::from(code.as_u16()), index);
            assert_eq!(ErrorCode::from_u16(code.as_u16()), Some(*code));
        }
        assert_eq!(ErrorCode::from_u16(18), None);
    }
}
