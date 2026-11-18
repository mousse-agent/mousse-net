//! Experimental: the X25519MLKEM768 hybrid group from pure-Rust parts
//! (`ml-kem` and `x25519-dalek`), so providers without it (ring, rustcrypto)
//! can negotiate the same hybrid group as aws-lc-rs, including on wasm32.
//!
//! Wire format (draft-ietf-tls-ecdhe-mlkem): the client share is the ML-KEM-768
//! encapsulation key (1184 bytes) followed by an X25519 public key (32 bytes).
//! The server share is the ML-KEM ciphertext (1088 bytes) followed by an X25519
//! public key. The shared secret is the ML-KEM secret followed by the X25519
//! secret. The client also offers its X25519 half on its own, so a classical
//! server can pick X25519 without a retry.

use ml_kem::array::Array;
use ml_kem::{Decapsulate, Encapsulate, EncapsulationKey, Kem, KeyExport, MlKem768};
use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};
use x25519_dalek::{PublicKey, StaticSecret};

const EK_LEN: usize = 1184;
const CT_LEN: usize = 1088;
const X_LEN: usize = 32;

/// The hybrid group. Add it first in a provider's `kx_groups`.
pub static X25519MLKEM768: &dyn SupportedKxGroup = &HybridGroup;

#[derive(Debug)]
struct HybridGroup;

fn x25519_secret() -> Result<StaticSecret, Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::FailedToGetRandomBytes)?;
    let secret = StaticSecret::from(bytes);
    bytes.fill(0);
    Ok(secret)
}

fn x25519_shared(secret: &StaticSecret, peer: &[u8]) -> Result<[u8; 32], Error> {
    let peer: [u8; 32] = peer
        .try_into()
        .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
    let shared = secret.diffie_hellman(&PublicKey::from(peer));
    if !shared.was_contributory() {
        return Err(PeerMisbehaved::InvalidKeyShare.into());
    }
    Ok(shared.to_bytes())
}

fn join_secret(mlkem: &[u8], x: &[u8; 32]) -> SharedSecret {
    let mut buf = Vec::with_capacity(mlkem.len() + X_LEN);
    buf.extend_from_slice(mlkem);
    buf.extend_from_slice(x);
    let secret = SharedSecret::from(&buf[..]);
    buf.fill(0);
    secret
}

impl SupportedKxGroup for HybridGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let (dk, ek) = MlKem768::generate_keypair();
        let x = x25519_secret()?;
        let mut share = Vec::with_capacity(EK_LEN + X_LEN);
        share.extend_from_slice(&ek.to_bytes());
        share.extend_from_slice(PublicKey::from(&x).as_bytes());
        Ok(Box::new(ClientHalf { dk, x, share }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != EK_LEN + X_LEN {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let (ek_bytes, x_peer) = client_share.split_at(EK_LEN);
        let ek_array =
            Array::try_from(ek_bytes).map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        // `new` runs the FIPS 203 encapsulation-key check.
        let ek = EncapsulationKey::<MlKem768>::new(&ek_array)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let (ct, mlkem_secret) = ek.encapsulate();
        let x = x25519_secret()?;
        let x_secret = x25519_shared(&x, x_peer)?;

        let mut pub_key = Vec::with_capacity(CT_LEN + X_LEN);
        pub_key.extend_from_slice(&ct);
        pub_key.extend_from_slice(PublicKey::from(&x).as_bytes());
        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key,
            secret: join_secret(&mlkem_secret, &x_secret),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct ClientHalf {
    dk: ml_kem::DecapsulationKey<MlKem768>,
    x: StaticSecret,
    share: Vec<u8>,
}

impl ActiveKeyExchange for ClientHalf {
    fn complete(self: Box<Self>, server_share: &[u8]) -> Result<SharedSecret, Error> {
        if server_share.len() != CT_LEN + X_LEN {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let (ct, x_peer) = server_share.split_at(CT_LEN);
        let mlkem_secret = self
            .dk
            .decapsulate_slice(ct)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let x_secret = x25519_shared(&self.x, x_peer)?;
        Ok(join_secret(&mlkem_secret, &x_secret))
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::X25519, &self.share[EK_LEN..]))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        server_share: &[u8],
    ) -> Result<SharedSecret, Error> {
        let x_secret = x25519_shared(&self.x, server_share)?;
        Ok(SharedSecret::from(&x_secret[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

/// `base` with the hybrid group put first.
pub fn with_hybrid(mut base: CryptoProvider) -> CryptoProvider {
    base.kx_groups.insert(0, X25519MLKEM768);
    base
}
