//! This device's prekey secrets: one signed prekey, one PQ signed prekey,
//! and a rolling set of one-time prekeys. Serialized by the runtime and
//! sealed at rest by `kult-store` (which treats the blob as opaque).

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use kult_crypto::{OneTimePrekeySecret, PqPrekeySecret, SignedPrekeySecret};
use rand_core::CryptoRngCore;

use crate::{NodeError, Result};

/// Retain at most this many unconsumed one-time prekeys (oldest dropped
/// first — a dropped OPK only means that particular handshake bundle can no
/// longer be answered).
const MAX_OPKS: usize = 32;

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Opk {
    id: u32,
    secret: [u8; 32],
}

/// All prekey secrets this device can answer handshakes with.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct PrekeyVault {
    pub spk_id: u32,
    spk: [u8; 32],
    pub pqspk_id: u32,
    pq_dk: Vec<u8>,
    pq_ek: Vec<u8>,
    opks: Vec<Opk>,
    next_opk_id: u32,
}

impl PrekeyVault {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let spk = SignedPrekeySecret::generate(rng, 1);
        let pqspk = PqPrekeySecret::generate(rng, 1);
        Self {
            spk_id: 1,
            spk: *spk.to_bytes(),
            pqspk_id: 1,
            pq_dk: pqspk.to_bytes().to_vec(),
            pq_ek: pqspk.public().to_vec(),
            opks: Vec::new(),
            next_opk_id: 1,
        }
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(postcard::to_allocvec(self).expect("vault serialization cannot fail"))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).map_err(|_| NodeError::CorruptState)
    }

    pub fn spk(&self) -> SignedPrekeySecret {
        SignedPrekeySecret::from_bytes(self.spk_id, &self.spk)
    }

    pub fn pqspk(&self) -> Result<PqPrekeySecret> {
        PqPrekeySecret::from_bytes(self.pqspk_id, &self.pq_dk, &self.pq_ek)
            .map_err(|_| NodeError::CorruptState)
    }

    /// Mint a fresh one-time prekey and remember its secret.
    pub fn fresh_opk(&mut self, rng: &mut impl CryptoRngCore) -> OneTimePrekeySecret {
        let id = self.next_opk_id;
        self.next_opk_id = self.next_opk_id.wrapping_add(1);
        let opk = OneTimePrekeySecret::generate(rng, id);
        self.opks.push(Opk {
            id,
            secret: *opk.to_bytes(),
        });
        if self.opks.len() > MAX_OPKS {
            self.opks.remove(0);
        }
        opk
    }

    /// Look up a stored one-time prekey by id (not yet consumed).
    pub fn opk(&self, id: u32) -> Option<OneTimePrekeySecret> {
        self.opks
            .iter()
            .find(|o| o.id == id)
            .map(|o| OneTimePrekeySecret::from_bytes(o.id, &o.secret))
    }

    /// Delete a consumed one-time prekey (forward secrecy for the first
    /// flight: once used, the secret must not survive).
    pub fn remove_opk(&mut self, id: u32) {
        self.opks.retain(|o| o.id != id);
    }
}
