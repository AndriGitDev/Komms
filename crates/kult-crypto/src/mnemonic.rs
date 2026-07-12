//! BIP-39-style mnemonic encoding of backup-key entropy
//! (docs/07-storage.md §4, docs/06-identity-trust.md §5).
//!
//! 32 bytes of entropy ⇔ 24 English words: the standard BIP-39 mapping
//! (SHA-256 checksum, 11 bits per word) so users can lean on the existing
//! ecosystem of printed recovery-card habits — but the phrase here guards a
//! *backup file*, not a wallet: it feeds Argon2id as the passphrase that
//! seals the export, and is worthless without the file (and vice versa).

use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::wordlist::WORDS;
use crate::{CryptoError, Result};

/// Words in a backup mnemonic (256 bits of entropy + 8 checksum bits).
pub const MNEMONIC_WORDS: usize = 24;

/// Encode 32 bytes of entropy as a 24-word mnemonic phrase
/// (single-space-separated, lowercase).
pub fn mnemonic_from_entropy(entropy: &[u8; 32]) -> Zeroizing<String> {
    // 256 entropy bits ‖ 8 checksum bits (first byte of SHA-256), read as
    // 24 groups of 11 bits, each indexing the wordlist.
    let checksum = Sha256::digest(entropy)[0];
    let mut bits = Zeroizing::new([0u8; 33]);
    bits[..32].copy_from_slice(entropy);
    bits[32] = checksum;

    let mut phrase = Zeroizing::new(String::new());
    for word in 0..MNEMONIC_WORDS {
        let mut index = 0usize;
        for bit in 0..11 {
            let pos = word * 11 + bit;
            let set = (bits[pos / 8] >> (7 - (pos % 8))) & 1;
            index = (index << 1) | usize::from(set);
        }
        if word > 0 {
            phrase.push(' ');
        }
        phrase.push_str(WORDS[index]);
    }
    phrase
}

/// Decode a 24-word mnemonic phrase back to its 32 bytes of entropy.
///
/// Forgiving about presentation (case, extra whitespace/newlines — phrases
/// get read off paper), strict about content: exactly 24 known words whose
/// checksum verifies, or [`CryptoError::InvalidMnemonic`].
pub fn mnemonic_to_entropy(phrase: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut indices: Vec<usize> = Vec::with_capacity(MNEMONIC_WORDS);
    for word in phrase.split_whitespace() {
        let lower = Zeroizing::new(word.to_lowercase());
        let index = WORDS
            .binary_search(&lower.as_str())
            .map_err(|_| CryptoError::InvalidMnemonic)?;
        indices.push(index);
    }
    if indices.len() != MNEMONIC_WORDS {
        return Err(CryptoError::InvalidMnemonic);
    }

    let mut bits = Zeroizing::new([0u8; 33]);
    for (word, index) in indices.iter().enumerate() {
        for bit in 0..11 {
            if (index >> (10 - bit)) & 1 == 1 {
                let pos = word * 11 + bit;
                bits[pos / 8] |= 1 << (7 - (pos % 8));
            }
        }
    }
    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy.copy_from_slice(&bits[..32]);
    if Sha256::digest(&entropy[..])[0] != bits[32] {
        return Err(CryptoError::InvalidMnemonic);
    }
    Ok(entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_sorted_and_unique() {
        // binary_search in decode depends on this.
        assert!(WORDS.windows(2).all(|w| w[0] < w[1]));
    }
}
