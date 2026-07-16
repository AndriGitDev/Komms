//! Private local contact-name validation, normalization, and spoofing review.
//!
//! Petnames are display metadata only. They are never identifiers and never
//! leave the sealed local store. Mutations continue to target the peer's
//! Ed25519 identity bytes, so duplicate or visually similar names cannot
//! redirect an operation.

use std::collections::BTreeSet;

use kult_store::ContactRecord;
use unicode_normalization::{char::canonical_combining_class, UnicodeNormalization};

use crate::{NodeError, Result};

/// Maximum canonical UTF-8 byte length of one local contact petname.
pub const MAX_CONTACT_NAME_BYTES: usize = 256;

/// One non-blocking risk that must be shown before a rename is confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContactNameWarning {
    /// Another stored contact already has the same NFC-normalized petname.
    DuplicateName,
    /// Mixed Latin/Greek/Cyrillic text or a local skeleton collision may be deceptive.
    ConfusableName,
    /// Directional formatting controls can make displayed order misleading.
    BidirectionalControl,
    /// Invisible formatting characters can make distinct names look identical.
    InvisibleCharacter,
}

/// Canonical proposed petname plus every deterministic local warning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactNameAssessment {
    /// NFC-normalized value that will be stored if the rename is accepted.
    pub normalized_name: String,
    /// Whether NFC normalization changed the exact proposed scalar sequence.
    pub changed_by_normalization: bool,
    /// Ordered, de-duplicated warnings. Warnings never make a name unique.
    pub warnings: Vec<ContactNameWarning>,
    /// Other contacts with the exact same canonical petname.
    pub duplicate_count: u32,
}

/// Validate and NFC-normalize a local petname.
pub(crate) fn normalize_contact_name(name: &str) -> Result<String> {
    let normalized: String = name.nfc().collect();
    if normalized.is_empty()
        || normalized.len() > MAX_CONTACT_NAME_BYTES
        || normalized.chars().all(char::is_whitespace)
        || normalized.chars().any(char::is_control)
    {
        return Err(NodeError::InvalidContactName);
    }
    Ok(normalized)
}

pub(crate) fn assess_contact_name(
    target: &[u8; 32],
    proposed: &str,
    contacts: &[ContactRecord],
) -> Result<ContactNameAssessment> {
    let normalized_name = normalize_contact_name(proposed)?;
    let changed_by_normalization = normalized_name != proposed;
    let proposed_skeleton = confusable_skeleton(&normalized_name);
    let mut duplicate_count = 0u32;
    let mut skeleton_collision = false;

    for contact in contacts.iter().filter(|contact| &contact.peer != target) {
        let Ok(existing) = normalize_contact_name(&contact.name) else {
            continue;
        };
        if existing == normalized_name {
            duplicate_count = duplicate_count.saturating_add(1);
        } else if !proposed_skeleton.is_empty()
            && proposed_skeleton == confusable_skeleton(&existing)
        {
            skeleton_collision = true;
        }
    }

    let mut warnings = BTreeSet::new();
    if duplicate_count > 0 {
        warnings.insert(ContactNameWarning::DuplicateName);
    }
    if skeleton_collision || mixes_confusable_scripts(&normalized_name) {
        warnings.insert(ContactNameWarning::ConfusableName);
    }
    if normalized_name.chars().any(is_bidi_control) {
        warnings.insert(ContactNameWarning::BidirectionalControl);
    }
    if normalized_name.chars().any(is_invisible_format) {
        warnings.insert(ContactNameWarning::InvisibleCharacter);
    }

    Ok(ContactNameAssessment {
        normalized_name,
        changed_by_normalization,
        warnings: warnings.into_iter().collect(),
        duplicate_count,
    })
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ConfusableScript {
    Latin,
    Greek,
    Cyrillic,
}

fn mixes_confusable_scripts(name: &str) -> bool {
    name.chars()
        .filter_map(confusable_script)
        .collect::<BTreeSet<_>>()
        .len()
        > 1
}

fn confusable_script(value: char) -> Option<ConfusableScript> {
    let code = value as u32;
    if value.is_ascii_alphabetic()
        || matches!(code, 0x00c0..=0x024f | 0x1e00..=0x1eff | 0xab30..=0xab6f)
    {
        Some(ConfusableScript::Latin)
    } else if matches!(code, 0x0370..=0x03ff | 0x1f00..=0x1fff) {
        Some(ConfusableScript::Greek)
    } else if matches!(code, 0x0400..=0x052f | 0x2de0..=0x2dff | 0xa640..=0xa69f) {
        Some(ConfusableScript::Cyrillic)
    } else {
        None
    }
}

/// A deliberately conservative local collision key, not a username system.
/// It catches common Greek/Cyrillic lookalikes and canonical accents without
/// claiming complete UTS #39 coverage.
fn confusable_skeleton(name: &str) -> String {
    name.nfkd()
        .filter(|value| canonical_combining_class(*value) == 0)
        .flat_map(char::to_lowercase)
        .map(|value| match value {
            // Greek lookalikes.
            'α' => 'a',
            'β' => 'b',
            'ε' => 'e',
            'ι' => 'i',
            'κ' => 'k',
            'ο' => 'o',
            'ρ' => 'p',
            'τ' => 't',
            'υ' => 'y',
            'χ' => 'x',
            // Cyrillic lookalikes.
            'а' => 'a',
            'в' => 'b',
            'е' => 'e',
            'к' => 'k',
            'м' => 'm',
            'н' => 'h',
            'о' => 'o',
            'р' => 'p',
            'с' => 'c',
            'т' => 't',
            'у' => 'y',
            'х' => 'x',
            'і' => 'i',
            'ј' => 'j',
            value => value,
        })
        .filter(|value| {
            !value.is_whitespace() && !is_bidi_control(*value) && !is_invisible_format(*value)
        })
        .collect()
}

fn is_bidi_control(value: char) -> bool {
    matches!(
        value,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn is_invisible_format(value: char) -> bool {
    matches!(
        value,
        '\u{00ad}' | '\u{034f}' | '\u{200b}'..='\u{200d}' | '\u{2060}' | '\u{feff}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(peer: u8, name: &str) -> ContactRecord {
        ContactRecord {
            peer: [peer; 32],
            identity: Vec::new(),
            name: name.to_owned(),
            bundle: Vec::new(),
            hints: Vec::new(),
            verified: false,
        }
    }

    #[test]
    fn assessment_normalizes_allows_duplicates_and_warns_about_spoofing() {
        let contacts = vec![contact(1, "Café"), contact(2, "paypal")];
        let duplicate = assess_contact_name(&[9; 32], "Cafe\u{301}", &contacts).unwrap();
        assert_eq!(duplicate.normalized_name, "Café");
        assert!(duplicate.changed_by_normalization);
        assert_eq!(duplicate.duplicate_count, 1);
        assert_eq!(duplicate.warnings, vec![ContactNameWarning::DuplicateName]);

        let spoof = assess_contact_name(&[9; 32], "pаypal\u{2069}", &contacts).unwrap();
        assert!(spoof.warnings.contains(&ContactNameWarning::ConfusableName));
        assert!(spoof
            .warnings
            .contains(&ContactNameWarning::BidirectionalControl));
    }

    #[test]
    fn invalid_names_fail_closed() {
        assert!(normalize_contact_name("").is_err());
        assert!(normalize_contact_name("\n\t").is_err());
        assert!(normalize_contact_name(&"x".repeat(MAX_CONTACT_NAME_BYTES + 1)).is_err());
    }
}
