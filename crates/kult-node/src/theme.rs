//! B12 private appearance preference over the accepted F5 sealed metadata.
//!
//! Resolution of System and semantic colors belongs to native shells. These
//! methods only own the canonical durable choice and a local change signal.

use rand_core::CryptoRngCore;

use crate::{Event, Node, Result, ThemePreference};

impl Node {
    /// Read the sealed choice, safely defaulting missing/legacy data to System.
    pub fn theme_preference(&self) -> Result<ThemePreference> {
        Ok(self.store.theme_preference()?.unwrap_or_default())
    }

    /// Whether an exact canonical choice exists in the sealed store.
    pub fn theme_preference_is_persisted(&self) -> Result<bool> {
        Ok(self.store.theme_preference()?.is_some())
    }

    /// Idempotently persist a canonical choice and emit one local event.
    pub fn set_theme_preference(
        &mut self,
        preference: ThemePreference,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let changed = self.store.set_theme_preference(preference, rng)?;
        if changed {
            self.events.push_back(Event::ThemeChanged);
        }
        Ok(changed)
    }
}
