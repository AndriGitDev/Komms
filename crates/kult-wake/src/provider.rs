use async_trait::async_trait;
use zeroize::Zeroizing;

use kult_protocol::{WakeEnvironment, WakePlatform, WakeProfile};

/// Exact static APNs background payload.
pub const APNS_BACKGROUND_PAYLOAD: &[u8] = br#"{"aps":{"content-available":1}}"#;
/// Exact static APNs generic-visible payload.
pub const APNS_GENERIC_PAYLOAD: &[u8] = br#"{"aps":{"alert":{"title":"Komms","body":"New activity"},"sound":"default","content-available":1}}"#;
/// Exact static FCM normal-priority background payload data.
pub const FCM_BACKGROUND_PAYLOAD: &[u8] = br#"{"data":{"wake":"1"}}"#;
/// Exact static FCM user-visible payload data.
pub const FCM_GENERIC_PAYLOAD: &[u8] =
    br#"{"notification":{"title":"Komms","body":"New activity"},"data":{"wake":"1"}}"#;

/// Reduced native-provider outcome retained only as aggregate metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderErrorClass {
    /// Temporary provider or network outage.
    Unavailable,
    /// Provider rate limit or overload.
    RateLimited,
    /// Gateway credential or provider authentication failure.
    Authentication,
    /// Native destination is invalid or unregistered and should be retired.
    InvalidDestination,
    /// Other bounded provider refusal.
    Other,
}

/// One least-authority provider operation.
///
/// Routing state is zeroized on drop. The custom debug view omits token,
/// topic, and collapse bytes.
pub struct NativePushRequest {
    platform: WakePlatform,
    environment: WakeEnvironment,
    profile: WakeProfile,
    provider_token: Zeroizing<Vec<u8>>,
    app_topic: Zeroizing<Vec<u8>>,
    collapse_id: [u8; 16],
}

impl NativePushRequest {
    pub(crate) fn new(
        platform: WakePlatform,
        environment: WakeEnvironment,
        profile: WakeProfile,
        provider_token: Vec<u8>,
        app_topic: Vec<u8>,
        collapse_id: [u8; 16],
    ) -> Self {
        Self {
            platform,
            environment,
            profile,
            provider_token: Zeroizing::new(provider_token),
            app_topic: Zeroizing::new(app_topic),
            collapse_id,
        }
    }

    /// Native provider.
    pub fn platform(&self) -> WakePlatform {
        self.platform
    }

    /// Provider environment.
    pub fn environment(&self) -> WakeEnvironment {
        self.environment
    }

    /// Static notification profile.
    pub fn profile(&self) -> WakeProfile {
        self.profile
    }

    /// Native routing token for the provider adapter only.
    pub fn provider_token(&self) -> &[u8] {
        &self.provider_token
    }

    /// Application topic/package for the provider adapter only.
    pub fn app_topic(&self) -> &[u8] {
        &self.app_topic
    }

    /// Destination-scoped opaque collapse identifier.
    pub fn collapse_id(&self) -> &[u8; 16] {
        &self.collapse_id
    }

    /// Exact static content-free provider payload.
    pub fn payload(&self) -> &'static [u8] {
        match (self.platform, self.profile) {
            (WakePlatform::Apns, WakeProfile::BackgroundOnly) => APNS_BACKGROUND_PAYLOAD,
            (WakePlatform::Apns, WakeProfile::GenericVisible) => APNS_GENERIC_PAYLOAD,
            (WakePlatform::Fcm, WakeProfile::BackgroundOnly) => FCM_BACKGROUND_PAYLOAD,
            (WakePlatform::Fcm, WakeProfile::GenericVisible) => FCM_GENERIC_PAYLOAD,
        }
    }

    /// APNs push type, when this is an APNs operation.
    pub fn apns_push_type(&self) -> Option<&'static str> {
        if self.platform != WakePlatform::Apns {
            return None;
        }
        Some(match self.profile {
            WakeProfile::BackgroundOnly => "background",
            WakeProfile::GenericVisible => "alert",
        })
    }

    /// APNs priority, when this is an APNs operation.
    pub fn apns_priority(&self) -> Option<u8> {
        if self.platform != WakePlatform::Apns {
            return None;
        }
        Some(match self.profile {
            WakeProfile::BackgroundOnly => 5,
            WakeProfile::GenericVisible => 10,
        })
    }

    /// Whether FCM high priority is permitted for this operation.
    pub fn fcm_high_priority(&self) -> bool {
        self.platform == WakePlatform::Fcm && self.profile == WakeProfile::GenericVisible
    }
}

impl core::fmt::Debug for NativePushRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativePushRequest")
            .field("platform", &self.platform)
            .field("environment", &self.environment)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

/// Narrow asynchronous APNs/FCM provider boundary.
#[async_trait]
pub trait NativePushProvider: Send + Sync {
    /// Send one static notification shape to the exact opened destination.
    async fn send(
        &self,
        request: NativePushRequest,
    ) -> core::result::Result<(), ProviderErrorClass>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_payloads_never_expose_routing_state() {
        let request = NativePushRequest::new(
            WakePlatform::Apns,
            WakeEnvironment::Production,
            WakeProfile::GenericVisible,
            b"native-token-secret".to_vec(),
            b"is.komms.secret".to_vec(),
            [9u8; 16],
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains("native-token-secret"));
        assert!(!debug.contains("is.komms.secret"));
        assert!(!debug.contains("0909"));
        assert_eq!(request.payload(), APNS_GENERIC_PAYLOAD);
        assert_eq!(request.apns_push_type(), Some("alert"));
        assert_eq!(request.apns_priority(), Some(10));
    }
}
