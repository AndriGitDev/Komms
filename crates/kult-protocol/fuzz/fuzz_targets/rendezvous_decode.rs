//! Fuzz: every ADR-0018 fixed-shape and authenticated control codec remains
//! bounded, canonical, and round-trippable.
#![no_main]

use kult_protocol::{
    RendezvousLookupRequest, RendezvousProviderControl, RendezvousProviderDescriptor,
    RendezvousRegisterRequest, RendezvousRoute, RendezvousRouteKind, RendezvousRouteRecord,
};
use libfuzzer_sys::fuzz_target;

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or(index as u8)
}

fn word(data: &[u8], offset: usize) -> u64 {
    (0..8).fold(0u64, |value, index| {
        (value << 8) | u64::from(byte(data, offset + index))
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(control) = RendezvousProviderControl::decode(data) {
        let encoded = control.encode().unwrap();
        assert_eq!(
            RendezvousProviderControl::decode(&encoded).unwrap(),
            control
        );
    }
    if let Ok(record) = RendezvousRouteRecord::decode(data) {
        let encoded = record.encode().unwrap();
        assert_eq!(RendezvousRouteRecord::decode(&encoded).unwrap(), record);
    }
    if let Ok(register) = RendezvousRegisterRequest::decode(data) {
        let encoded = register.encode().unwrap();
        assert_eq!(
            RendezvousRegisterRequest::decode(&encoded).unwrap(),
            register
        );
    }
    if let Ok(lookup) = RendezvousLookupRequest::decode(data) {
        let encoded = lookup.encode();
        assert_eq!(RendezvousLookupRequest::decode(&encoded).unwrap(), lookup);
    }

    // Keep every input on valid canonical paths as well as the raw malformed
    // paths above, so fixed widths and namespace magic do not become coverage
    // barriers for a short smoke budget.
    let epoch = word(data, 0);
    let generation = word(data, 8).max(1);
    let issued_at = word(data, 16) % (u64::MAX - 7_200);
    let expires_at = issued_at + 1 + (word(data, 24) % 7_200);
    let record = RendezvousRouteRecord {
        epoch,
        generation,
        issued_at,
        expires_at,
        routes: vec![RendezvousRoute {
            kind: if byte(data, 32) & 1 == 0 {
                RendezvousRouteKind::Multiaddr
            } else {
                RendezvousRouteKind::MailboxRelay
            },
            value: format!(
                "/dns4/fuzz-{}.example/tcp/{}/p2p/test",
                byte(data, 33),
                1_024 + u16::from(byte(data, 34))
            ),
        }],
    };
    let encoded_record = record.encode().unwrap();
    assert_eq!(
        RendezvousRouteRecord::decode(&encoded_record).unwrap(),
        record
    );

    let mut slot = [0u8; 32];
    let mut sealed_record = [0u8; kult_protocol::RENDEZVOUS_REGISTER_REQUEST_LEN - 44];
    for (index, destination) in slot.iter_mut().enumerate() {
        *destination = byte(data, index);
    }
    for (index, destination) in sealed_record.iter_mut().enumerate() {
        *destination = byte(data, index);
    }
    let register = RendezvousRegisterRequest {
        slot,
        epoch,
        ttl_seconds: 1 + (u32::from(byte(data, 35)) % 7_200),
        sealed_record,
    };
    let encoded_register = register.encode().unwrap();
    assert_eq!(
        RendezvousRegisterRequest::decode(&encoded_register).unwrap(),
        register
    );

    let lookup = RendezvousLookupRequest { slot, epoch };
    let encoded_lookup = lookup.encode();
    assert_eq!(
        RendezvousLookupRequest::decode(&encoded_lookup).unwrap(),
        lookup
    );

    let control = RendezvousProviderControl {
        account: slot,
        device: [byte(data, 36); 32],
        authority_generation: word(data, 37).max(1),
        generation,
        providers: vec![RendezvousProviderDescriptor {
            origin: format!("https://fuzz-{}.example", byte(data, 45)),
            static_key: [byte(data, 46).max(1); 32],
        }],
    };
    let encoded_control = control.encode().unwrap();
    assert_eq!(
        RendezvousProviderControl::decode(&encoded_control).unwrap(),
        control
    );
});
