//! Protocol-layer tests, including the M2 fragmentation acceptance test:
//! round-trip at MTU 180 with 30% random fragment loss driven by NACK
//! selective retransmission (docs/08-roadmap.md, M2).

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use kult_protocol::{
    bundle_export, bundle_import, delivery_token, epoch_day, fragment, intro_token, pad, unpad,
    Envelope, EnvelopeKind, MailboxKey, ProtocolError, Reassembler, ReceiptPayload, PAD_BUCKETS,
};

const NOW: u64 = 1_800_000_000;

#[test]
fn padding_roundtrip_all_buckets() {
    for &bucket in &PAD_BUCKETS {
        for len in [0, 1, bucket - 1] {
            let data = vec![0xAB; len];
            let padded = pad(&data).unwrap();
            assert!(PAD_BUCKETS.contains(&padded.len()));
            assert!(padded.len() > len);
            assert_eq!(unpad(&padded).unwrap(), data);
        }
    }
    // A short message lands in the LoRa-friendly 192 B bucket.
    assert_eq!(pad(b"hello mesh").unwrap().len(), 192);
    // Over the top bucket is refused.
    assert_eq!(pad(&vec![0; 65536]).unwrap_err(), ProtocolError::TooLarge);
}

#[test]
fn unpad_rejects_malformed() {
    assert!(unpad(&[0u8; 100]).is_err()); // not a bucket size
    assert!(unpad(&[0u8; 192]).is_err()); // all zeros, no marker
    let mut ok = pad(b"x").unwrap();
    ok[1] = 0xFF; // corrupt interior is fine (that's data), but...
    let mut bad = pad(b"x").unwrap();
    let len = bad.len();
    bad[len - 1] = 0x01; // trailing non-zero, non-marker
    assert!(unpad(&bad).is_err());
}

#[test]
fn envelope_roundtrip_and_garbage() {
    let env = Envelope::new(EnvelopeKind::Message, [7u8; 32], vec![1, 2, 3]);
    assert_eq!(Envelope::decode(&env.encode()).unwrap(), env);

    let mut rng = StdRng::seed_from_u64(1);
    for len in [0usize, 1, 33, 34, 200] {
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf[..]);
        let _ = Envelope::decode(&buf); // must not panic
    }
    // Unknown kind byte rejected.
    let mut bytes = env.encode();
    bytes[1] = 0x99;
    assert!(Envelope::decode(&bytes).is_err());
}

#[test]
fn tokens_rotate_and_differ() {
    let k = MailboxKey::from_bytes([3u8; 32]);
    let alice = [7u8; 32];
    let bob = [9u8; 32];
    let e = epoch_day(NOW);
    let t1 = delivery_token(&k, e, &bob);
    let t2 = delivery_token(&k, e + 1, &bob);
    assert_ne!(t1, t2);
    assert_eq!(
        t1,
        delivery_token(&MailboxKey::from_bytes([3u8; 32]), e, &bob)
    );
    // The two directions of a pair never share a token (ADR-0007): a shared
    // relay must not let one party collect the other's mail.
    assert_ne!(t1, delivery_token(&k, e, &alice));
    // Intro tokens are distinct from mailbox tokens even with related input.
    assert_ne!(intro_token(&[3u8; 32], e), t1);
}

#[test]
fn bundle_roundtrip_and_strictness() {
    let envs: Vec<Envelope> = (0..5)
        .map(|i| Envelope::new(EnvelopeKind::Message, [i as u8; 32], vec![i as u8; 40 + i]))
        .collect();
    let bytes = bundle_export(&envs);
    assert_eq!(bundle_import(&bytes).unwrap(), envs);

    assert!(bundle_import(b"NOPE").is_err());
    let mut truncated = bytes.clone();
    truncated.truncate(bytes.len() - 3);
    assert!(bundle_import(&truncated).is_err());
    // Absurd length prefix rejected.
    let mut evil = b"KKB1".to_vec();
    evil.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(bundle_import(&evil).is_err());
}

#[test]
fn receipt_roundtrip() {
    let r = ReceiptPayload {
        acks: vec![[1u8; 16], [2u8; 16]],
        nacks: vec![([9, 9, 9, 9], vec![0, 4, 7])],
    };
    assert_eq!(ReceiptPayload::decode(&r.encode()).unwrap(), r);
}

#[test]
fn fragment_reassembly_in_order() {
    let payload = vec![0x5A; 5000];
    let frags = fragment(&payload, 180).unwrap();
    // MTU 180 → 172-byte slices → ceil(5000/172) = 30 fragments.
    assert_eq!(frags.len(), 30);
    assert!(frags.iter().all(|f| f.len() <= 180));

    let mut r = Reassembler::new();
    let mut done = None;
    for f in &frags {
        if let Some(p) = r.insert(f, NOW).unwrap() {
            done = Some(p);
        }
    }
    assert_eq!(done.unwrap(), payload);
    assert_eq!(r.pending(), 0);
}

/// M2 acceptance: MTU 180, 30% random fragment loss per transmission round,
/// NACK-driven selective retransmission until complete.
#[test]
fn fragmentation_survives_30pct_loss_with_nacks() {
    let mut rng = StdRng::seed_from_u64(0xBEEF);
    for trial in 0..10 {
        let payload: Vec<u8> = (0..4096).map(|_| rng.gen()).collect();
        let frags = fragment(&payload, 180).unwrap();
        let mut r = Reassembler::new();
        let mut assembled = None;
        let mut rounds = 0;

        // Round 1: initial transmission with 30% loss.
        let mut to_send: Vec<usize> = (0..frags.len()).collect();
        while assembled.is_none() {
            rounds += 1;
            assert!(rounds < 50, "trial {trial}: too many rounds");
            for &i in &to_send {
                if rng.gen_range(0..100) < 30 {
                    continue; // lost on the air
                }
                if let Some(p) = r.insert(&frags[i], NOW).unwrap() {
                    assembled = Some(p);
                }
            }
            if assembled.is_some() {
                break;
            }
            // Receiver NACKs missing indices; sender retransmits exactly those.
            let missing = r.missing(NOW);
            assert_eq!(missing.len(), 1);
            to_send = missing[0].1.iter().map(|&i| i as usize).collect();
            assert!(!to_send.is_empty());
        }
        assert_eq!(assembled.unwrap(), payload);
    }
}

#[test]
fn reassembly_window_expires() {
    let payload = vec![1u8; 1000];
    let frags = fragment(&payload, 180).unwrap();
    let mut r = Reassembler::new();
    r.insert(&frags[0], NOW).unwrap();
    assert_eq!(r.pending(), 1);
    // 25 hours later the partial is gone and NACKs stop.
    let later = NOW + 25 * 3600;
    assert!(r.missing(later).is_empty());
    r.insert(&frags[1], later).unwrap();
    assert_eq!(r.pending(), 1); // fresh partial, old one purged
}

#[test]
fn mixed_fragments_fail_integrity() {
    let a = fragment(&vec![1u8; 400], 180).unwrap();
    let b = fragment(&vec![2u8; 400], 180).unwrap();
    let mut r = Reassembler::new();
    // Forge: b's slice claiming a's message id.
    let mut forged = b[1].clone();
    forged[..4].copy_from_slice(&a[1][..4]);
    r.insert(&a[0], NOW).unwrap();
    r.insert(&a[2], NOW).unwrap();
    let res = r.insert(&forged, NOW);
    assert_eq!(res.unwrap_err(), ProtocolError::IntegrityMismatch);
}

#[test]
fn fragment_edge_cases() {
    assert_eq!(
        fragment(&[1, 2, 3], 8).unwrap_err(),
        ProtocolError::MtuTooSmall
    );
    // Empty payload → one well-formed fragment.
    let frags = fragment(&[], 180).unwrap();
    assert_eq!(frags.len(), 1);
    let mut r = Reassembler::new();
    assert_eq!(r.insert(&frags[0], NOW).unwrap().unwrap(), Vec::<u8>::new());
    // Garbage fragment bodies never panic.
    let mut rng = StdRng::seed_from_u64(2);
    for len in [0usize, 7, 8, 9, 100] {
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf[..]);
        let _ = r.insert(&buf, NOW);
    }
}
