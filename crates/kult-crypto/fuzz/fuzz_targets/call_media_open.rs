//! Fuzz: media-record parsing, authentication, and replay state are total.
#![no_main]
use libfuzzer_sys::fuzz_target;

fn context() -> kult_crypto::CallMediaContext {
    kult_crypto::CallMediaContext {
        call_id: [1; 16],
        initiator_account: [2; 32],
        responder_account: [3; 32],
        initiator_device: [4; 32],
        responder_device: [5; 32],
    }
}

fuzz_target!(|data: &[u8]| {
    let secret = [9; 32];
    let mut arbitrary =
        kult_crypto::CallMediaReceiver::new(&secret, &context(), kult_crypto::CallRole::Responder)
            .unwrap();
    let _ = arbitrary.open(data);

    let mut sender =
        kult_crypto::CallMediaSender::new(&secret, &context(), kult_crypto::CallRole::Initiator)
            .unwrap();
    let hello = sender.seal_hello().unwrap();
    let mut receiver =
        kult_crypto::CallMediaReceiver::new(&secret, &context(), kult_crypto::CallRole::Responder)
            .unwrap();
    receiver.open(&hello).unwrap();
    if !data.is_empty() {
        let payload = &data[..data.len().min(kult_crypto::MAX_CALL_MEDIA_PAYLOAD_LEN)];
        let valid = sender.seal_audio(1, payload).unwrap();
        let opened = receiver.open(&valid).unwrap();
        assert_eq!(opened.payload, payload);
        assert!(receiver.open(&valid).is_err());
    }
});
