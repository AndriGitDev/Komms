//! Komms stable-v1 conformance adapter.
//!
//! The adapter is intentionally narrow: it exposes deterministic protocol
//! operations through bounded JSON-lines requests so a language-neutral runner
//! can compare separately produced implementations against one fixture set.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use rand_core::{CryptoRng, Error as RngError, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use kult_crypto::{
    account_recovery_authority_public, admission_bundle_digest, derive_rendezvous_epoch_keys,
    discovery_epoch_valid_until, discovery_introduction_token, discovery_locator, group_origin_tag,
    initiate, open_account_recovery_authority, open_discovery_record, rendezvous_provider_id,
    respond, seal_account_recovery_authority, seal_discovery_record, seal_rendezvous_record,
    AdmissionPolicy, ConnectCode, DeviceAuthorityCertificate, DeviceAuthorityManifest,
    DeviceAuthorityRelation, DiscoveryIngressBundle, DiscoveryRoute, DiscoveryRouteKind,
    GroupHeaderKey, GroupMessage, GroupOriginContext, GroupOriginEnvelope, GroupReceiverChain,
    GroupSenderChain, Identity, KdfProfile, OneTimePrekeySecret, PqPrekeySecret, PrekeyBundle,
    SignedPrekeySecret, DISCOVERY_RECORD_SIZE, RENDEZVOUS_RECORD_PLAINTEXT_LEN,
};
use kult_protocol::{
    admission_invitation_proof, attachment_chunk_count, decode_content, decode_group_authority,
    delivery_token, encode_attachment, encode_call_control, encode_disappearing_text_payload,
    encode_edit, encode_ephemeral, encode_group_authority, encode_group_authority_state,
    encode_mention, encode_poll, encode_poll_create_payload, encode_poll_vote_payload, encode_text,
    group_authority_state_signing_bytes, solve_admission_puzzle, verify_admission_puzzle,
    verify_wake_generic_response, wake_generic_response, wake_provider_id, AdmissionContext,
    AdmissionEnvelope, AdmissionProofKind, AttachmentManifest, AttachmentObject, AttachmentRole,
    CallControl, DecodedContent, DecodedGroupAuthority, Edit, Envelope, EnvelopeKind,
    GroupAuthorityMember, GroupRole, MailboxKey, MentionSpan, PollOption, PollVote,
    SignedGroupAuthorityState, WakeCapability, WakeCapabilityControl, WakeCapabilityDescriptor,
    WakeCapabilityPayload, WakeEnvironment, WakePlatform, WakeProfile, WakeRegisterRequest,
    WakeRegisterResponse, WakeTriggerRequest, ATTACHMENT_CHUNK_DATA_LEN, GROUP_AUTHORITY_VERSION,
    WAKE_CAPABILITY_ASSOCIATED_DATA,
};
use kult_store::{
    DeviceAuthorityStateRecord, DiscoveryCapabilityState, Store, AUTHORITY_BACKUP_MAGIC,
};
use kult_transport::{
    decode_mailbox_v2_request, decode_mailbox_v2_response, encode_mailbox_v2_request,
    encode_mailbox_v2_response, MailboxV2LeasedRow, MailboxV2Request, MailboxV2Response,
};

const VECTOR_RNG_DOMAIN: &[u8] = b"Komms-Conformance-RNG-v1";

/// Process one UTF-8 JSON request and return one response value.
pub fn process_request_bytes(bytes: &[u8]) -> Value {
    let request: AdapterRequest = match serde_json::from_slice(bytes) {
        Ok(request) => request,
        Err(_) => return error_response(None, "invalid_json", "request is not canonical JSON"),
    };
    let id = request.id.clone();
    match process_request(&request.operation, &request.arguments) {
        Ok(result) => json!({"id": id, "ok": true, "result": result}),
        Err(error) => error_response(Some(id), error.code, &error.message),
    }
}

/// Construct a stable adapter error response.
pub fn error_response(id: Option<Value>, code: &str, message: &str) -> Value {
    json!({
        "id": id.unwrap_or(Value::Null),
        "ok": false,
        "error": {"code": code, "message": message}
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterRequest {
    #[serde(default)]
    id: Value,
    operation: String,
    #[serde(default)]
    arguments: Value,
}

struct AdapterError {
    code: &'static str,
    message: String,
}

impl AdapterError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

type AdapterResult = Result<Value, AdapterError>;

fn process_request(operation: &str, arguments: &Value) -> AdapterResult {
    match operation {
        "adapter.capabilities" => Ok(json!({
            "profile": "komms-stable-v1",
            "adapter_version": 1,
            "operations": [
                "adapter.capabilities",
                "primitive.x25519",
                "primitive.ed25519",
                "primitive.hkdf_sha256",
                "primitive.xchacha20poly1305",
                "primitive.argon2id",
                "content.encode_text",
                "content.suite",
                "content.decode",
                "envelope.decode",
                "token.delivery",
                "group.origin_tag",
                "group.message_trace",
                "group.authority_trace",
                "admission.puzzle",
                "admission.trace",
                "discovery.connect_code",
                "discovery.locator",
                "discovery.introduction_token",
                "discovery.record_trace",
                "mailbox.v2.trace",
                "mailbox.v2.canonicalize",
                "rendezvous.derive",
                "rendezvous.seal",
                "wake.trace",
                "recovery_authority.trace",
                "backup.root_free_trace",
                "device_authority.trace",
                "device_authority.verify",
                "pqxdh.trace"
            ]
        })),
        "primitive.x25519" => primitive_x25519(arguments),
        "primitive.ed25519" => primitive_ed25519(arguments),
        "primitive.hkdf_sha256" => primitive_hkdf(arguments),
        "primitive.xchacha20poly1305" => primitive_xchacha(arguments),
        "primitive.argon2id" => primitive_argon2id(arguments),
        "content.encode_text" => content_encode_text(arguments),
        "content.suite" => content_suite(arguments),
        "content.decode" => content_decode(arguments),
        "envelope.decode" => envelope_decode(arguments),
        "token.delivery" => token_delivery(arguments),
        "group.origin_tag" => origin_tag(arguments),
        "group.message_trace" => group_message_trace(arguments),
        "group.authority_trace" => group_authority_trace(arguments),
        "admission.puzzle" => admission_puzzle(arguments),
        "admission.trace" => admission_trace(arguments),
        "discovery.connect_code" => connect_code(arguments),
        "discovery.locator" => locator(arguments),
        "discovery.introduction_token" => introduction_token(arguments),
        "discovery.record_trace" => discovery_record_trace(arguments),
        "mailbox.v2.trace" => mailbox_v2_trace(arguments),
        "mailbox.v2.canonicalize" => mailbox_v2_canonicalize(arguments),
        "rendezvous.derive" => rendezvous_derive(arguments),
        "rendezvous.seal" => rendezvous_seal(arguments),
        "wake.trace" => wake_trace(arguments),
        "recovery_authority.trace" => recovery_authority_trace(arguments),
        "backup.root_free_trace" => root_free_backup_trace(arguments),
        "device_authority.trace" => device_authority_trace(arguments),
        "device_authority.verify" => device_authority_verify(arguments),
        "pqxdh.trace" => pqxdh_trace(arguments),
        _ => Err(AdapterError::new(
            "unsupported_operation",
            "operation is not part of adapter version 1",
        )),
    }
}

fn primitive_x25519(arguments: &Value) -> AdapterResult {
    use x25519_dalek::{PublicKey, StaticSecret};

    let alice_secret = StaticSecret::from(hex_array::<32>(arguments, "alice_secret_hex")?);
    let bob_secret = StaticSecret::from(hex_array::<32>(arguments, "bob_secret_hex")?);
    let alice_public = PublicKey::from(&alice_secret);
    let bob_public = PublicKey::from(&bob_secret);
    let shared = alice_secret.diffie_hellman(&bob_public);
    Ok(json!({
        "alice_public_hex": hex::encode(alice_public.as_bytes()),
        "bob_public_hex": hex::encode(bob_public.as_bytes()),
        "shared_secret_hex": hex::encode(shared.as_bytes())
    }))
}

fn primitive_ed25519(arguments: &Value) -> AdapterResult {
    use ed25519_dalek::{Signer, SigningKey};

    let signing = SigningKey::from_bytes(&hex_array::<32>(arguments, "secret_hex")?);
    let message = hex_bytes(arguments, "message_hex")?;
    let signature = signing.sign(&message);
    Ok(json!({
        "public_hex": hex::encode(signing.verifying_key().as_bytes()),
        "signature_hex": hex::encode(signature.to_bytes())
    }))
}

fn primitive_hkdf(arguments: &Value) -> AdapterResult {
    use hkdf::Hkdf;

    let ikm = hex_bytes(arguments, "ikm_hex")?;
    let salt = hex_bytes(arguments, "salt_hex")?;
    let info = hex_bytes(arguments, "info_hex")?;
    let output_len = usize_value(arguments, "output_len")?;
    if output_len == 0 || output_len > 8_160 {
        return Err(AdapterError::new(
            "invalid_length",
            "HKDF output length must be between 1 and 8160 bytes",
        ));
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut output = vec![0u8; output_len];
    hkdf.expand(&info, &mut output)
        .map_err(|_| AdapterError::new("invalid_length", "HKDF expansion length is invalid"))?;
    Ok(json!({"okm_hex": hex::encode(output)}))
}

fn primitive_xchacha(arguments: &Value) -> AdapterResult {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let key = hex_array::<32>(arguments, "key_hex")?;
    let nonce = hex_array::<24>(arguments, "nonce_hex")?;
    let aad = hex_bytes(arguments, "aad_hex")?;
    let plaintext = hex_bytes(arguments, "plaintext_hex")?;
    let cipher = XChaCha20Poly1305::new(&key.into());
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| AdapterError::new("encryption_failed", "AEAD encryption failed"))?;
    Ok(json!({"sealed_hex": hex::encode(sealed)}))
}

fn primitive_argon2id(arguments: &Value) -> AdapterResult {
    use argon2::{Algorithm, Argon2, AssociatedData, KeyId, ParamsBuilder, Version};

    let password = hex_bytes(arguments, "password_hex")?;
    let salt = hex_bytes(arguments, "salt_hex")?;
    let secret = optional_hex_bytes(arguments, "secret_hex")?.unwrap_or_default();
    let associated_data = optional_hex_bytes(arguments, "associated_data_hex")?.unwrap_or_default();
    let memory_kib = u32_value(arguments, "memory_kib")?;
    let iterations = u32_value(arguments, "iterations")?;
    let parallelism = u32_value(arguments, "parallelism")?;
    let output_len = usize_value(arguments, "output_len")?;
    if output_len == 0 || output_len > 1024 {
        return Err(AdapterError::new(
            "invalid_length",
            "Argon2 output length must be between 1 and 1024 bytes",
        ));
    }
    let params = ParamsBuilder::new()
        .m_cost(memory_kib)
        .t_cost(iterations)
        .p_cost(parallelism)
        .data(AssociatedData::new(&associated_data).map_err(|_| {
            AdapterError::new("invalid_arguments", "Argon2 associated data is invalid")
        })?)
        .keyid(KeyId::new(&[]).expect("empty Argon2 key id is valid"))
        .output_len(output_len)
        .build()
        .map_err(|_| AdapterError::new("invalid_arguments", "Argon2 parameters are invalid"))?;
    let argon2 = if secret.is_empty() {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    } else {
        Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
            .map_err(|_| AdapterError::new("invalid_arguments", "Argon2 secret is invalid"))?
    };
    let mut output = vec![0u8; output_len];
    argon2
        .hash_password_into(&password, &salt, &mut output)
        .map_err(|_| AdapterError::new("derivation_failed", "Argon2 derivation failed"))?;
    Ok(json!({"output_hex": hex::encode(output)}))
}

fn content_encode_text(arguments: &Value) -> AdapterResult {
    let id = hex_array::<16>(arguments, "content_id_hex")?;
    let text = string(arguments, "text")?;
    let encoded = encode_text(id, text)
        .map_err(|_| AdapterError::new("invalid_content", "text cannot be encoded canonically"))?;
    Ok(json!({"encoded_hex": hex::encode(encoded)}))
}

fn content_suite(arguments: &Value) -> AdapterResult {
    let attachment_bytes = hex_bytes(arguments, "attachment_bytes_hex")?;
    let attachment_object = AttachmentObject {
        role: AttachmentRole::Primary,
        object_id: hex_array::<16>(arguments, "attachment_object_id_hex")?,
        total_len: u64::try_from(attachment_bytes.len())
            .map_err(|_| AdapterError::new("invalid_content", "attachment length overflow"))?,
        chunk_data_len: ATTACHMENT_CHUNK_DATA_LEN,
        chunk_count: attachment_chunk_count(attachment_bytes.len() as u64),
        content_hash: *blake3::hash(&attachment_bytes).as_bytes(),
        media_type: string(arguments, "attachment_media_type")?,
        filename: Some(string(arguments, "attachment_filename")?),
    };
    let attachment_manifest = AttachmentManifest {
        attachment_key: hex_array::<32>(arguments, "attachment_key_hex")?,
        primary: attachment_object,
        preview: None,
    };
    let attachment = encode_attachment(
        hex_array::<16>(arguments, "attachment_content_id_hex")?,
        &attachment_manifest,
    )
    .map_err(|_| AdapterError::new("invalid_content", "attachment content encoding failed"))?;

    let mention_target = hex_array::<32>(arguments, "mention_target_hex")?;
    let mention_text = string(arguments, "mention_text")?;
    let mention_start = u32_value(arguments, "mention_start")?;
    let mention_end = u32_value(arguments, "mention_end")?;
    let mention = encode_mention(
        hex_array::<16>(arguments, "mention_content_id_hex")?,
        mention_text,
        &[MentionSpan {
            start: mention_start,
            end: mention_end,
            target: mention_target,
        }],
    )
    .map_err(|_| AdapterError::new("invalid_content", "mention content encoding failed"))?;

    let edit = encode_edit(
        hex_array::<16>(arguments, "edit_content_id_hex")?,
        &Edit {
            target_author: hex_array::<32>(arguments, "edit_target_author_hex")?,
            target_content_id: hex_array::<16>(arguments, "edit_target_content_id_hex")?,
            revision: u64_value(arguments, "edit_revision")?,
            text: string(arguments, "edit_text")?,
        },
    )
    .map_err(|_| AdapterError::new("invalid_content", "edit content encoding failed"))?;

    let ephemeral_payload = encode_disappearing_text_payload(
        u64_value(arguments, "ephemeral_expires_at")?,
        string(arguments, "ephemeral_text")?,
    )
    .map_err(|_| AdapterError::new("invalid_content", "ephemeral payload encoding failed"))?;
    let ephemeral = encode_ephemeral(
        hex_array::<16>(arguments, "ephemeral_content_id_hex")?,
        &ephemeral_payload,
    )
    .map_err(|_| AdapterError::new("invalid_content", "ephemeral content encoding failed"))?;

    let poll_options = [
        PollOption {
            id: hex_array::<16>(arguments, "poll_option_one_id_hex")?,
            text: string(arguments, "poll_option_one_text")?,
        },
        PollOption {
            id: hex_array::<16>(arguments, "poll_option_two_id_hex")?,
            text: string(arguments, "poll_option_two_text")?,
        },
    ];
    let poll_voters = [
        hex_array::<32>(arguments, "poll_voter_one_hex")?,
        hex_array::<32>(arguments, "poll_voter_two_hex")?,
    ];
    let poll_create_payload = encode_poll_create_payload(
        u64_value(arguments, "poll_generation")?,
        string(arguments, "poll_question")?,
        &poll_options,
        &poll_voters,
    )
    .map_err(|_| AdapterError::new("invalid_content", "poll creation encoding failed"))?;
    let poll_create = encode_poll(
        hex_array::<16>(arguments, "poll_content_id_hex")?,
        &poll_create_payload,
    )
    .map_err(|_| AdapterError::new("invalid_content", "poll content encoding failed"))?;
    let poll_vote_payload = encode_poll_vote_payload(&PollVote {
        poll_author: hex_array::<32>(arguments, "poll_author_hex")?,
        poll_id: hex_array::<16>(arguments, "poll_content_id_hex")?,
        option_id: poll_options[0].id,
        revision: u64_value(arguments, "poll_vote_revision")?,
    })
    .map_err(|_| AdapterError::new("invalid_content", "poll vote encoding failed"))?;
    let poll_vote = encode_poll(
        hex_array::<16>(arguments, "poll_vote_content_id_hex")?,
        &poll_vote_payload,
    )
    .map_err(|_| AdapterError::new("invalid_content", "poll vote content encoding failed"))?;

    let call_offer = encode_call_control(
        hex_array::<16>(arguments, "call_content_id_hex")?,
        &CallControl::Offer {
            call_id: hex_array::<16>(arguments, "call_id_hex")?,
            initiator_device: hex_array::<32>(arguments, "call_initiator_device_hex")?,
            expires_at: u64_value(arguments, "call_expires_at")?,
            master_secret: hex_array::<32>(arguments, "call_master_secret_hex")?,
        },
    )
    .map_err(|_| AdapterError::new("invalid_content", "call content encoding failed"))?;

    let round_trip = matches!(
        decode_content(&attachment),
        DecodedContent::Attachment { .. }
    ) && matches!(decode_content(&mention), DecodedContent::Mention { .. })
        && matches!(decode_content(&edit), DecodedContent::Edit { .. })
        && matches!(decode_content(&ephemeral), DecodedContent::Ephemeral { .. })
        && matches!(decode_content(&poll_create), DecodedContent::Poll { .. })
        && matches!(decode_content(&poll_vote), DecodedContent::Poll { .. })
        && matches!(
            decode_content(&call_offer),
            DecodedContent::CallControl { .. }
        );

    Ok(json!({
        "attachment_hex": hex::encode(attachment),
        "mention_hex": hex::encode(mention),
        "edit_hex": hex::encode(edit),
        "ephemeral_hex": hex::encode(ephemeral),
        "poll_create_hex": hex::encode(poll_create),
        "poll_vote_hex": hex::encode(poll_vote),
        "call_offer_hex": hex::encode(call_offer),
        "all_round_trip": round_trip
    }))
}

fn content_decode(arguments: &Value) -> AdapterResult {
    let encoded = hex_bytes(arguments, "encoded_hex")?;
    let result = match decode_content(&encoded) {
        DecodedContent::LegacyText(text) => {
            json!({"classification": "legacy_text", "text": text})
        }
        DecodedContent::Text { id, text } => json!({
            "classification": "text",
            "content_id_hex": hex::encode(id),
            "text": text
        }),
        DecodedContent::Attachment { id, .. } => json!({
            "classification": "attachment",
            "content_id_hex": hex::encode(id)
        }),
        DecodedContent::Mention { id, mention } => json!({
            "classification": "mention",
            "content_id_hex": hex::encode(id),
            "text": mention.text,
            "targets_hex": mention.targets().map(hex::encode).collect::<Vec<_>>(),
            "spans": mention.spans().map(|span| json!({
                "start": span.start,
                "end": span.end,
                "target_hex": hex::encode(span.target)
            })).collect::<Vec<_>>()
        }),
        DecodedContent::Edit { id, edit } => json!({
            "classification": "edit",
            "content_id_hex": hex::encode(id),
            "target_author_hex": hex::encode(edit.target_author),
            "target_content_id_hex": hex::encode(edit.target_content_id),
            "revision": edit.revision,
            "text": edit.text
        }),
        DecodedContent::Ephemeral { id, .. } => json!({
            "classification": "ephemeral",
            "content_id_hex": hex::encode(id)
        }),
        DecodedContent::Poll { id, .. } => json!({
            "classification": "poll",
            "content_id_hex": hex::encode(id)
        }),
        DecodedContent::GroupAuthority { id, .. } => json!({
            "classification": "group_authority",
            "content_id_hex": hex::encode(id)
        }),
        DecodedContent::CallControl { id, .. } => json!({
            "classification": "call_control",
            "content_id_hex": hex::encode(id)
        }),
        DecodedContent::Unsupported {
            format_version,
            kind,
        } => json!({
            "classification": "unsupported",
            "format_version": format_version,
            "kind": kind
        }),
        DecodedContent::Malformed => json!({"classification": "malformed"}),
    };
    Ok(result)
}

fn envelope_decode(arguments: &Value) -> AdapterResult {
    let encoded = hex_bytes(arguments, "encoded_hex")?;
    let envelope = Envelope::decode(&encoded)
        .map_err(|_| AdapterError::new("malformed", "envelope is not canonical"))?;
    Ok(json!({
        "kind": envelope_kind_name(envelope.kind),
        "token_hex": hex::encode(envelope.token),
        "retention_until": envelope.retention_until,
        "body_hex": hex::encode(&envelope.body),
        "content_id_hex": hex::encode(envelope.content_id())
    }))
}

fn token_delivery(arguments: &Value) -> AdapterResult {
    let key = MailboxKey::from_bytes(hex_array::<32>(arguments, "mailbox_key_hex")?);
    let recipient = hex_array::<32>(arguments, "recipient_ed25519_hex")?;
    let epoch = u64_value(arguments, "epoch")?;
    Ok(json!({"token_hex": hex::encode(delivery_token(&key, epoch, &recipient))}))
}

fn origin_tag(arguments: &Value) -> AdapterResult {
    let context = GroupOriginContext {
        group_id: hex_array::<32>(arguments, "group_id_hex")?,
        sender_account: hex_array::<32>(arguments, "sender_account_hex")?,
        sender_device: hex_array::<32>(arguments, "sender_device_hex")?,
        recipient_account: hex_array::<32>(arguments, "recipient_account_hex")?,
        recipient_device: hex_array::<32>(arguments, "recipient_device_hex")?,
        sender_chain_key_id: hex_array::<16>(arguments, "sender_chain_key_id_hex")?,
        envelope_content_id: hex_array::<16>(arguments, "content_id_hex")?,
        authenticated_retention: optional_u64(arguments, "authenticated_retention")?,
    };
    let key = hex_array::<32>(arguments, "origin_key_hex")?;
    let ciphertext = hex_bytes(arguments, "shared_ciphertext_hex")?;
    Ok(json!({
        "tag_hex": hex::encode(group_origin_tag(&key, &context, &ciphertext))
    }))
}

fn group_message_trace(arguments: &Value) -> AdapterResult {
    let group_id = hex_array::<32>(arguments, "group_id_hex")?;
    let group_secret = hex_array::<32>(arguments, "group_secret_hex")?;
    let origin_key = hex_array::<32>(arguments, "origin_key_hex")?;
    let content_id = hex_array::<16>(arguments, "content_id_hex")?;
    let plaintext = hex_bytes(arguments, "plaintext_hex")?;
    let now = u64_value(arguments, "now")?;
    let header_key = GroupHeaderKey::derive(&group_secret);
    let mut rng = VectorRng::new(hex_array::<32>(arguments, "rng_seed_hex")?);
    let mut sender = GroupSenderChain::generate(&mut rng);
    let (key_id, chain_key, iteration) = sender.snapshot();
    let mut receiver = GroupReceiverChain::new(key_id, &chain_key, iteration);

    let shared = sender.seal_origin(&header_key, &group_id, content_id, &plaintext, &mut rng);
    let shared_bytes = shared.encode();
    let parsed_shared = GroupMessage::decode(&shared_bytes)
        .map_err(|_| AdapterError::new("group_failed", "shared group message decode failed"))?;
    let header = parsed_shared
        .open_header_details(&header_key)
        .map_err(|_| AdapterError::new("group_failed", "shared group header failed"))?;
    if header.key_id != key_id || header.content_id != Some(content_id) {
        return Err(AdapterError::new(
            "group_failed",
            "shared group header does not bind the expected chain and content",
        ));
    }
    let context = GroupOriginContext {
        group_id,
        sender_account: hex_array::<32>(arguments, "sender_account_hex")?,
        sender_device: hex_array::<32>(arguments, "sender_device_hex")?,
        recipient_account: hex_array::<32>(arguments, "recipient_account_hex")?,
        recipient_device: hex_array::<32>(arguments, "recipient_device_hex")?,
        sender_chain_key_id: header.key_id,
        envelope_content_id: content_id,
        authenticated_retention: optional_u64(arguments, "authenticated_retention")?,
    };
    let wrapped = GroupOriginEnvelope::seal(parsed_shared.clone(), &origin_key, &context)
        .map_err(|_| AdapterError::new("group_failed", "origin wrapper sealing failed"))?;
    let wrapper_bytes = wrapped.encode();
    let decoded = GroupOriginEnvelope::decode(&wrapper_bytes)
        .map_err(|_| AdapterError::new("group_failed", "origin wrapper decoding failed"))?;
    decoded
        .verify(&origin_key, &context)
        .map_err(|_| AdapterError::new("group_failed", "origin wrapper verification failed"))?;
    let opened = receiver
        .open(&group_id, decoded.shared(), header.iteration, now)
        .map_err(|_| AdapterError::new("group_failed", "group payload opening failed"))?;
    let replay_rejected = receiver
        .open(&group_id, decoded.shared(), header.iteration, now)
        .is_err();

    let mut wrong_recipient = context;
    wrong_recipient.recipient_device[0] ^= 1;
    let wrong_recipient_rejected = decoded.verify(&origin_key, &wrong_recipient).is_err();
    let mut tampered_wrapper = wrapper_bytes.clone();
    if let Some(last) = tampered_wrapper.last_mut() {
        *last ^= 1;
    }
    let tampered_tag_rejected = GroupOriginEnvelope::decode(&tampered_wrapper)
        .and_then(|candidate| candidate.verify(&origin_key, &context))
        .is_err();

    Ok(json!({
        "key_id_hex": hex::encode(header.key_id),
        "iteration": header.iteration,
        "content_id_hex": hex::encode(content_id),
        "shared_ciphertext_hex": hex::encode(shared_bytes),
        "origin_tag_hex": hex::encode(decoded.tag()),
        "wrapper_hex": hex::encode(wrapper_bytes),
        "opened_plaintext_hex": hex::encode(opened),
        "replay_rejected": replay_rejected,
        "wrong_recipient_rejected": wrong_recipient_rejected,
        "tampered_tag_rejected": tampered_tag_rejected
    }))
}

fn group_authority_trace(arguments: &Value) -> AdapterResult {
    let account = Identity::from_bytes(&hex_array::<64>(arguments, "account_identity_secret_hex")?);
    let device = Identity::from_bytes(&hex_array::<64>(arguments, "device_identity_secret_hex")?);
    let issued_at = u64_value(arguments, "issued_at")?;
    let mut authority_rng = VectorRng::new(hex_array::<32>(arguments, "authority_rng_seed_hex")?);
    let authority = DeviceAuthorityManifest::initial(
        &account,
        &device,
        "Group signer".into(),
        issued_at,
        &mut authority_rng,
    )
    .map_err(|_| AdapterError::new("group_authority_failed", "device authority genesis failed"))?;
    let authority_bytes = authority.encode().map_err(|_| {
        AdapterError::new(
            "group_authority_failed",
            "device authority proof encoding failed",
        )
    })?;
    let account_public = account.public();
    let member_identity = postcard::to_allocvec(&account_public).map_err(|_| {
        AdapterError::new("group_authority_failed", "member identity encoding failed")
    })?;
    let mut state = SignedGroupAuthorityState {
        version: GROUP_AUTHORITY_VERSION,
        group: hex_array::<32>(arguments, "group_id_hex")?,
        generation: u64_value(arguments, "generation")?,
        owner_epoch: 0,
        original_owner: account_public.ed,
        owner: account_public.ed,
        signer: account_public.ed,
        signer_device: device.public().ed,
        signer_authority: authority_bytes,
        prior_state_id: [0u8; 16],
        name: string(arguments, "name")?.to_owned(),
        members: vec![GroupAuthorityMember {
            peer: account_public.ed,
            identity: member_identity,
            role: GroupRole::Owner,
        }],
        secret_hash: Sha256::digest(hex_bytes(arguments, "group_secret_hex")?).into(),
        transfers: Vec::new(),
        signature: [0u8; 64],
    };
    let signing_bytes = group_authority_state_signing_bytes(&state).map_err(|_| {
        AdapterError::new(
            "group_authority_failed",
            "group authority canonical signing bytes failed",
        )
    })?;
    state.signature = device.sign_group_authority_state(&signing_bytes);
    let payload = encode_group_authority_state(&state).map_err(|_| {
        AdapterError::new(
            "group_authority_failed",
            "group authority payload encoding failed",
        )
    })?;
    let decoded = match decode_group_authority(&payload) {
        DecodedGroupAuthority::State(state) => state,
        _ => {
            return Err(AdapterError::new(
                "group_authority_failed",
                "group authority payload decoding failed",
            ))
        }
    };
    let decoded_authority =
        DeviceAuthorityManifest::decode(&decoded.signer_authority).map_err(|_| {
            AdapterError::new(
                "group_authority_failed",
                "embedded device authority proof failed",
            )
        })?;
    let certificate = decoded_authority
        .active_certificate(&decoded.signer_device)
        .ok_or_else(|| {
            AdapterError::new(
                "group_authority_failed",
                "signing device is not active in authority proof",
            )
        })?;
    if decoded_authority.account().ed != decoded.signer || certificate.account.ed != decoded.signer
    {
        return Err(AdapterError::new(
            "group_authority_failed",
            "signing account does not match device authority",
        ));
    }
    let decoded_signing = group_authority_state_signing_bytes(&decoded).map_err(|_| {
        AdapterError::new(
            "group_authority_failed",
            "decoded group authority canonical bytes failed",
        )
    })?;
    certificate
        .device
        .verify_group_authority_state(&decoded_signing, &decoded.signature)
        .map_err(|_| {
            AdapterError::new(
                "group_authority_failed",
                "group authority device signature failed",
            )
        })?;
    let content = encode_group_authority(hex_array::<16>(arguments, "content_id_hex")?, &payload)
        .map_err(|_| {
        AdapterError::new(
            "group_authority_failed",
            "group authority content framing failed",
        )
    })?;
    let content_round_trip = matches!(
        decode_content(&content),
        DecodedContent::GroupAuthority { .. }
    );

    Ok(json!({
        "device_authority_hex": hex::encode(decoded.signer_authority.as_slice()),
        "signing_bytes_hex": hex::encode(decoded_signing),
        "payload_hex": hex::encode(payload),
        "content_hex": hex::encode(content),
        "signer_account_hex": hex::encode(decoded.signer),
        "signer_device_hex": hex::encode(decoded.signer_device),
        "device_authority_generation": decoded_authority.generation(),
        "signature_verified": true,
        "content_round_trip": content_round_trip
    }))
}

fn admission_puzzle(arguments: &Value) -> AdapterResult {
    let context = AdmissionContext {
        target_account: hex_array::<32>(arguments, "target_account_hex")?,
        target_device: hex_array::<32>(arguments, "target_device_hex")?,
        bundle_digest: hex_array::<32>(arguments, "bundle_digest_hex")?,
        validity_epoch: u64_value(arguments, "validity_epoch")?,
    };
    let content_id = hex_array::<16>(arguments, "content_id_hex")?;
    let difficulty = u8_value(arguments, "difficulty")?;
    let max_attempts = u32_value(arguments, "max_attempts")?;
    let mut rng = VectorRng::new(hex_array::<32>(arguments, "rng_seed_hex")?);
    let nonce = solve_admission_puzzle(&context, &content_id, difficulty, max_attempts, &mut rng)
        .map_err(|_| {
        AdapterError::new(
            "admission_work_exhausted",
            "bounded puzzle search did not find a valid nonce",
        )
    })?;
    Ok(json!({
        "nonce_hex": hex::encode(nonce),
        "verified": verify_admission_puzzle(&context, &content_id, &nonce, difficulty)
    }))
}

fn admission_trace(arguments: &Value) -> AdapterResult {
    let account = Identity::from_bytes(&hex_array::<64>(arguments, "account_identity_secret_hex")?);
    let device = Identity::from_bytes(&hex_array::<64>(arguments, "device_identity_secret_hex")?);
    let signed_prekey = SignedPrekeySecret::from_bytes(
        u32_value(arguments, "signed_prekey_id")?,
        &hex_array::<32>(arguments, "signed_prekey_secret_hex")?,
    );
    let mut pq_rng = VectorRng::new(hex_array::<32>(arguments, "pq_prekey_rng_seed_hex")?);
    let pq_prekey = PqPrekeySecret::generate(&mut pq_rng, u32_value(arguments, "pq_prekey_id")?);
    let one_time_prekey = OneTimePrekeySecret::from_bytes(
        u32_value(arguments, "one_time_prekey_id")?,
        &hex_array::<32>(arguments, "one_time_prekey_secret_hex")?,
    );
    let now = u64_value(arguments, "now")?;
    let expires_at = u64_value(arguments, "expires_at")?;
    let invitation = hex_array::<32>(arguments, "invitation_secret_hex")?;
    let mut bundle = PrekeyBundle::build(
        &device,
        &signed_prekey,
        &pq_prekey,
        Some(&one_time_prekey),
        expires_at,
        Vec::new(),
    );
    bundle
        .attach_admission(
            &device,
            now,
            AdmissionPolicy {
                difficulty: u8_value(arguments, "difficulty")?,
                max_first_ciphertext: u32_value(arguments, "max_first_ciphertext")?,
                max_clock_skew_secs: u32_value(arguments, "max_clock_skew_secs")?,
                token_issuers: Vec::new(),
            },
            Some(invitation),
        )
        .map_err(|_| {
            AdapterError::new(
                "admission_failed",
                "signed admission descriptor construction failed",
            )
        })?;
    let verified = bundle
        .verify_admission(now)
        .map_err(|_| AdapterError::new("admission_failed", "admission descriptor failed"))?;
    let public_bundle = bundle.without_invitation_capability();
    let public_admission = public_bundle.verify_admission(now).map_err(|_| {
        AdapterError::new(
            "admission_failed",
            "public admission descriptor verification failed",
        )
    })?;
    let public_bundle_bytes = public_bundle.encode();
    let context = AdmissionContext {
        target_account: account.public().ed,
        target_device: device.public().ed,
        bundle_digest: public_admission.descriptor.bundle_digest,
        validity_epoch: public_admission.descriptor.validity_epoch,
    };
    if context.bundle_digest != admission_bundle_digest(&public_bundle) {
        return Err(AdapterError::new(
            "admission_failed",
            "public bundle digest does not match descriptor",
        ));
    }
    let sealed_flight = hex_bytes(arguments, "sealed_flight_hex")?;

    let invitation_base = AdmissionEnvelope::new(
        context,
        AdmissionProofKind::Invitation,
        [0u8; 32],
        public_bundle_bytes.clone(),
        sealed_flight.clone(),
    )
    .map_err(|_| AdapterError::new("admission_failed", "invitation wrapper framing failed"))?;
    let invitation_proof =
        admission_invitation_proof(&invitation, &context, &invitation_base.content_id);
    let invitation_envelope = AdmissionEnvelope {
        proof: invitation_proof,
        ..invitation_base
    };
    let invitation_bytes = invitation_envelope
        .encode()
        .map_err(|_| AdapterError::new("admission_failed", "invitation wrapper encoding failed"))?;
    let invitation_round_trip = AdmissionEnvelope::decode(&invitation_bytes)
        .map_err(|_| AdapterError::new("admission_failed", "invitation wrapper decoding failed"))?
        == invitation_envelope;

    let puzzle_base = AdmissionEnvelope::new(
        context,
        AdmissionProofKind::Puzzle,
        [0u8; 32],
        public_bundle_bytes.clone(),
        sealed_flight,
    )
    .map_err(|_| AdapterError::new("admission_failed", "puzzle wrapper framing failed"))?;
    let mut puzzle_rng = VectorRng::new(hex_array::<32>(arguments, "puzzle_rng_seed_hex")?);
    let puzzle_nonce = solve_admission_puzzle(
        &context,
        &puzzle_base.content_id,
        public_admission.descriptor.difficulty,
        u32_value(arguments, "max_attempts")?,
        &mut puzzle_rng,
    )
    .map_err(|_| {
        AdapterError::new(
            "admission_work_exhausted",
            "bounded admission trace puzzle did not find a nonce",
        )
    })?;
    let puzzle_envelope = AdmissionEnvelope {
        proof: puzzle_nonce,
        ..puzzle_base
    };
    let puzzle_bytes = puzzle_envelope
        .encode()
        .map_err(|_| AdapterError::new("admission_failed", "puzzle wrapper encoding failed"))?;
    let puzzle_round_trip = AdmissionEnvelope::decode(&puzzle_bytes)
        .map_err(|_| AdapterError::new("admission_failed", "puzzle wrapper decoding failed"))?
        == puzzle_envelope;
    let puzzle_verified = verify_admission_puzzle(
        &context,
        &puzzle_envelope.content_id,
        &puzzle_nonce,
        public_admission.descriptor.difficulty,
    );

    Ok(json!({
        "public_bundle_hex": hex::encode(public_bundle_bytes),
        "bundle_digest_hex": hex::encode(context.bundle_digest),
        "validity_epoch": context.validity_epoch,
        "expires_at": public_admission.descriptor.expires_at,
        "difficulty": public_admission.descriptor.difficulty,
        "invitation_commitment_hex": public_admission
            .descriptor
            .invitation_commitment
            .map(hex::encode),
        "public_bundle_contains_invitation_secret": public_bundle
            .relay_hints
            .iter()
            .any(|hint| hint.starts_with(b"KAI1")),
        "private_bundle_invitation_matches": verified.invitation == Some(invitation),
        "content_id_hex": hex::encode(invitation_envelope.content_id),
        "invitation_proof_hex": hex::encode(invitation_proof),
        "invitation_envelope_hex": hex::encode(invitation_bytes),
        "puzzle_nonce_hex": hex::encode(puzzle_nonce),
        "puzzle_envelope_hex": hex::encode(puzzle_bytes),
        "invitation_round_trip": invitation_round_trip,
        "puzzle_round_trip": puzzle_round_trip,
        "puzzle_verified": puzzle_verified
    }))
}

fn connect_code(arguments: &Value) -> AdapterResult {
    let identity = Identity::from_bytes(&hex_array::<64>(arguments, "identity_secret_hex")?);
    let capability = hex_array::<32>(arguments, "capability_hex")?;
    let code = ConnectCode::new(&identity.public(), capability).map_err(|_| {
        AdapterError::new("invalid_identity", "identity cannot form a Connect code")
    })?;
    Ok(json!({
        "text": code.encode(),
        "identity_digest_hex": hex::encode(code.identity_digest()),
        "capability_hex": hex::encode(code.capability())
    }))
}

fn locator(arguments: &Value) -> AdapterResult {
    let capability = hex_array::<32>(arguments, "capability_hex")?;
    let epoch = u64_value(arguments, "epoch")?;
    Ok(json!({
        "locator_hex": hex::encode(discovery_locator(&capability, epoch))
    }))
}

fn introduction_token(arguments: &Value) -> AdapterResult {
    let capability = hex_array::<32>(arguments, "capability_hex")?;
    let device = hex_array::<32>(arguments, "device_id_hex")?;
    let epoch_day = u64_value(arguments, "epoch_day")?;
    Ok(json!({
        "token_hex": hex::encode(discovery_introduction_token(
            &capability,
            &device,
            epoch_day
        ))
    }))
}

fn discovery_record_trace(arguments: &Value) -> AdapterResult {
    let root = Identity::from_bytes(&hex_array::<64>(arguments, "root_identity_secret_hex")?);
    let device = Identity::from_bytes(&hex_array::<64>(arguments, "device_identity_secret_hex")?);
    let capability = hex_array::<32>(arguments, "capability_hex")?;
    let epoch = u64_value(arguments, "epoch")?;
    let generation = u64_value(arguments, "generation")?;
    let issued_at = u64_value(arguments, "issued_at")?;
    let route_value = hex_bytes(arguments, "introduction_route_hex")?;

    let code = ConnectCode::new(&root.public(), capability)
        .map_err(|_| AdapterError::new("discovery_failed", "Connect code creation failed"))?;
    let mut authority_rng = VectorRng::new(hex_array::<32>(arguments, "authority_rng_seed_hex")?);
    let authority = DeviceAuthorityManifest::initial(
        &root,
        &device,
        "Ingress".into(),
        issued_at,
        &mut authority_rng,
    )
    .map_err(|_| AdapterError::new("discovery_failed", "authority genesis failed"))?;
    let signed_prekey = SignedPrekeySecret::from_bytes(
        17,
        &hex_array::<32>(arguments, "signed_prekey_secret_hex")?,
    );
    let mut pq_rng = VectorRng::new(hex_array::<32>(arguments, "pq_prekey_rng_seed_hex")?);
    let pq_prekey = PqPrekeySecret::generate(&mut pq_rng, 18);
    let expires_at = discovery_epoch_valid_until(epoch)
        .map_err(|_| AdapterError::new("discovery_failed", "discovery epoch overflow"))?;
    let mut bundle = PrekeyBundle::build(
        &device,
        &signed_prekey,
        &pq_prekey,
        None,
        expires_at,
        Vec::new(),
    );
    bundle
        .attach_admission(&device, issued_at, AdmissionPolicy::default(), None)
        .map_err(|_| AdapterError::new("discovery_failed", "admission descriptor failed"))?;
    let ingress = DiscoveryIngressBundle {
        certificate: authority.devices()[0].certificate.clone(),
        prekey: bundle,
    };
    let route = DiscoveryRoute {
        kind: DiscoveryRouteKind::IntroductionMailbox,
        value: route_value,
    };
    let mut record_rng = VectorRng::new(hex_array::<32>(arguments, "record_rng_seed_hex")?);
    let sealed = seal_discovery_record(
        &code,
        epoch,
        generation,
        issued_at,
        root.public(),
        authority,
        vec![ingress],
        vec![route],
        &device,
        &mut record_rng,
    )
    .map_err(|_| AdapterError::new("discovery_failed", "record sealing failed"))?;
    let opened = open_discovery_record(&code, epoch, &sealed, issued_at)
        .map_err(|_| AdapterError::new("discovery_failed", "record verification failed"))?;
    if sealed.len() != DISCOVERY_RECORD_SIZE {
        return Err(AdapterError::new(
            "discovery_failed",
            "record did not have the exact fixed size",
        ));
    }
    Ok(json!({
        "connect_code": code.encode(),
        "locator_hex": hex::encode(discovery_locator(&capability, epoch)),
        "record_hex": hex::encode(&sealed),
        "record_sha256_hex": hex::encode(Sha256::digest(&sealed)),
        "record_bytes": sealed.len(),
        "record_digest_hex": hex::encode(opened.digest()),
        "account_ed25519_hex": hex::encode(opened.account.ed),
        "authority_generation": opened.authority.generation(),
        "generation": opened.generation,
        "issued_at": opened.issued_at,
        "expires_at": opened.expires_at,
        "ingress_devices": opened.ingress.len(),
        "routes": opened.routes.len(),
        "introduction_routes_only": opened.routes.iter().all(
            |route| route.kind == DiscoveryRouteKind::IntroductionMailbox
        )
    }))
}

fn mailbox_v2_trace(arguments: &Value) -> AdapterResult {
    let envelope = hex_bytes(arguments, "envelope_hex")?;
    Envelope::decode(&envelope)
        .map_err(|_| AdapterError::new("invalid_envelope", "mailbox envelope is malformed"))?;
    let token_one = hex_array::<32>(arguments, "token_one_hex")?;
    let token_two = hex_array::<32>(arguments, "token_two_hex")?;
    let lease_id = hex_array::<16>(arguments, "lease_id_hex")?;
    let row_id = hex_array::<16>(arguments, "row_id_hex")?;
    let expires_at = u64_value(arguments, "expires_at")?;

    let deposit = MailboxV2Request::Deposit {
        envelope: envelope.clone(),
    };
    let lease = MailboxV2Request::Lease {
        tokens: vec![token_one, token_two],
    };
    let ack = MailboxV2Request::AckLease {
        lease_id,
        row_ids: vec![row_id],
    };
    let accepted = MailboxV2Response::Deposit { accepted: true };
    let refused = MailboxV2Response::Deposit { accepted: false };
    let page = MailboxV2Response::Lease {
        serving: true,
        lease_id,
        expires_at,
        rows: vec![MailboxV2LeasedRow { row_id, envelope }],
    };
    let miss = MailboxV2Response::Lease {
        serving: false,
        lease_id: [0u8; 16],
        expires_at: 0,
        rows: Vec::new(),
    };
    let acked = MailboxV2Response::AckLease { accepted: true };

    let deposit = encode_mailbox_v2_request(&deposit)
        .map_err(|_| AdapterError::new("mailbox_codec_failed", "deposit encoding failed"))?;
    let lease = encode_mailbox_v2_request(&lease)
        .map_err(|_| AdapterError::new("mailbox_codec_failed", "lease encoding failed"))?;
    let ack = encode_mailbox_v2_request(&ack)
        .map_err(|_| AdapterError::new("mailbox_codec_failed", "ack encoding failed"))?;
    let accepted = encode_mailbox_v2_response(&accepted)
        .map_err(|_| AdapterError::new("mailbox_codec_failed", "accepted encoding failed"))?;
    let refused = encode_mailbox_v2_response(&refused)
        .map_err(|_| AdapterError::new("mailbox_codec_failed", "refusal encoding failed"))?;
    let page = encode_mailbox_v2_response(&page)
        .map_err(|_| AdapterError::new("mailbox_codec_failed", "page encoding failed"))?;
    let miss = encode_mailbox_v2_response(&miss)
        .map_err(|_| AdapterError::new("mailbox_codec_failed", "miss encoding failed"))?;
    let acked = encode_mailbox_v2_response(&acked)
        .map_err(|_| AdapterError::new("mailbox_codec_failed", "ack response encoding failed"))?;

    Ok(json!({
        "deposit_request_hex": hex::encode(deposit),
        "lease_request_hex": hex::encode(lease),
        "ack_request_hex": hex::encode(ack),
        "deposit_accepted_response_hex": hex::encode(accepted),
        "deposit_refused_response_hex": hex::encode(refused),
        "lease_page_response_hex": hex::encode(page),
        "lease_miss_response_hex": hex::encode(miss),
        "ack_accepted_response_hex": hex::encode(acked)
    }))
}

fn mailbox_v2_canonicalize(arguments: &Value) -> AdapterResult {
    let encoded = hex_bytes(arguments, "encoded_hex")?;
    let message = string(arguments, "message")?;
    let canonical = match message {
        "request" => {
            let value = decode_mailbox_v2_request(&encoded).map_err(|_| {
                AdapterError::new("malformed", "mailbox-v2 request is not canonical")
            })?;
            encode_mailbox_v2_request(&value).map_err(|_| {
                AdapterError::new("malformed", "mailbox-v2 request is not canonical")
            })?
        }
        "response" => {
            let value = decode_mailbox_v2_response(&encoded).map_err(|_| {
                AdapterError::new("malformed", "mailbox-v2 response is not canonical")
            })?;
            encode_mailbox_v2_response(&value).map_err(|_| {
                AdapterError::new("malformed", "mailbox-v2 response is not canonical")
            })?
        }
        _ => {
            return Err(AdapterError::new(
                "invalid_arguments",
                "message must be request or response",
            ))
        }
    };
    Ok(json!({"canonical_hex": hex::encode(canonical)}))
}

fn rendezvous_derive(arguments: &Value) -> AdapterResult {
    let origin = string(arguments, "canonical_provider_origin")?.as_bytes();
    let static_key = hex_array::<32>(arguments, "provider_static_key_hex")?;
    let exporter = hex_array::<32>(arguments, "hybrid_service_exporter_hex")?;
    let recipient = Identity::from_bytes(&hex_array::<64>(
        arguments,
        "recipient_identity_secret_hex",
    )?)
    .public();
    let epoch = u64_value(arguments, "epoch")?;
    let provider_id = rendezvous_provider_id(origin, &static_key)
        .map_err(|_| AdapterError::new("invalid_provider", "provider origin is not canonical"))?;
    let keys = derive_rendezvous_epoch_keys(&exporter, &provider_id, &recipient, epoch)
        .map_err(|_| AdapterError::new("invalid_rendezvous", "rendezvous derivation failed"))?;
    Ok(json!({
        "provider_id_hex": hex::encode(provider_id),
        "recipient_ed25519_hex": hex::encode(recipient.ed),
        "recipient_x25519_hex": hex::encode(recipient.x),
        "slot_hex": hex::encode(keys.slot()),
        "epoch": keys.epoch()
    }))
}

fn rendezvous_seal(arguments: &Value) -> AdapterResult {
    let origin = string(arguments, "canonical_provider_origin")?.as_bytes();
    let static_key = hex_array::<32>(arguments, "provider_static_key_hex")?;
    let exporter = hex_array::<32>(arguments, "hybrid_service_exporter_hex")?;
    let recipient = Identity::from_bytes(&hex_array::<64>(
        arguments,
        "recipient_identity_secret_hex",
    )?)
    .public();
    let epoch = u64_value(arguments, "epoch")?;
    let plaintext = hex_array::<RENDEZVOUS_RECORD_PLAINTEXT_LEN>(arguments, "plaintext_hex")?;
    let seed = hex_array::<32>(arguments, "rng_seed_hex")?;
    let provider_id = rendezvous_provider_id(origin, &static_key)
        .map_err(|_| AdapterError::new("invalid_provider", "provider origin is not canonical"))?;
    let keys = derive_rendezvous_epoch_keys(&exporter, &provider_id, &recipient, epoch)
        .map_err(|_| AdapterError::new("invalid_rendezvous", "rendezvous derivation failed"))?;
    let mut rng = VectorRng::new(seed);
    let sealed = seal_rendezvous_record(&keys, &plaintext, &mut rng);
    Ok(json!({
        "sealed_hex": hex::encode(sealed),
        "sealed_sha256_hex": hex::encode(Sha256::digest(sealed)),
        "nonce_hex": hex::encode(&sealed[..24])
    }))
}

fn wake_trace(arguments: &Value) -> AdapterResult {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let platform = match string(arguments, "platform")? {
        "apns" => WakePlatform::Apns,
        "fcm" => WakePlatform::Fcm,
        _ => {
            return Err(AdapterError::new(
                "invalid_arguments",
                "wake platform must be apns or fcm",
            ))
        }
    };
    let environment = match string(arguments, "environment")? {
        "development" => WakeEnvironment::Development,
        "production" => WakeEnvironment::Production,
        _ => {
            return Err(AdapterError::new(
                "invalid_arguments",
                "wake environment must be development or production",
            ))
        }
    };
    let profile = match string(arguments, "profile")? {
        "background_only" => WakeProfile::BackgroundOnly,
        "generic_visible" => WakeProfile::GenericVisible,
        _ => {
            return Err(AdapterError::new(
                "invalid_arguments",
                "wake profile must be background_only or generic_visible",
            ))
        }
    };
    let expires_at = u64_value(arguments, "expires_at")?;
    let capability_payload = WakeCapabilityPayload {
        platform,
        environment,
        profile,
        expires_at,
        capability_id: hex_array::<16>(arguments, "capability_id_hex")?,
        provider_token: hex_bytes(arguments, "provider_token_hex")?,
        app_topic: string(arguments, "app_topic")?.as_bytes().to_vec(),
    };
    let plaintext = capability_payload.encode().map_err(|_| {
        AdapterError::new(
            "invalid_wake",
            "wake capability payload cannot be encoded canonically",
        )
    })?;
    let gateway_key = hex_array::<32>(arguments, "gateway_key_hex")?;
    let capability_nonce = hex_array::<24>(arguments, "capability_nonce_hex")?;
    let key_id = u32_value(arguments, "key_id")?;
    let cipher = XChaCha20Poly1305::new(&gateway_key.into());
    let sealed_payload = cipher
        .encrypt(
            XNonce::from_slice(&capability_nonce),
            Payload {
                msg: &plaintext,
                aad: WAKE_CAPABILITY_ASSOCIATED_DATA,
            },
        )
        .map_err(|_| AdapterError::new("invalid_wake", "wake capability sealing failed"))?;
    let capability = WakeCapability::from_parts(key_id, capability_nonce, &sealed_payload)
        .map_err(|_| AdapterError::new("invalid_wake", "wake capability framing failed"))?;
    let opened = cipher
        .decrypt(
            XNonce::from_slice(&capability.nonce()),
            Payload {
                msg: capability.sealed_payload(),
                aad: WAKE_CAPABILITY_ASSOCIATED_DATA,
            },
        )
        .map_err(|_| AdapterError::new("invalid_wake", "wake capability opening failed"))?;
    let opened_payload = WakeCapabilityPayload::decode(&opened)
        .map_err(|_| AdapterError::new("invalid_wake", "opened wake payload is malformed"))?;

    let register = WakeRegisterRequest {
        platform,
        environment,
        profile,
        provider_token: capability_payload.provider_token.clone(),
        app_topic: capability_payload.app_topic.clone(),
        request_nonce: hex_array::<16>(arguments, "register_nonce_hex")?,
    };
    let register_bytes = register
        .encode()
        .map_err(|_| AdapterError::new("invalid_wake", "wake registration encoding failed"))?;
    let register_round_trip = WakeRegisterRequest::decode(&register_bytes)
        .map_err(|_| AdapterError::new("invalid_wake", "wake registration decoding failed"))?
        == register;

    let issued = WakeRegisterResponse::issued(expires_at, capability.clone())
        .map_err(|_| AdapterError::new("invalid_wake", "wake issued response failed"))?;
    let issued_bytes = issued
        .encode()
        .map_err(|_| AdapterError::new("invalid_wake", "wake response encoding failed"))?;
    let issued_round_trip = WakeRegisterResponse::decode(&issued_bytes)
        .map_err(|_| AdapterError::new("invalid_wake", "wake response decoding failed"))?
        == issued;
    let refused = WakeRegisterResponse::refused();
    let refused_bytes = refused
        .encode()
        .map_err(|_| AdapterError::new("invalid_wake", "wake refusal encoding failed"))?;
    let refused_round_trip = WakeRegisterResponse::decode(&refused_bytes)
        .map_err(|_| AdapterError::new("invalid_wake", "wake refusal decoding failed"))?
        == refused;

    let trigger = WakeTriggerRequest {
        capability: capability.clone(),
        request_nonce: hex_array::<16>(arguments, "trigger_nonce_hex")?,
    };
    let trigger_bytes = trigger
        .encode()
        .map_err(|_| AdapterError::new("invalid_wake", "wake trigger encoding failed"))?;
    let trigger_round_trip = WakeTriggerRequest::decode(&trigger_bytes)
        .map_err(|_| AdapterError::new("invalid_wake", "wake trigger decoding failed"))?
        == trigger;
    let generic = wake_generic_response();
    verify_wake_generic_response(&generic)
        .map_err(|_| AdapterError::new("invalid_wake", "wake generic response failed"))?;

    let origin = string(arguments, "canonical_provider_origin")?;
    let static_key = hex_array::<32>(arguments, "provider_static_key_hex")?;
    let provider_id = wake_provider_id(origin.as_bytes(), &static_key)
        .map_err(|_| AdapterError::new("invalid_provider", "wake provider is not canonical"))?;
    let control = WakeCapabilityControl {
        sender_account: hex_array::<32>(arguments, "sender_account_hex")?,
        sender_device: hex_array::<32>(arguments, "sender_device_hex")?,
        recipient_account: hex_array::<32>(arguments, "recipient_account_hex")?,
        recipient_device: hex_array::<32>(arguments, "recipient_device_hex")?,
        authority_generation: u64_value(arguments, "authority_generation")?,
        generation: u64_value(arguments, "generation")?,
        capabilities: vec![WakeCapabilityDescriptor {
            origin: origin.to_owned(),
            static_key,
            expires_at,
            capability: capability.clone(),
        }],
    };
    let control_bytes = control.encode().map_err(|_| {
        AdapterError::new(
            "invalid_wake",
            "wake capability control cannot be encoded canonically",
        )
    })?;
    let control_round_trip = WakeCapabilityControl::decode(&control_bytes)
        .map_err(|_| AdapterError::new("invalid_wake", "wake capability control failed"))?
        == control;

    Ok(json!({
        "provider_id_hex": hex::encode(provider_id),
        "capability_plaintext_hex": hex::encode(plaintext),
        "capability_hex": hex::encode(capability.as_bytes()),
        "register_request_hex": hex::encode(register_bytes),
        "issued_response_hex": hex::encode(issued_bytes),
        "refused_response_hex": hex::encode(refused_bytes),
        "trigger_request_hex": hex::encode(trigger_bytes),
        "generic_response_hex": hex::encode(generic),
        "capability_control_hex": hex::encode(control_bytes),
        "opened_matches": opened_payload == capability_payload,
        "register_round_trip": register_round_trip,
        "issued_round_trip": issued_round_trip,
        "refused_round_trip": refused_round_trip,
        "trigger_round_trip": trigger_round_trip,
        "control_round_trip": control_round_trip
    }))
}

fn recovery_authority_trace(arguments: &Value) -> AdapterResult {
    let root = Identity::from_bytes(&hex_array::<64>(arguments, "root_identity_secret_hex")?);
    let mut rng = VectorRng::new(hex_array::<32>(arguments, "rng_seed_hex")?);
    let (package, mnemonic) = seal_account_recovery_authority(&root, &mut rng).map_err(|_| {
        AdapterError::new(
            "recovery_authority_failed",
            "recovery authority could not be sealed",
        )
    })?;
    let public = account_recovery_authority_public(&package).map_err(|_| {
        AdapterError::new(
            "recovery_authority_failed",
            "recovery authority public binding failed",
        )
    })?;
    let opened = open_account_recovery_authority(&package, &mnemonic).map_err(|_| {
        AdapterError::new(
            "recovery_authority_failed",
            "recovery authority could not be opened",
        )
    })?;
    Ok(json!({
        "package_hex": hex::encode(package),
        "mnemonic": &*mnemonic,
        "account_ed25519_hex": hex::encode(public.ed),
        "account_x25519_hex": hex::encode(public.x),
        "opened_matches": opened.public() == root.public()
    }))
}

fn root_free_backup_trace(arguments: &Value) -> AdapterResult {
    let root = Identity::from_bytes(&hex_array::<64>(arguments, "root_identity_secret_hex")?);
    let device = Identity::from_bytes(&hex_array::<64>(arguments, "device_identity_secret_hex")?);
    let discovery = hex_array::<32>(arguments, "discovery_capability_hex")?;
    if discovery == [0u8; 32] {
        return Err(AdapterError::new(
            "invalid_arguments",
            "discovery capability must be non-zero",
        ));
    }
    let profile = KdfProfile {
        m_cost_kib: u32_value(arguments, "memory_kib")?,
        t_cost: u32_value(arguments, "iterations")?,
        p_cost: u32_value(arguments, "parallelism")?,
    };
    let created_at = u64_value(arguments, "created_at")?;
    let recovered_at = u64_value(arguments, "recovered_at")?;
    let profile_passphrase = hex_bytes(arguments, "profile_passphrase_hex")?;
    let restored_passphrase = hex_bytes(arguments, "restored_passphrase_hex")?;
    let prekey_marker = hex_bytes(arguments, "live_prekey_marker_hex")?;

    let mut authority_rng = VectorRng::new(hex_array::<32>(arguments, "authority_rng_seed_hex")?);
    let manifest = DeviceAuthorityManifest::initial(
        &root,
        &device,
        "Vector device".into(),
        created_at.saturating_sub(1),
        &mut authority_rng,
    )
    .map_err(|_| AdapterError::new("backup_failed", "authority genesis failed"))?;
    let state = DeviceAuthorityStateRecord {
        local_device_secret: device.to_bytes().to_vec(),
        local_certificate: manifest.devices()[0].certificate.clone(),
        accepted_recovery_epoch: manifest.recovery_epoch(),
        accepted_recovery_anchor: manifest.recovery_anchor_id(),
        manifest,
        sync_counter: 0,
        channels: Vec::new(),
        conflicts: Vec::new(),
        discovery: DiscoveryCapabilityState {
            capability: discovery,
            generation: 1,
            legacy_v1_enabled: false,
        },
    };

    let directory = tempfile::tempdir()
        .map_err(|_| AdapterError::new("backup_failed", "temporary directory failed"))?;
    let source_path = directory.path().join("source.db");
    let mut store_rng = VectorRng::new(hex_array::<32>(arguments, "store_rng_seed_hex")?);
    let store = Store::create_authority_profile(
        &source_path,
        &profile_passphrase,
        profile,
        &root.public(),
        &state,
        &prekey_marker,
        &mut store_rng,
    )
    .map_err(|_| AdapterError::new("backup_failed", "root-free profile creation failed"))?;
    let mut backup_rng = VectorRng::new(hex_array::<32>(arguments, "backup_rng_seed_hex")?);
    let (backup, mnemonic) = store
        .export_authority_backup(created_at, &mut backup_rng)
        .map_err(|_| AdapterError::new("backup_failed", "KKR10 export failed"))?;
    drop(store);

    if backup.len() < 32 || backup[..4] != AUTHORITY_BACKUP_MAGIC {
        return Err(AdapterError::new(
            "backup_failed",
            "KKR10 header is missing",
        ));
    }
    let word = |offset: usize| {
        u32::from_le_bytes(
            backup[offset..offset + 4]
                .try_into()
                .expect("fixed KKR10 header"),
        )
    };

    let restored_path = directory.path().join("restored.db");
    let mut restore_rng = VectorRng::new(hex_array::<32>(arguments, "restore_rng_seed_hex")?);
    let (restored, recovered_device, recovered_state, ()) =
        Store::restore_authority_backup_with_initializer(
            &restored_path,
            &backup,
            &mnemonic,
            &root,
            recovered_at,
            &restored_passphrase,
            profile,
            &mut restore_rng,
            |_store, _rng| Ok(()),
        )
        .map_err(|_| AdapterError::new("backup_failed", "KKR10 restore failed"))?;
    let restored_account = restored
        .get_account_identity()
        .map_err(|_| AdapterError::new("backup_failed", "restored account read failed"))?
        .ok_or_else(|| AdapterError::new("backup_failed", "restored account is missing"))?;
    drop(restored);
    let root_secret = root.to_bytes();
    let old_device_secret = device.to_bytes();

    Ok(json!({
        "backup_hex": hex::encode(&backup),
        "backup_sha256_hex": hex::encode(Sha256::digest(&backup)),
        "mnemonic": &*mnemonic,
        "header": {
            "magic_hex": hex::encode(&backup[..4]),
            "memory_kib": word(4),
            "iterations": word(8),
            "parallelism": word(12),
            "salt_hex": hex::encode(&backup[16..32]),
            "sealed_bytes": backup.len() - 32
        },
        "account_ed25519_hex": hex::encode(root.public().ed),
        "restored_account_matches": restored_account == root.public(),
        "recovered_device_ed25519_hex": hex::encode(recovered_device.public().ed),
        "recovered_generation": recovered_state.manifest.generation(),
        "recovered_epoch": recovered_state.manifest.recovery_epoch(),
        "active_after_restore": recovered_state.manifest.devices()
            .iter().filter(|entry| entry.is_active()).count(),
        "root_secret_bytes_present": contains_subslice(&backup, root_secret.as_ref()),
        "old_device_secret_bytes_present": contains_subslice(
            &backup,
            old_device_secret.as_ref()
        ),
        "live_prekey_marker_present": !prekey_marker.is_empty()
            && contains_subslice(&backup, &prekey_marker)
    }))
}

fn device_authority_trace(arguments: &Value) -> AdapterResult {
    let root = Identity::from_bytes(&hex_array::<64>(arguments, "root_identity_secret_hex")?);
    let device_one = Identity::from_bytes(&hex_array::<64>(arguments, "device_one_secret_hex")?);
    let device_two = Identity::from_bytes(&hex_array::<64>(arguments, "device_two_secret_hex")?);
    let recovery_device =
        Identity::from_bytes(&hex_array::<64>(arguments, "recovery_device_secret_hex")?);
    let issued_at = u64_value(arguments, "issued_at")?;
    let recovered_at = u64_value(arguments, "recovered_at")?;

    let mut genesis_rng = VectorRng::new(hex_array::<32>(arguments, "genesis_rng_seed_hex")?);
    let genesis = DeviceAuthorityManifest::initial(
        &root,
        &device_one,
        "Primary".into(),
        issued_at,
        &mut genesis_rng,
    )
    .map_err(|_| AdapterError::new("authority_failed", "genesis creation failed"))?;

    let mut certificate_rng =
        VectorRng::new(hex_array::<32>(arguments, "certificate_rng_seed_hex")?);
    let certificate = DeviceAuthorityCertificate::issue(
        root.public(),
        &device_two,
        issued_at + 1,
        &mut certificate_rng,
    )
    .map_err(|_| AdapterError::new("authority_failed", "certificate creation failed"))?;
    let mut proposal_rng = VectorRng::new(hex_array::<32>(arguments, "proposal_rng_seed_hex")?);
    let mut transition = genesis
        .propose_add_device(
            certificate,
            "Secondary".into(),
            issued_at + 1,
            &mut proposal_rng,
        )
        .map_err(|_| AdapterError::new("authority_failed", "add-device proposal failed"))?;
    genesis
        .sign_transition(&mut transition, &device_one)
        .map_err(|_| AdapterError::new("authority_failed", "quorum approval failed"))?;
    let linked = genesis
        .append(transition)
        .map_err(|_| AdapterError::new("authority_failed", "approved transition failed"))?;

    let mut recovery_rng = VectorRng::new(hex_array::<32>(arguments, "recovery_rng_seed_hex")?);
    let recovered = linked
        .recover(
            &root,
            &recovery_device,
            "Recovered".into(),
            recovered_at,
            &mut recovery_rng,
        )
        .map_err(|_| AdapterError::new("authority_failed", "root recovery failed"))?;

    Ok(json!({
        "genesis_hex": hex::encode(genesis.encode().map_err(|_| {
            AdapterError::new("authority_failed", "genesis encoding failed")
        })?),
        "linked_hex": hex::encode(linked.encode().map_err(|_| {
            AdapterError::new("authority_failed", "linked encoding failed")
        })?),
        "recovered_hex": hex::encode(recovered.encode().map_err(|_| {
            AdapterError::new("authority_failed", "recovery encoding failed")
        })?),
        "genesis_state_id_hex": hex::encode(genesis.state_id()),
        "linked_state_id_hex": hex::encode(linked.state_id()),
        "recovered_state_id_hex": hex::encode(recovered.state_id()),
        "linked_generation": linked.generation(),
        "linked_quorum_threshold": linked.quorum_threshold(),
        "recovery_epoch": recovered.recovery_epoch(),
        "active_after_recovery": recovered.devices().iter()
            .filter(|entry| entry.is_active()).count(),
        "genesis_to_linked": authority_relation_name(genesis.relation(&linked).map_err(|_| {
            AdapterError::new("authority_failed", "authority relation failed")
        })?),
        "linked_to_recovered": authority_relation_name(linked.relation(&recovered).map_err(|_| {
            AdapterError::new("authority_failed", "recovery relation failed")
        })?),
        "recovered_to_linked": authority_relation_name(recovered.relation(&linked).map_err(|_| {
            AdapterError::new("authority_failed", "old-epoch relation failed")
        })?)
    }))
}

fn device_authority_verify(arguments: &Value) -> AdapterResult {
    let encoded = hex_bytes(arguments, "encoded_hex")?;
    let manifest = DeviceAuthorityManifest::decode(&encoded).map_err(|_| {
        AdapterError::new("invalid_authority", "authority proof failed verification")
    })?;
    let active = manifest
        .devices()
        .iter()
        .filter(|entry| entry.is_active())
        .count();
    Ok(json!({
        "account_ed25519_hex": hex::encode(manifest.account().ed),
        "generation": manifest.generation(),
        "recovery_epoch": manifest.recovery_epoch(),
        "state_id_hex": hex::encode(manifest.state_id()),
        "active_devices": active,
        "total_entries": manifest.devices().len(),
        "quorum_threshold": manifest.quorum_threshold()
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PqxdhTraceArguments {
    alice_identity_secret_hex: String,
    bob_identity_secret_hex: String,
    signed_prekey_secret_hex: String,
    one_time_prekey_secret_hex: String,
    pq_prekey_rng_seed_hex: String,
    initiate_rng_seed_hex: String,
    responder_rng_seed_hex: String,
    sender_rng_seed_hex: String,
    receiver_rng_seed_hex: String,
    bob_sender_rng_seed_hex: String,
    alice_receiver_rng_seed_hex: String,
    post_ratchet_sender_rng_seed_hex: String,
    post_ratchet_receiver_rng_seed_hex: String,
    first_payload_hex: String,
    followup_payloads_hex: Vec<String>,
    delivery_order: Vec<usize>,
    bob_reply_hex: String,
    alice_post_ratchet_hex: String,
    now: u64,
    expires_at: u64,
}

fn pqxdh_trace(arguments: &Value) -> AdapterResult {
    let args: PqxdhTraceArguments = serde_json::from_value(arguments.clone()).map_err(|_| {
        AdapterError::new("invalid_arguments", "PQXDH trace arguments are incomplete")
    })?;
    if args.delivery_order.len() != args.followup_payloads_hex.len()
        || args
            .delivery_order
            .iter()
            .any(|index| *index >= args.followup_payloads_hex.len())
        || {
            let mut order = args.delivery_order.clone();
            order.sort_unstable();
            order.dedup();
            order.len() != args.delivery_order.len()
        }
    {
        return Err(AdapterError::new(
            "invalid_arguments",
            "delivery order must name every follow-up exactly once",
        ));
    }

    let alice = Identity::from_bytes(&decode_hex_exact::<64>(&args.alice_identity_secret_hex)?);
    let bob = Identity::from_bytes(&decode_hex_exact::<64>(&args.bob_identity_secret_hex)?);
    let spk =
        SignedPrekeySecret::from_bytes(7, &decode_hex_exact::<32>(&args.signed_prekey_secret_hex)?);
    let opk = OneTimePrekeySecret::from_bytes(
        9,
        &decode_hex_exact::<32>(&args.one_time_prekey_secret_hex)?,
    );
    let mut pq_rng = VectorRng::new(decode_hex_exact::<32>(&args.pq_prekey_rng_seed_hex)?);
    let pqspk = PqPrekeySecret::generate(&mut pq_rng, 8);
    let bundle = PrekeyBundle::build(&bob, &spk, &pqspk, Some(&opk), args.expires_at, vec![]);
    let verified = bundle.verify(args.now).map_err(|_| {
        AdapterError::new("invalid_bundle", "generated vector bundle did not verify")
    })?;

    let mut initiate_rng = VectorRng::new(decode_hex_exact::<32>(&args.initiate_rng_seed_hex)?);
    let first_payload = decode_hex(&args.first_payload_hex)?;
    let (mut alice_session, initial) = initiate(
        &alice,
        &verified,
        &first_payload,
        args.now,
        &mut initiate_rng,
    )
    .map_err(|_| AdapterError::new("handshake_failed", "PQXDH initiation failed"))?;
    let mut responder_rng = VectorRng::new(decode_hex_exact::<32>(&args.responder_rng_seed_hex)?);
    let (mut bob_session, opened_first) = respond(
        &bob,
        &spk,
        &pqspk,
        Some(&opk),
        &initial,
        args.now,
        &mut responder_rng,
    )
    .map_err(|_| AdapterError::new("handshake_failed", "PQXDH response failed"))?;

    let mut sender_rng = VectorRng::new(decode_hex_exact::<32>(&args.sender_rng_seed_hex)?);
    let mut followups = Vec::with_capacity(args.followup_payloads_hex.len());
    for payload in &args.followup_payloads_hex {
        let payload = decode_hex(payload)?;
        followups.push(alice_session.encrypt(&mut sender_rng, args.now, &payload, &[]));
    }
    let mut receiver_rng = VectorRng::new(decode_hex_exact::<32>(&args.receiver_rng_seed_hex)?);
    let mut delivered = Vec::with_capacity(args.delivery_order.len());
    for index in &args.delivery_order {
        let plaintext = bob_session
            .decrypt(&mut receiver_rng, args.now, &followups[*index], &[])
            .map_err(|_| AdapterError::new("ratchet_failed", "follow-up delivery failed"))?;
        delivered.push(json!({
            "message_index": index,
            "plaintext_hex": hex::encode(plaintext)
        }));
    }
    let replay_rejected = bob_session
        .decrypt(
            &mut receiver_rng,
            args.now,
            &followups[args.delivery_order[0]],
            &[],
        )
        .is_err();

    let bob_reply = decode_hex(&args.bob_reply_hex)?;
    let mut bob_sender_rng = VectorRng::new(decode_hex_exact::<32>(&args.bob_sender_rng_seed_hex)?);
    let bob_message = bob_session.encrypt(&mut bob_sender_rng, args.now, &bob_reply, &[]);
    let mut alice_receiver_rng =
        VectorRng::new(decode_hex_exact::<32>(&args.alice_receiver_rng_seed_hex)?);
    let opened_bob_reply = alice_session
        .decrypt(&mut alice_receiver_rng, args.now, &bob_message, &[])
        .map_err(|_| AdapterError::new("ratchet_failed", "reply delivery failed"))?;

    let alice_post_ratchet = decode_hex(&args.alice_post_ratchet_hex)?;
    let mut post_sender_rng = VectorRng::new(decode_hex_exact::<32>(
        &args.post_ratchet_sender_rng_seed_hex,
    )?);
    let post_message =
        alice_session.encrypt(&mut post_sender_rng, args.now, &alice_post_ratchet, &[]);
    let mut post_receiver_rng = VectorRng::new(decode_hex_exact::<32>(
        &args.post_ratchet_receiver_rng_seed_hex,
    )?);
    let opened_post = bob_session
        .decrypt(&mut post_receiver_rng, args.now, &post_message, &[])
        .map_err(|_| AdapterError::new("ratchet_failed", "post-ratchet delivery failed"))?;

    Ok(json!({
        "bundle_hex": hex::encode(bundle.encode()),
        "initial_message_hex": hex::encode(initial.encode()),
        "session_id_hex": hex::encode(alice_session.session_id()),
        "alice_mailbox_key_hex": hex::encode(*alice_session.mailbox_key()),
        "bob_mailbox_key_hex": hex::encode(*bob_session.mailbox_key()),
        "hybrid_service_exporter_hex": alice_session
            .hybrid_service_exporter()
            .map(|value| hex::encode(*value)),
        "opened_first_hex": hex::encode(opened_first),
        "followup_messages_hex": followups
            .iter()
            .map(|message| hex::encode(message.encode()))
            .collect::<Vec<_>>(),
        "delivered": delivered,
        "replay_rejected": replay_rejected,
        "bob_reply_message_hex": hex::encode(bob_message.encode()),
        "opened_bob_reply_hex": hex::encode(opened_bob_reply),
        "alice_post_ratchet_message_hex": hex::encode(post_message.encode()),
        "opened_alice_post_ratchet_hex": hex::encode(opened_post)
    }))
}

fn envelope_kind_name(kind: EnvelopeKind) -> &'static str {
    match kind {
        EnvelopeKind::Message => "message",
        EnvelopeKind::Handshake => "handshake",
        EnvelopeKind::Receipt => "receipt",
        EnvelopeKind::Fragment => "fragment",
        EnvelopeKind::GroupControl => "group_control",
        EnvelopeKind::GroupMessage => "group_message",
    }
}

fn authority_relation_name(relation: DeviceAuthorityRelation) -> &'static str {
    match relation {
        DeviceAuthorityRelation::Same => "same",
        DeviceAuthorityRelation::Descendant => "descendant",
        DeviceAuthorityRelation::Stale => "stale",
        DeviceAuthorityRelation::RecoverySupersedes => "recovery_supersedes",
        DeviceAuthorityRelation::OldEpoch => "old_epoch",
        DeviceAuthorityRelation::Fork => "fork",
        DeviceAuthorityRelation::RecoveryConflict => "recovery_conflict",
    }
}

fn object(arguments: &Value) -> Result<&serde_json::Map<String, Value>, AdapterError> {
    arguments
        .as_object()
        .ok_or_else(|| AdapterError::new("invalid_arguments", "arguments must be a JSON object"))
}

fn string<'a>(arguments: &'a Value, name: &str) -> Result<&'a str, AdapterError> {
    object(arguments)?
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AdapterError::new(
                "invalid_arguments",
                format!("argument {name} must be a string"),
            )
        })
}

fn u64_value(arguments: &Value, name: &str) -> Result<u64, AdapterError> {
    object(arguments)?
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            AdapterError::new(
                "invalid_arguments",
                format!("argument {name} must be an unsigned integer"),
            )
        })
}

fn usize_value(arguments: &Value, name: &str) -> Result<usize, AdapterError> {
    let value = u64_value(arguments, name)?;
    usize::try_from(value).map_err(|_| {
        AdapterError::new(
            "invalid_arguments",
            format!("argument {name} exceeds the local integer range"),
        )
    })
}

fn u32_value(arguments: &Value, name: &str) -> Result<u32, AdapterError> {
    let value = u64_value(arguments, name)?;
    u32::try_from(value)
        .map_err(|_| AdapterError::new("invalid_arguments", format!("argument {name} exceeds u32")))
}

fn u8_value(arguments: &Value, name: &str) -> Result<u8, AdapterError> {
    let value = u64_value(arguments, name)?;
    u8::try_from(value)
        .map_err(|_| AdapterError::new("invalid_arguments", format!("argument {name} exceeds u8")))
}

fn optional_u64(arguments: &Value, name: &str) -> Result<Option<u64>, AdapterError> {
    match object(arguments)?.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            AdapterError::new(
                "invalid_arguments",
                format!("argument {name} must be null or an unsigned integer"),
            )
        }),
    }
}

fn hex_bytes(arguments: &Value, name: &str) -> Result<Vec<u8>, AdapterError> {
    decode_hex(string(arguments, name)?)
}

fn optional_hex_bytes(arguments: &Value, name: &str) -> Result<Option<Vec<u8>>, AdapterError> {
    match object(arguments)?.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => decode_hex(value).map(Some),
        Some(_) => Err(AdapterError::new(
            "invalid_arguments",
            format!("argument {name} must be null or a hex string"),
        )),
    }
}

fn hex_array<const N: usize>(arguments: &Value, name: &str) -> Result<[u8; N], AdapterError> {
    decode_hex_exact(string(arguments, name)?)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, AdapterError> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AdapterError::new(
            "invalid_hex",
            "hex values must contain an even number of ASCII hexadecimal digits",
        ));
    }
    hex::decode(value)
        .map_err(|_| AdapterError::new("invalid_hex", "hex value could not be decoded"))
}

fn decode_hex_exact<const N: usize>(value: &str) -> Result<[u8; N], AdapterError> {
    let bytes = decode_hex(value)?;
    bytes.try_into().map_err(|_| {
        AdapterError::new(
            "invalid_length",
            format!("hex value must decode to exactly {N} bytes"),
        )
    })
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Deterministic SHA-256 counter stream used only by public test vectors.
///
/// Each block is `SHA-256("Komms-Conformance-RNG-v1" || seed || u64_be(i))`.
/// This is not a production random generator.
struct VectorRng {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 32],
    offset: usize,
}

impl VectorRng {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            block: [0u8; 32],
            offset: 32,
        }
    }

    fn refill(&mut self) {
        let mut hash = Sha256::new();
        hash.update(VECTOR_RNG_DOMAIN);
        hash.update(self.seed);
        hash.update(self.counter.to_be_bytes());
        self.block.copy_from_slice(&hash.finalize());
        self.counter = self.counter.wrapping_add(1);
        self.offset = 0;
    }
}

impl RngCore for VectorRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut written = 0;
        while written < dest.len() {
            if self.offset == self.block.len() {
                self.refill();
            }
            let available = self.block.len() - self.offset;
            let take = available.min(dest.len() - written);
            dest[written..written + take]
                .copy_from_slice(&self.block[self.offset..self.offset + take]);
            self.offset += take;
            written += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for VectorRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_json_and_unknown_operation_are_bounded() {
        let malformed = process_request_bytes(b"{");
        assert_eq!(malformed["error"]["code"], "invalid_json");

        let unknown =
            process_request_bytes(br#"{"id":"case","operation":"unknown","arguments":{}}"#);
        assert_eq!(unknown["id"], "case");
        assert_eq!(unknown["error"]["code"], "unsupported_operation");
    }

    #[test]
    fn vector_rng_is_chunking_independent() {
        let seed = [7u8; 32];
        let mut one = VectorRng::new(seed);
        let mut all = [0u8; 97];
        one.fill_bytes(&mut all);

        let mut chunks = VectorRng::new(seed);
        let mut joined = Vec::new();
        for len in [1usize, 31, 32, 33] {
            let mut part = vec![0u8; len];
            chunks.fill_bytes(&mut part);
            joined.extend_from_slice(&part);
        }
        assert_eq!(all.as_slice(), joined.as_slice());
    }
}
