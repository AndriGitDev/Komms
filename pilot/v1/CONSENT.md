# Komms stable-v1 Alpha pilot consent

**Consent version:** `stable-v1-pilot-consent/v1`

Komms is Alpha software. It may fail, lose availability, delay messages, or
require recovery. Do not use this pilot for emergency, safety-critical,
irreplaceable, or legally required communication.

Before installing, the coordinator must show you:

- the exact artifact name and SHA-256 digest;
- how its release evidence and signature are verified;
- the supported device, operating-system, and update limits;
- the current security, availability, notification, and recovery limitations;
- how to get help and report a security problem; and
- the planned pilot start and end dates.

Participation is voluntary. You may stop at any time. Withdrawal stops future
pilot steps and removes the separate consent record according to the pilot
runbook. It cannot erase messages or records retained by another participant,
an operating system, a platform provider, or an aggregate report that no
longer identifies a participant.

## Data boundary

The public pilot record may contain only combined counts, rates, duration
buckets, issue categories, artifact digests, and redacted evidence links. It
must not contain:

- message text, media, filenames, or other message content;
- a contact graph or the identities of communication partners;
- a name, email address, phone number, account fingerprint, device identifier,
  IP address, push token, or other stable participant identifier;
- a participant-by-participant event stream or timeline; or
- raw application, network, notification-provider, or device logs.

Consent records stay in a separate restricted location and are never included
in the repository, release bundle, aggregate worksheet, or public issue
tracker. If a diagnostic is necessary, the participant chooses what to share,
uses the redaction procedure in `SECURITY.md`, and approves the exact retained
attachment.

## Pilot activities

The bounded pilot may ask you to:

1. verify, install, and start the exact Alpha artifact;
2. create a throwaway pilot identity and keep its recovery material safe;
3. establish contact with another consenting participant;
4. exchange non-sensitive test messages;
5. exercise offline delivery and a disclosed fallback;
6. explain the selected Standard, Private, or Sovereign mode in your own words;
7. observe notification behavior under the named device settings;
8. exercise a backup/recovery or controlled interruption path; and
9. report accessibility problems and the support effort required.

The pilot lasts no more than 21 days and accepts no more than 24 consenting
participants. A participant may skip any step and report it as not attempted.

## Consent record

The coordinator records consent outside the repository using a one-time pilot
code that expires when the pilot closes. The record contains only:

- this consent-version identifier;
- the exact artifact/evidence digest shown;
- the time consent was given or withdrawn;
- confirmation that the disclosures above were shown; and
- the one-time pilot code.

The one-time code is not reused as a Komms identity, analytics identifier,
support identifier, or future-pilot identifier.

By affirming the separate consent record, you confirm that you understand the
Alpha limitations, data boundary, voluntary nature, and withdrawal procedure.
