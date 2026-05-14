# dlms-association Requirements

## 1. Scope

The association layer owns the DLMS/COSEM application association lifecycle.
It sits above the APDU channel profile layer and below future client/object
model layers.

The layer shall:

- open and close the lower `dlms-profile` APDU channel
- construct AARQ APDUs with xDLMS InitiateRequest
- send AARQ and receive AARE
- decode AARE result, diagnostic, and xDLMS InitiateResponse
- construct RLRQ APDUs and accept RLRE for clean release
- expose negotiated association parameters
- reject invalid state transitions
- keep APDU codec details delegated to `dlms-apdu`
- keep transport/profile framing delegated to `dlms-profile`

## 2. Normative Model

Document RAG references:

- Green Book edition 8.3 describes `COSEM-OPEN` and states that the proposed
  xDLMS context is carried by an InitiateRequest in the AARQ user-information
  field.
- The AARE user-information field carries either the negotiated
  InitiateResponse or a confirmedServiceError when xDLMS context negotiation is
  rejected.
- The negotiated context includes negotiated conformance, server maximum
  receive PDU size, and VAA name.
- ACSE authentication fields depend on the selected authentication mechanism;
  the first implementation supports only no-authentication association.

## 3. First Implementation

Version 1 implements a client-side confirmed association open flow only:

1. `AssociationClient::Open()` opens the lower APDU channel.
2. `AssociationClient::Establish()` builds AARQ from configured xDLMS options.
3. The AARQ bytes are sent through `dlms::profile::IApduChannel`.
4. One APDU is received and decoded as AARE.
5. A successful AARE moves the client to `Associated`.
6. The negotiated context is stored in `AssociationResult`.

## 4. State Requirements

The client state machine shall use these stable states:

- `Closed`
- `Open`
- `Associating`
- `Associated`

Rules:

- `Establish()` from `Closed` is invalid.
- `Establish()` from `Associated` returns `AlreadyAssociated`.
- failed send, receive, or decode returns to `Open`
- rejected AARE returns to `Open`
- `Close()` closes the lower channel and returns to `Closed`
- `Release()` is valid only from `Associated`
- successful `Release()` sends RLRQ, receives RLRE, closes the lower channel,
  clears negotiated context, and returns to `Closed`
- failed `Release()` leaves the client `Associated` so the caller can fall back
  to `Close()`

## 5. Security Boundary

The layer shall model the association authentication boundary without owning
cryptographic algorithms or secret lifecycle.

The phase 4 boundary shall:

- keep `None` as the default lowest-level security mode
- model Low Level Security (LLS) credentials in `AssociationOptions`
- reject LLS when no credential is configured
- encode LLS AARQ authentication fields when a credential is configured
- model High Level Security (HLS) as a delegated strategy interface
- reject HLS when no strategy is configured
- let the strategy validate the selected HLS mechanism and provide the initial
  client-to-server challenge bytes
- keep the HLS pass-3/pass-4 xDLMS method exchange out of this layer until the
  future client/object layer exists
- keep global ciphering, dedicated ciphering, keys, invocation counters, and
  security suite algorithms outside this repo

LLS credentials are caller-supplied bytes. The association layer shall send
them exactly as supplied in the ACSE calling-authentication-value field. It
shall not hash, derive, persist, or otherwise transform the credential.

## 6. Out of Scope

- server-side acceptor
- global or dedicated ciphering
- retry policies for failed AARE receive
- object model and high-level GET/SET/ACTION client
