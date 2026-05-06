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

The first implementation shall reject authentication modes other than `None`.
It shall not encode ACSE authentication requirements, mechanism name,
authentication value, ciphered initiate request, or dedicated key.

Future security work belongs in a dedicated security/authentication layer or a
later association phase with explicit interfaces.

## 6. Out of Scope

- C API
- server-side acceptor
- HLS challenge/response
- global or dedicated ciphering
- retry policies for failed AARE receive
- object model and high-level GET/SET/ACTION client
