# dlms-association Architecture

## 1. Layer Position

```mermaid
flowchart TD
  Client["Future dlms-client"]
  Association["lib/dlms-association"]
  Apdu["lib/dlms-apdu"]
  Profile["lib/dlms-profile"]
  Lower["transport + hdlc/llc/wrapper"]

  Client --> Association
  Association --> Apdu
  Association --> Profile
  Profile --> Lower
```

## 2. Open Handshake

```mermaid
sequenceDiagram
  participant App as Caller
  participant Assoc as AssociationClient
  participant Apdu as dlms-apdu
  participant Channel as IApduChannel

  App->>Assoc: Open()
  Assoc->>Channel: Open()
  App->>Assoc: Establish()
  Assoc->>Apdu: Encode AARQ(InitiateRequest)
  Assoc->>Channel: SendApdu(AARQ)
  Assoc->>Channel: ReceiveApdu()
  Assoc->>Apdu: Decode AARE(InitiateResponse)
  Assoc-->>App: AssociationResult
```

## 3. State Machine

```mermaid
stateDiagram-v2
  [*] --> Closed
  Closed --> Open: Open ok
  Open --> Associating: Establish
  Associating --> Associated: AARE accepted
  Associating --> Open: send/receive/decode/reject
  Associated --> Closed: Release ok
  Associated --> Associated: Release send/receive/decode failure
  Associated --> Closed: Close
  Open --> Closed: Close
```

## 4. Class Interaction

```mermaid
classDiagram
  class AssociationClient {
    +Open() AssociationStatus
    +Close() AssociationStatus
    +Establish() AssociationStatus
    +Release() AssociationStatus
    +State() AssociationState
    +Result() AssociationResult
  }

  class IApduChannel {
    +Open() ProfileStatus
    +Close() ProfileStatus
    +SendApdu(ProfileByteView) ProfileStatus
    +ReceiveApdu(vector~uint8_t~&) ProfileStatus
  }

  class AssociationOptions
  class AssociationResult
  class dlms_apdu {
    +EncodeAcseApdu()
    +DecodeAcseApdu()
  }

  AssociationClient --> IApduChannel
  AssociationClient --> AssociationOptions
  AssociationClient --> AssociationResult
  AssociationClient --> dlms_apdu
```

## 5. Ownership

`AssociationClient` stores a reference to `dlms::profile::IApduChannel`. It
does not own the channel and does not own transport resources directly.
