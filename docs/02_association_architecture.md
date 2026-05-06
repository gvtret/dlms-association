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

## 6. Authentication Boundary

```mermaid
flowchart TD
  Caller["Caller"]
  Options["AssociationOptions"]
  Client["AssociationClient"]
  Hls["IHighLevelSecurityStrategy"]
  Apdu["dlms-apdu ACSE codec"]
  FutureSecurity["Future security layer"]

  Caller --> Options
  Options --> Client
  Client --> Hls
  Hls --> FutureSecurity
  Client --> Apdu
```

```mermaid
sequenceDiagram
  participant App as Caller
  participant Assoc as AssociationClient
  participant Hls as IHighLevelSecurityStrategy
  participant Apdu as dlms-apdu

  App->>Assoc: Establish()
  Assoc->>Assoc: Validate authentication mode
  alt None
    Assoc->>Apdu: Encode AARQ without authentication fields
  else LLS
    Assoc-->>App: UnsupportedAuthentication until ACSE auth encode exists
  else HLS
    Assoc->>Hls: Mechanism()
    Assoc->>Hls: BuildInitialChallenge()
    Assoc-->>App: UnsupportedAuthentication until ACSE auth encode exists
  end
```

`dlms-association` owns only the association state machine and option
validation. Authentication mechanism OIDs, ACSE authentication fields,
challenge functions, ciphering, keys, and invocation counters remain delegated
to `dlms-apdu` or a future security layer.
