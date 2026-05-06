# dlms-association API

## 1. Public Headers

```text
include/dlms/association/association_client.hpp
include/dlms/association/association_status.hpp
include/dlms/association/association_types.hpp
```

## 2. Status

`AssociationStatus` is the stable C++ status contract:

- `Ok`
- `InvalidArgument`
- `InvalidState`
- `AlreadyAssociated`
- `UnsupportedAuthentication`
- `ChannelOpenFailed`
- `ChannelCloseFailed`
- `SendFailed`
- `ReceiveFailed`
- `EncodeFailed`
- `DecodeFailed`
- `AssociationRejected`
- `NegotiationFailed`
- `InternalError`

## 3. Options

`AssociationOptions` contains:

- `applicationContext`
- `authenticationMode`
- `proposedDlmsVersionNumber`
- `proposedConformance`
- `clientMaxReceivePduSize`

`DefaultAssociationOptions()` returns a no-authentication LN association
proposal using `dlms-apdu` default xDLMS initiate settings.

## 4. Result

`AssociationResult` contains:

- `negotiatedDlmsVersionNumber`
- `negotiatedConformance`
- `serverMaxReceivePduSize`
- `vaaName`
- `aareResult`
- `aareDiagnostic`

## 5. Client

```cpp
dlms::association::AssociationClient client(channel, options);

client.Open();
client.Establish();

const dlms::association::AssociationResult& result =
  client.Result();

client.Close();
```

`AssociationClient` does not own the lower channel object. The caller must keep
the channel alive for the lifetime of the association client.
