# dlms-association API

## 1. Public Headers

```text
include/dlms/association/association_client.hpp
include/dlms/association/association_c_api.h
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
client.Release();

const dlms::association::AssociationResult& result =
  client.Result();

client.Close();
```

`Release()` performs the confirmed association release exchange. It sends RLRQ,
expects RLRE, and closes the lower APDU channel on success. If sending,
receiving, or decoding RLRE fails, the client remains associated so `Close()`
can still be used as an unconfirmed fallback.

`AssociationClient` does not own the lower channel object. The caller must keep
the channel alive for the lifetime of the association client.

## 6. C API

The C ABI mirrors the C++ client lifecycle through an opaque
`dlms_association_client_t` handle:

```c
dlms_association_client_t* client =
  dlms_association_create_client_from_callbacks(&callbacks, &options);

dlms_association_open(client);
dlms_association_establish(client);
dlms_association_release(client);
dlms_association_close(client);
dlms_association_destroy_client(client);
```

The C API does not own a `dlms-profile` channel from another C ABI. It owns a
small callback-based APDU channel adapter supplied by the caller. Callback
return values are association statuses and are mapped to profile-channel
statuses internally.

Use `dlms_association_default_options()` before changing individual fields.
Use `dlms_association_get_result()` after a successful establish to copy the
negotiated context into a caller-owned result struct.
