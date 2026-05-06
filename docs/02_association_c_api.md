# dlms-association C API

## 1. Scope

The C API exposes the client-side association lifecycle to C callers without
exposing C++ classes or ownership rules.

In scope:

- opaque `dlms_association_client_t` handle
- stable `dlms_association_status_t` values
- stable `dlms_association_state_t` values
- default no-authentication LN options
- callback-based APDU channel adapter
- `open`, `establish`, `release`, `close`, `is_associated`, and result copy

Out of scope:

- direct ownership of `dlms-profile` C ABI handles
- server-side association acceptor
- authentication and ciphering
- asynchronous callbacks or background work

## 2. Callback Channel

The C API creates an association client from callbacks:

```c
typedef dlms_association_status_t (*dlms_association_channel_open_fn)(void*);
typedef dlms_association_status_t (*dlms_association_channel_close_fn)(void*);
typedef dlms_association_status_t (*dlms_association_channel_send_fn)(
  void*, const uint8_t*, size_t);
typedef dlms_association_status_t (*dlms_association_channel_receive_fn)(
  void*, uint8_t*, size_t, size_t*);
```

All callbacks are synchronous. The receive callback writes one complete ACSE
APDU into caller-provided storage and reports its size through `written_size`.

## 3. Options

`dlms_association_default_options()` initializes:

- Logical Name without ciphering
- no authentication
- DLMS version 6
- default proposed conformance copied from `dlms-apdu`
- default client max receive PDU size copied from `dlms-apdu`

## 4. Result

`dlms_association_get_result()` copies the negotiated context:

- negotiated DLMS version
- negotiated conformance bytes
- server max receive PDU size
- VAA name
- AARE result and diagnostic presence/value

The result struct is caller-owned and does not contain borrowed pointers.

## 5. Error Model

Public functions return `dlms_association_status_t`. Null handles and null
required pointers return `DLMS_ASSOCIATION_STATUS_INVALID_ARGUMENT`.

Destroy is null-safe. Exceptions from C++ implementation code are caught and
reported as `DLMS_ASSOCIATION_STATUS_INTERNAL_ERROR`.
