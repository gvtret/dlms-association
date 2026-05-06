# dlms-association Test Plan

## 1. Unit Tests

Required first-phase tests:

- default options match the xDLMS initiate defaults used by `dlms-apdu`
- `Open()` maps lower channel open success/failure
- `Close()` is idempotent enough to return to `Closed`
- `Establish()` sends an encoded AARQ
- successful AARE transitions to `Associated`
- rejected AARE returns `AssociationRejected`
- malformed AARE returns `DecodeFailed`
- `Establish()` from `Closed` returns `InvalidState`
- repeated `Establish()` after success returns `AlreadyAssociated`
- unsupported authentication mode returns `UnsupportedAuthentication`

## 2. Integration Tests

Root integration shall later verify association over:

- Wrapper/TCP profile fake stream
- Wrapper/UDP profile fake datagram
- HDLC/LLC profile fake byte stream

The first phase only requires unit-level fake `IApduChannel` tests.

## 3. Verification Commands

Use an existing build directory when one is already configured by the workspace.
The expected root checks are:

```text
cmake --build <build-dir>
ctest --test-dir <build-dir> --output-on-failure
```
