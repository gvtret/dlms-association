# dlms-association

`dlms-association` manages the DLMS/COSEM application association lifecycle
above `dlms-profile` and `dlms-apdu`.

The first implementation provides a client-side confirmed association open
flow:

- build AARQ with xDLMS InitiateRequest
- send it over a profile APDU channel
- receive and decode AARE with xDLMS InitiateResponse
- expose negotiated DLMS version, conformance block, max PDU size, and VAA name
- maintain an association state machine

Out of scope for the first implementation:

- server-side association acceptor
- RLRQ/RLRE release
- LLS/HLS authentication
- ciphered APDUs and dedicated key handling
- COSEM object model and GET/SET/ACTION orchestration

## Build

```text
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

When built inside the root workspace, `dlms-association` links against
`dlms-profile` and `dlms-apdu`.
