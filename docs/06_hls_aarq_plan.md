# HLS AARQ Boundary Plan

## 1. Scope

This phase enables the ACSE part of High Level Security association setup in
`dlms-association`.

It covers:

- `AuthenticationMode::HighLevelSecurity` option validation;
- AARQ sender ACSE requirements field;
- AARQ authentication mechanism name field;
- AARQ calling-authentication-value field containing the client-to-server
  challenge supplied by `IHighLevelSecurityStrategy`;
- AARE responding-authentication-value server-to-client challenge extraction
  for the caller.

It does not cover:

- xDLMS ACTION pass-3/pass-4 execution;
- GMAC, MD5, SHA-1, SHA-256, or ECDSA cryptographic processing;
- key storage or invocation counter storage;
- client-level HLS orchestration.

The security layer owns challenge processing. The client layer owns the
subsequent Association LN method call once `dlms-association` exposes the
server challenge.

## 2. Standards Boundary

The COSEM authentication mechanism name object identifier uses the common
prefix:

```text
{ joint-iso-ccitt(2) country(16) country-name(756)
  identified-organization(5) DLMS-UA(8)
  authentication_mechanism_name(2) mechanism_id(x) }
```

For the mechanisms modeled by this repo:

| Mechanism | mechanism_id |
|---|---:|
| HLS High | `2` |
| HLS MD5 | `3` |
| HLS SHA-1 | `4` |
| HLS GMAC | `5` |

The encoded ACSE mechanism-name field therefore keeps the existing prefix
bytes and changes only the final mechanism id byte:

```text
8B 07 60 85 74 05 08 02 <mechanism_id>
```

## 3. API Contract

`IHighLevelSecurityStrategy` remains a non-owning strategy pointer:

```cpp
class IHighLevelSecurityStrategy
{
public:
  virtual HighLevelSecurityMechanism Mechanism() const = 0;
  virtual AssociationStatus BuildInitialChallenge(
    std::vector<std::uint8_t>& output) const = 0;
};
```

For this phase, `BuildInitialChallenge()` supplies only the AARQ
client-to-server challenge bytes. The strategy is not called for pass-3/pass-4
inside `dlms-association`.

`AssociationResult` shall expose the server-to-client challenge decoded from
the AARE responding-authentication-value field:

```cpp
std::vector<std::uint8_t> highLevelSecurityServerChallenge;
```

The vector is empty when the AARE has no HLS challenge or when no HLS mode was
used.

## 4. Validation

HLS validation shall:

- require a non-null `highLevelSecurity` strategy;
- reject `HighLevelSecurityMechanism::Unknown`;
- call `BuildInitialChallenge()` exactly once while building AARQ;
- reject empty challenges;
- reject challenges longer than 125 bytes while ACSE raw fields use short-form
  BER lengths;
- keep MD5/SHA-1 modeled but not cryptographically implemented in this layer.

Validation shall no longer reject HLS after a valid strategy returns a valid
challenge.

## 5. AARQ Fields

For HLS, `BuildAarq()` shall add:

```text
8A 02 07 80
8B 07 60 85 74 05 08 02 <mechanism_id>
AC <challenge_size + 2> 80 <challenge_size> <challenge_bytes>
```

The challenge bytes are forwarded exactly as supplied by the strategy.

## 6. AARE Fields

`DecodeAare()` shall scan raw AARE fields for
`responding-authentication-value` tag `0xAA` and extract the inner charstring
value when encoded as:

```text
AA <size + 2> 80 <size> <server_challenge_bytes>
```

Malformed authentication value fields shall be ignored for non-HLS modes and
shall return `DecodeFailed` for HLS mode.

## 7. Test Plan

Deterministic tests shall cover:

- HLS High AARQ contains sender ACSE requirements, mechanism id `2`, and the
  exact client challenge;
- HLS GMAC AARQ contains sender ACSE requirements, mechanism id `5`, and the
  exact client challenge;
- HLS MD5 and SHA-1 map to mechanism ids `3` and `4`;
- missing strategy, unknown mechanism, empty challenge, and oversize challenge
  fail before send;
- strategy is called once for a successful HLS AARQ build;
- AARE HLS server challenge is exposed in `AssociationResult`;
- malformed AARE HLS authentication value returns `DecodeFailed`.

Root verification remains:

```text
cmake --build build-mingw64
ctest --test-dir build-mingw64 --output-on-failure
```

## 8. Commit Message

```text
docs(association): define HLS AARQ boundary
```
