# dlms-association Implementation Plan

## Phase 0. Documentation

Deliverables:

- requirements
- API contract
- architecture diagrams
- test plan

Commit message:

```text
docs(association): define association layer
```

## Phase 1. Client Association Open

Deliverables:

- CMake project and test harness
- `AssociationStatus`
- `AssociationOptions`
- `AssociationResult`
- `AssociationClient`
- fake-channel tests for successful and failed AARE paths

Verification:

- build target `dlms_association`
- run `dlms_association_tests`
- run root integration build and test suite

Commit message:

```text
feat(association): add client open handshake
```

## Phase 2. Release Association

Deliverables:

- RLRQ/RLRE encode/decode dependency boundary
- client release state transition
- tests for clean release and close fallback

## Phase 3. C API

Deliverables:

- stable C ABI handles
- callback-based channel adapter
- C header smoke test

## Phase 4. Authentication Boundary

Deliverables:

- documentation-first contract for LLS/HLS boundary
- LLS credential option modeling
- HLS strategy interface
- tests for unsupported and delegated authentication modes

Commit messages:

```text
docs(association): specify authentication boundary
feat(association): model authentication boundary
```

## Phase 5. LLS AARQ Authentication

Deliverables:

- documentation-first contract for LLS ACSE fields
- validation that accepts non-empty LLS credentials
- AARQ sender ACSE requirements field
- AARQ low-level-security mechanism name field
- AARQ calling authentication value field
- tests for exact credential preservation

Commit messages:

```text
docs(association): define LLS AARQ authentication
feat(association): encode LLS AARQ authentication
```

## Phase 6. HLS AARQ Boundary

Deliverables:

- documentation-first contract for HLS ACSE fields;
- AARQ sender ACSE requirements field;
- AARQ HLS mechanism-name field;
- AARQ calling-authentication-value field with the initial client challenge;
- AARE server challenge extraction into `AssociationResult`;
- tests for mechanism ids, challenge validation, exact challenge preservation,
  and malformed AARE authentication values.

Commit messages:

```text
docs(association): define HLS AARQ boundary
feat(association): encode HLS AARQ authentication
```
