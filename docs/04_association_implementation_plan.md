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
