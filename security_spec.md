# AI GOD (GOD-X) v0.1 — Firestore Security Specification (Phase 0 & Phase 5 Audit)

## 1. Data Invariants & Master Source of Truth

1. **Strict Tenant Isolation**: Every document in AI GOD (GOD-X) lives under `/users/{userId}` and can only be read or mutated when `request.auth != null`, `request.auth.uid == userId`, and `request.auth.token.email_verified == true` for writes.
2. **Master Gate (Relational Sync)**:
   - Subcollections (`/private/{docId}`, `/conversations/{conversationId}`, `/tasks/{taskId}`, `/auditEvents/{eventId}`) require `/users/{userId}` to exist (`exists` or `existsAfter` on atomic batch creation) and belong to `request.auth.uid`.
   - Nested `/conversations/{conversationId}/messages/{messageId}` requires BOTH `/users/{userId}` and `/users/{userId}/conversations/{conversationId}` to exist (`exists` or `existsAfter`).
3. **PII Split Isolation**: User email addresses are never stored in `/users/{userId}`; they are strictly isolated in `/users/{userId}/private/account` (`docId == 'account'`).
4. **Strict Key & Size Bounds**: Every `create` enforces `hasAll` + `hasOnly`, every `update` wraps logic inside `isValid[Entity](incoming())` and `affectedKeys().hasOnly(...)`, every string enforces `.size()`, and path IDs enforce `^[a-zA-Z0-9_\-]+$` (`<= 128` chars).
5. **Temporal & Append-Only Integrity**:
   - `createdAt == request.time` on `create`, immutable on `update`.
   - `updatedAt == request.time` on `update`.
   - `messages` cannot be modified after creation (`allow update: if false`), only read or deleted by the owner.
   - `auditEvents` are strictly append-only (`allow update, delete: if false`) so security logs cannot be tampered with or erased.
   - `tasks` reaching terminal state `status == 'archived'` reject all further `update` mutations.
6. **Secure List Queries**: Every `allow list` validates `request.auth.uid == userId && resource.data.userId == request.auth.uid` with zero `get()` or `exists()` lookups inside `list`.

---

## 2. The "Dirty Dozen" Adversarial Payloads

1. **Cross-Tenant Profile Read (`PII / Identity Breach`)**: User `uid_attacker` attempts `get` on `/users/uid_victim` or `/users/uid_victim/private/account`.
2. **Unverified Email Write (`Spoof Attack`)**: User `uid_1` with `email_verified: false` attempts `create` on `/users/uid_1`.
3. **Shadow Field Injection (`Ghost Key`)**: Owner sends valid `UserProfile` payload plus `"isAdmin": true` or `"role": "god"` on `create` or `update`.
4. **UID Spoofing inside Owned Path (`Identity Mismatch`)**: User `uid_1` writes `/users/uid_1/tasks/task_1` with `{"userId": "uid_victim", ...}`.
5. **Path ID Poisoning (`Denial of Wallet`)**: User `uid_1` attempts `create` on `/users/uid_1/tasks/bad..id$with/slashes_or_200_chars...`.
6. **Oversized Payload Exhaustion (`1MB String`)**: User `uid_1` attempts `create` on `Message` with a 50,000-character `content` string (exceeding `32000` maxLength).
7. **Forged Client Timestamp (`Temporal Tampering`)**: User `uid_1` passes a backdated `createdAt` (`2020-01-01T00:00:00Z`) instead of `request.time`.
8. **Orphaned Subcollection Write (`Master Gate Bypass`)**: User `uid_1` attempts `create` on `/users/uid_1/conversations/conv_1/messages/msg_1` when `/users/uid_1/conversations/conv_1` does not exist.
9. **Immutable Field Mutation (`CreatedAt / Owner Rewrite`)**: User `uid_1` updates `/users/uid_1/conversations/conv_1` altering `createdAt` or `userId`.
10. **Terminal State Resurrection (`State Shortcutting`)**: User `uid_1` attempts `update` on a `TaskRecord` whose existing `status` is already `'archived'`.
11. **Audit Log Tampering (`Evidence Destruction`)**: User `uid_1` attempts `delete` or `update` on `/users/uid_1/auditEvents/evt_1`.
12. **Unfiltered Collection Scraping (`Query Trust Bypass`)**: User `uid_1` attempts an unscoped `list` query without `where('userId', '==', 'uid_1')` or against another user's path.

---

## 3. Phase 5 Red Team Conflict Report

| Collection | Identity Spoofing | State Shortcutting | Resource / Value Poisoning | Shadow Update Gate | List Query Enforcement | Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `/users/{userId}` | Blocked (`incoming().uid == request.auth.uid && userId == request.auth.uid`) | Validated (`executionMode in ['cloud','local','hybrid']`) | Bounded strings + `isValidUserProfile` wraps `update` | `hasOnly` enforced on both `create` and `update` | `allow list: if false` | PASS |
| `/users/{userId}/private/{docId}` | Blocked (`isOwner(userId)` + `docId == 'account'`) | N/A | Email bounded (`<= 320`) + `email == request.auth.token.email` | `hasOnly` enforced | `allow list: if false` | PASS |
| `/users/{userId}/conversations/{conversationId}` | Blocked (`incoming().userId == request.auth.uid`) | Validated (`lastIntent` enum, `messageCount >= 0`) | `title <= 160`, `lastMessagePreview <= 300`, `isValidId` | `isValidConversation` + `affectedKeys().hasOnly` | `resource.data.userId == request.auth.uid` | PASS |
| `/users/{userId}/conversations/{conversationId}/messages/{messageId}` | Blocked (`incoming().userId == request.auth.uid`) | Append-only (`allow update: if false`) | `content <= 32000`, `agentModuleNote <= 400`, `isValidId` | `hasOnly` on `create`; `update` denied | `resource.data.userId == request.auth.uid && resource.data.conversationId == conversationId` | PASS |
| `/users/{userId}/tasks/{taskId}` | Blocked (`incoming().userId == request.auth.uid`) | Terminal gate `existing().status != 'archived'` | `title <= 200`, enums validated, `isValidTask` wraps `update` | `isValidTask` + `affectedKeys().hasOnly` | `resource.data.userId == request.auth.uid` | PASS |
| `/users/{userId}/auditEvents/{eventId}` | Blocked (`incoming().userId == request.auth.uid`) | Immutable (`allow update, delete: if false`) | `action <= 80`, `summary <= 320`, `isValidId` | `hasOnly` on `create`; `update` denied | `resource.data.userId == request.auth.uid` | PASS |
