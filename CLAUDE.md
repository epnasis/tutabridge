# TutaBridge

## Architecture

TutaBridge is an IMAP/SMTP bridge for Tuta encrypted email. It exposes a local IMAP+SMTP server that mail clients (Thunderbird, etc.) connect to.

### Core principle: syncer-driven, store-backed

```
Tuta API  ←──  Syncer (background)  ──→  MailStore (in-memory)  ←──  IMAP server  ──→  Thunderbird
                                                                 ←──  Tauri UI (stats)
```

- The **syncer** (`sync.rs`) runs independently in a background tokio task. It pulls emails from the Tuta API and populates the `MailStore`.
- The **IMAP server** (`imap/`) ONLY reads from the `MailStore`. It NEVER makes API calls for reads.
- The only IMAP→network calls are **mutations**: marking read/unread (`STORE \Seen`), trashing (`EXPUNGE`), moving (`MOVE`), and label operations (`STORE` with keywords — apply/remove/create, see below).

### Labels ↔ IMAP keywords

Tuta labels (`MailSet`s with `kind == Label`) are exposed as IMAP keywords
(custom per-message flags — Thunderbird tags). Two-way sync:

- **Registry** (`labels.rs`): label id ↔ keyword atom mapping. Label names
  sanitize deterministically to atoms (diacritic fold, `_` for specials,
  case-insensitive collision suffixes in creation-order; `$` allowed so
  Thunderbird's `$label1…5` round-trip). Lookups always go through the
  registry — atoms are never reverse-derived into names.
- **Read**: the syncer (and MailSet events) populate the registry in the
  `MailStore` via `MailBackend::list_labels()` — labels ride the same
  server list as folders but the SDK `FolderSystem` drops them, so the raw
  `MailSet` range is walked instead. SELECT advertises keywords in FLAGS +
  PERMANENTFLAGS (incl. `\*`); FETCH FLAGS appends keywords from
  `Mail.sets ∩ registry`.
- **Write**: `STORE ±FLAGS (keyword)` → `ApplyLabelService` (batched,
  50-mail server cap). Unknown keyword on an adding STORE → the label is
  created via `ManageLabelService` (fresh session key encrypted with the
  current mail owner-group key — same envelope as the draft path), then
  applied and registered in the same command. STORE answers with untagged
  FETCH FLAGS responses per RFC 3501 §6.4.6 unless `.SILENT`.
- **Resilience**: folder/label enumeration decrypts per entity
  (`load_range_tolerant` in the SDK submodule); a broken MailSet is logged
  with its id and skipped, never blinding the whole folder list. Empty
  encrypted values (e.g. a label without a color) decrypt to their
  defaults — an SDK fix; both SDK commits live on the submodule branch
  `sdk-label-fixes` (epnasis/tutanota) until upstreamed.

### Syncer two-phase cycle

1. **Phase 1 (fast, ~3s)**: Sync mail lists for ALL 6 folders. Store gets populated with mail metadata immediately.
2. **Phase 2 (slow, ~2min)**: Prefetch mail details (body) one by one with rate limiting (150ms/mail). Bodies become available progressively.
3. Wait 60s, repeat.

## Testing

### Unit tests

```bash
cargo test --workspace        # ~300 bridge tests + SDK tests
```

### Integration test (IMAP)

Requires a running bridge instance (either `cargo run` or `./dev.sh` for GUI).

```bash
python3 scripts/test_imap.py
```

This connects to the local IMAP server and verifies: TLS, auth, folder list, mail count, body fetch, search. It reads the bridge password from `~/Library/Application Support/tutabridge/config.toml` automatically.

### Manual Thunderbird test

1. Start bridge: `./dev.sh` (GUI) or `cargo run` (CLI)
2. Wait for "Pre-fetching N mail details for Inbox" in logs
3. In Thunderbird: IMAP server `127.0.0.1:1143` SSL/TLS, SMTP `127.0.0.1:1025` SSL/TLS
4. Username: your tuta email, Password: bridge_password from config
5. Accept self-signed cert

## Build

```bash
cargo build                   # CLI + GUI
cargo build -p tutabridge-core  # Core library only
```

## SDK branches (tuta-repo submodule)

- `feat/rust-sdk-blob-read` — blob element reading (MailDetailsBlob)
- `feat/rust-sdk-load-multiple` — batch entity loading (load_multiple)
- Locally, `feat/rust-sdk-blob-read` has both merged for development
- `sdk-label-fixes` (epnasis/tutanota) — `load_range_tolerant` (per-entity
  decrypt fault tolerance) + empty-encrypted-value decrypt fix; pinned by
  main until upstreamed to spartanz51/tutanota `tutabridge-integration`
