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
- The only IMAP→network calls are **mutations**: marking read/unread (`STORE \Seen`), trashing (`EXPUNGE`), moving (`MOVE`), label operations (`STORE` with keywords — apply/remove/create, see below), and folder `CREATE`/`RENAME`/`DELETE` (see below). Folder mutations re-read the folder list from the server afterwards instead of waiting for the syncer.

### Synthesized messages carry provenance headers only

`mail_to_rfc2822` RECONSTRUCTS a message from the Tuta entity; it never
forwards an original. So the header set is ours (`Date`, `From`, `Subject`,
`To`/`Cc`, a synthesized `Message-ID`, MIME) plus an allowlist copied from
`MailDetails.headers`: `List-Unsubscribe`, `List-Unsubscribe-Post`,
`List-Id`, `Precedence`, `Auto-Submitted`. The allowlist is the whole design
— the body we emit is re-encoded with our own boundary, so the sender's
`Content-Type`, `Message-ID`, `MIME-Version`, `DKIM-Signature` and `Received`
would all describe a body that no longer exists. Header values are
sender-controlled, so parsing is line-wise and stray CR/LF is stripped: a
value cannot smuggle a structural header in. Absent headers are normal
(Tuta-internal mail never had any).

**Renditions are cached** (`<element_id>.eml.enc`, gated by `has_eml`), so
changing what this function emits only affects mail rendered after the
change — unless `RENDITION_VERSION` in `store.rs` is bumped. The bridge (not
backup) calls `LocalStore::drop_stale_renditions` at start: on a version
mismatch every `.eml.enc` is deleted and re-rendered as bodies are fetched
(prefetch window by the syncer, older mail by on-demand FETCH, which also
persists — but only when its attachments loaded). Bump it whenever the
emitted headers change.

### `X-Tutabridge-Authentication` (issue #16)

Every rendition's FIRST header, e.g. `status=hard_fail;
status-source=tuta-server; encryption-auth=unknown;
encryption-auth-source=tuta-client-decrypt; v=1`. Guarantee: if present in
the top-level header block, the bridge wrote it and exactly one copy exists.

- `status` = `MailDetails.authStatus` (what the web client's "could not
  verify sender" banner reads), NOT `Mail.authStatus`. `unknown` = no details.
- `encryption-auth` = `Mail.encryptionAuthStatus`, a client-side value.
- Phishing status is deliberately left out: Tuta clients set it after
  delivery and a served rendition is immutable, so it would go stale.
- Enforcement is two layers: no sender text reaches a header line raw
  (`sanitize_header_line` / `encode_header_value` neutralise every
  `is_line_break` char — the whole `str.splitlines` set, not just CR/LF),
  and `prepend_authentication_header` strips every same-named field with the
  name rule of the IMAP `HEADER.FIELDS` filter (Unicode uppercase).
  Line breaks are replaced BEFORE base64-encoding a value, since a decoding
  client would get them back. Sender text containing an RFC 2047
  encoded-word start (`=?`) is never emitted raw: subject/names are wrapped
  in our own encoded-word (one decode yields it literally), addresses have
  it broken up, and passthrough fields carrying one are dropped. No decoder:
  clients decode more leniently than any check we could write.
- Every top-level header line is printable ASCII (`is_plain_header_text`):
  readers disagree on what is a break or trimmable (Latin-1 0x85 in UTF-8
  `Å`, U+FEFF, control chars), so non-ASCII sender text is base64-encoded
  (subject/names), turned into `?` (addresses — an RFC 6531 address is shown
  mangled), or dropped (passthrough fields). Server ids in Message-ID and
  the boundary go through the same filter. The stripper trims everything
  but visible ASCII off names. No plain line exceeds 998 octets (a relay
  may split it): long subject/names are base64'd (no `:` to split into),
  addresses are cut at 254, From/To/Cc fold before a line passes 900
  (`address_field`; ordinary mail stays on one line), over-long passthrough
  fields are dropped. Header-safe addresses come from
  `header_address_tokens`; `format_address` (search, MCP) keeps the stored
  address as data.
- The verdict needs the mail's details, which header-only FETCHes never
  load. For mail not fetched yet they show `status=unknown` (true, not a
  guess); a full-body FETCH (`BODY.PEEK[]`) always carries the real verdict.

### IMAP SEARCH: an error, never a false answer

`imap/search.rs` reads a SEARCH exactly or not at all (issue #16): any
criterion it cannot read — unknown key, malformed set/date/size, missing
argument, unbalanced parens, literal `{N}`, unterminated quote — parses to
`SearchKey::Invalid` and the command answers BAD. A fallback ("match all")
would be a silent wrong answer, and under `NOT` an empty success. Other
rules:
- `*` is the largest sequence number / UID (`SearchContext.max_*`).
- FETCH/STORE/MOVE share the strict `parse_seqset` (BAD when malformed).
- `KEYWORD` matches label keywords exactly as FETCH FLAGS reports them.
- Body terms are quoted FTS5 words; an index error answers
  `NO [UNAVAILABLE]`, a term without alphanumerics `NO [CANNOT]`, a
  charset other than US-ASCII/UTF-8 `NO [BADCHARSET]`.
- Not covered: the index matches word prefixes, so a substring in the
  middle of a CJK run is not found. Accents fold (`gesla` finds "gęślą"),
  but letters that are not base + accent do not (`zazolc` misses
  "zażółć": `ł` is its own letter) — checked with SQLite 3.50.4's FTS5.

### UIDs and UIDVALIDITY

- **One source of truth:** `folder_uids(folder_id, element_id) → uid` in the
  local store. `LocalStore::assign_folder_uids` is atomic and idempotent, so
  the syncer and the event handler always get the same UID for a placement.
  Never derive a UID from memory.
- **Release on leave:** a MailSetEntry DELETE or a sync that no longer lists
  a mail releases its UID in that folder. A return is a new arrival with a
  higher UID (RFC 3501 §2.3.1.1).
- **UIDVALIDITY is per folder** (`sync_state.uid_validity`), issued from a
  store-wide counter that only grows (`store_meta.uid_validity`). Any
  restart of a folder's counter — schema migration, reset, a recreated
  folder id — yields a value no client has seen. UIDNEXT is the persisted
  `next_uid` (or one past the highest UID in memory, if that is larger).
- **Events wait for the bootstrap:** the event handler holds batches until
  the syncer signals `BootstrapDone` (cache loaded + any full-metadata
  sync). Earlier, a folder load or listing taken before an event overwrote
  it. Held batches still advance the in-memory bus ids (reconnect resumes
  after them); the wait gives up after 15 min or 10,000 batches.
- **Failure is an error, not a guess:** a failed UID assignment leaves the
  folder untouched; SELECT/STATUS answer `NO [UNAVAILABLE]`; multi-statement
  writes to the mail rows, UID map and UID counters go through
  `in_transaction` (rollback on error). `index_body` and the migration drop
  run in autocommit.

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

### Folder CREATE / RENAME / DELETE

Custom folders map to `MailFolderService` (POST create, PUT move, DELETE)
and a MailSet `update_instance` for a rename. The rules mirror Tuta's own
web client:

- **DELETE** of a folder outside Trash/Spam moves it into Trash; an empty
  folder (and empty descendants, deepest first) is deleted outright, since
  Trash does not take empty folders (UNVERIFIED live). Inside Trash/Spam,
  DELETE deletes for good. `RENAME X Trash/...` (Thunderbird's delete) is
  the same operation.
- **No two siblings of one name.** Tuta allows them, IMAP cannot address
  them. A folder arriving where its name is taken gets `Name (2)`, …. Into
  Trash: if its own name is free there it moves first, then renames; if
  not, it renames first to a name free in both places. Either way a
  failure between the two calls cannot leave a duplicate.
- **Exact names** (`folder_by_exact_path`) for existence checks — `Work`
  → `work` is a rename. Lookups for SELECT etc. still fold case.
- **Partial failure** answers `NO … earlier steps may have completed, LIST
  shows the result`, re-reads the list and deselects a folder that is gone.
- Emptiness reads ascending from `CustomId::default()`, as the web client
  does. Nothing here has run against a live account yet.

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
- `sdk-360-rebase` (epnasis/tutanota) — every patch above cherry-picked onto
  `tutanota-release-360.260921.0`; pinned by main since 2026-09-24. Push it
  over SSH: upstream commits touch `.github/workflows`, which an HTTPS token
  without the `workflow` scope may not push.

### Tuta retires old client versions

The SDK sends its crate version (`CLIENT_VERSION`, from the tuta-repo
workspace `version`) as `cv` on every request and as `clientVersion` on the
event-bus URL. Once Tuta stops accepting that version, every REST call and
every websocket connect answers **474 Invalid Software Version**. That happened
to `348.260528.0` on 2026-09-16, and the bridge served a frozen inbox for
eight days. A restart does not help. The fix: cherry-pick our SDK patches
onto a current `tutanota-release-*` tag, adapt the bridge to renamed APIs,
redeploy. The log shows `ws connect failed: HTTP error: 474`, and
`status.json` in the data dir carries the connection state for clients.

### Every rebuild re-asks the Keychain

The binary is ad-hoc signed with a per-build identifier, so the saved-session
Keychain item's access list stops matching after every rebuild. On first start
the bridge blocks in `SecKeychainFindGenericPassword` (the log stops at
`Initializing SDK...`) until someone clicks **Always Allow** on the Mac's
screen. Deploy only the final build: a grant given to an intermediate build is
lost at the next one.
