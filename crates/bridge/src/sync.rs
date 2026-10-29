use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use tokio::sync::{watch, RwLock};
use tutasdk::entities::generated::tutanota::{Mail, MailDetails, TutanotaFile};

use crate::labels::{LabelInfo, LabelRegistry};
use crate::mail::{extract_body_text, mail_to_rfc2822, strip_html};
use crate::store::{LocalStore, MailMetadata};
use crate::tuta::{FolderInfo, MailBackend};

const INTER_REQUEST_DELAY: Duration = Duration::from_millis(150);
const INTER_FOLDER_DELAY: Duration = Duration::from_millis(300);
const MAX_RETRIES: u32 = 3;
/// How long a mail whose on-demand body fetch just failed is skipped before the
/// bridge will try the API again for it. Stops a client from re-triggering a
/// fetch for the same message on every redraw while the server is throttling.
const BODY_FETCH_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct StoredMail {
    pub mail: Mail,
    pub details: Option<MailDetails>,
    pub rfc2822: Option<String>,
    /// Stable IMAP UID within the folder, persisted across restarts.
    pub uid: u32,
    /// True while the mail's body has been rendered without its attachment
    /// parts because the server returned them with unresolved encryption
    /// metadata (a fresh-mail race). The `prefetch_loop` keeps retrying
    /// just the attachment load until it succeeds — at which point the
    /// `.eml` is rewritten as a proper `multipart/mixed`.
    pub attachments_pending: bool,
}

pub struct MailStore {
    /// folder id → mails in that folder.
    folders: RwLock<HashMap<String, Vec<StoredMail>>>,
    /// The folder list (system + custom), for IMAP enumeration.
    folder_list: RwLock<Vec<FolderInfo>>,
    /// Label ↔ IMAP keyword registry, refreshed alongside the folder list.
    labels: RwLock<LabelRegistry>,
    generation: watch::Sender<u64>,
    gen_counter: std::sync::atomic::AtomicU64,
    /// element_id -> instant until which an on-demand body fetch is skipped,
    /// armed after a fetch failure. Shared across IMAP connections.
    body_fetch_cooldown: Mutex<HashMap<String, Instant>>,
}

impl MailStore {
    pub fn new() -> Arc<Self> {
        let (tx, _) = watch::channel(0u64);
        Arc::new(Self {
            folders: RwLock::new(HashMap::new()),
            folder_list: RwLock::new(Vec::new()),
            labels: RwLock::new(LabelRegistry::default()),
            generation: tx,
            gen_counter: std::sync::atomic::AtomicU64::new(0),
            body_fetch_cooldown: Mutex::new(HashMap::new()),
        })
    }

    /// True if a recent on-demand body fetch for `element_id` failed and its
    /// cooldown has not yet elapsed. Expired entries are dropped lazily.
    pub(crate) fn body_fetch_on_cooldown(&self, element_id: &str) -> bool {
        let mut map = crate::util::lock_recover(&self.body_fetch_cooldown);
        match map.get(element_id) {
            Some(&until) if until > Instant::now() => true,
            Some(_) => {
                map.remove(element_id);
                false
            }
            None => false,
        }
    }

    /// Arm a cooldown after a failed on-demand body fetch so the bridge does not
    /// immediately re-hit a throttled or erroring server for the same mail.
    pub(crate) fn mark_body_fetch_failed(&self, element_id: &str) {
        let mut map = crate::util::lock_recover(&self.body_fetch_cooldown);
        let now = Instant::now();
        // Drop elapsed entries so the map stays bounded by the number of mails
        // currently cooling down, not every mail that has ever failed.
        map.retain(|_, until| *until > now);
        map.insert(element_id.to_string(), now + BODY_FETCH_COOLDOWN);
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    pub async fn total_mail_count(&self) -> usize {
        self.folders.read().await.values().map(|v| v.len()).sum()
    }

    pub async fn folder_count(&self, folder_id: &str) -> usize {
        self.folders
            .read()
            .await
            .get(folder_id)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    pub async fn get_folder(&self, folder_id: &str) -> Vec<StoredMail> {
        self.folders
            .read()
            .await
            .get(folder_id)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn get_details(
        &self,
        folder_id: &str,
        element_id: &str,
    ) -> Option<(MailDetails, String)> {
        let folders = self.folders.read().await;
        let folder = folders.get(folder_id)?;
        folder.iter().find_map(|m| {
            let eid = m.mail._id.as_ref()?.element_id.to_string();
            if eid == element_id {
                Some((m.details.clone()?, m.rfc2822.clone()?))
            } else {
                None
            }
        })
    }

    /// The current folder list (system + custom).
    pub async fn list_folders(&self) -> Vec<FolderInfo> {
        self.folder_list.read().await.clone()
    }

    /// Look up a folder by its IMAP path (case-insensitive for INBOX).
    pub async fn folder_by_imap_path(&self, path: &str) -> Option<FolderInfo> {
        let list = self.folder_list.read().await;
        list.iter()
            .find(|f| f.imap_path == path || f.imap_path.eq_ignore_ascii_case(path))
            .cloned()
    }

    pub(crate) async fn set_folder_list(&self, folders: Vec<FolderInfo>) {
        *self.folder_list.write().await = folders;
        self.bump_generation();
    }

    /// Snapshot of the label ↔ keyword registry. The IMAP layer takes one
    /// per command, so a mid-command registry refresh cannot skew a response.
    pub async fn label_registry(&self) -> LabelRegistry {
        self.labels.read().await.clone()
    }

    /// Replace the label registry from a fresh backend enumeration.
    pub(crate) async fn set_labels(&self, labels: Vec<LabelInfo>) {
        *self.labels.write().await = LabelRegistry::new(labels);
        self.bump_generation();
    }

    pub(crate) async fn set_folder(&self, folder_id: &str, mails: Vec<StoredMail>) {
        self.folders
            .write()
            .await
            .insert(folder_id.to_string(), mails);
        self.bump_generation();
    }

    /// Refresh an existing mail's metadata in every folder that holds it
    /// (body/details preserved). No-op if the mail is not cached.
    pub async fn refresh_mail_in_place(&self, mail: &Mail) {
        let Some(eid) = mail._id.as_ref().map(|id| id.element_id.to_string()) else {
            return;
        };
        let mut folders = self.folders.write().await;
        let mut changed = false;
        for mails in folders.values_mut() {
            if let Some(m) = mails.iter_mut().find(|m| {
                m.mail
                    ._id
                    .as_ref()
                    .map(|id| id.element_id.to_string())
                    .as_deref()
                    == Some(&eid)
            }) {
                m.mail = mail.clone();
                changed = true;
            }
        }
        drop(folders);
        if changed {
            self.bump_generation();
        }
    }

    /// Find a mail by element id across all folders. Returns the source
    /// folder id and a clone of the [`StoredMail`] entry — letting the
    /// event handler reuse the already-decrypted Mail/details when the
    /// same mail just hopped between two cached folders, no REST round-trip.
    pub async fn find_mail_anywhere(&self, element_id: &str) -> Option<(String, StoredMail)> {
        let folders = self.folders.read().await;
        for (fid, mails) in folders.iter() {
            for m in mails {
                if m.mail
                    ._id
                    .as_ref()
                    .map(|id| id.element_id.to_string())
                    .as_deref()
                    == Some(element_id)
                {
                    return Some((fid.clone(), m.clone()));
                }
            }
        }
        None
    }

    /// `true` if any folder still references this mail. Used after a
    /// per-folder removal to decide whether the cached `.eml` can go.
    pub async fn is_mail_anywhere(&self, element_id: &str) -> bool {
        let folders = self.folders.read().await;
        folders.values().any(|mails| {
            mails.iter().any(|m| {
                m.mail
                    ._id
                    .as_ref()
                    .map(|id| id.element_id.to_string())
                    .as_deref()
                    == Some(element_id)
            })
        })
    }

    /// Remove a single mail from one specific folder. Returns `true` if a
    /// row was actually removed (the mail might already be gone from this
    /// folder if we are reprocessing an event).
    pub async fn remove_mail_from_folder(&self, folder_id: &str, element_id: &str) -> bool {
        let mut folders = self.folders.write().await;
        let Some(mails) = folders.get_mut(folder_id) else {
            return false;
        };
        let before = mails.len();
        mails.retain(|m| {
            m.mail
                ._id
                .as_ref()
                .map(|id| id.element_id.to_string())
                .as_deref()
                != Some(element_id)
        });
        let changed = mails.len() != before;
        drop(folders);
        if changed {
            self.bump_generation();
        }
        changed
    }

    /// Insert or replace a mail in `folder_id`. Replace-by-element-id keeps
    /// the operation idempotent — re-applying the same event leaves the
    /// store unchanged.
    pub async fn upsert_mail_in_folder(&self, folder_id: &str, mail: StoredMail) {
        let Some(eid) = mail.mail._id.as_ref().map(|id| id.element_id.to_string()) else {
            return;
        };
        let mut folders = self.folders.write().await;
        let entries = folders.entry(folder_id.to_string()).or_default();
        if let Some(slot) = entries.iter_mut().find(|m| {
            m.mail
                ._id
                .as_ref()
                .map(|id| id.element_id.to_string())
                .as_deref()
                == Some(&eid)
        }) {
            *slot = mail;
        } else {
            entries.push(mail);
        }
        drop(folders);
        self.bump_generation();
    }

    /// Drop in-memory state for folders that are no longer on the server.
    /// Returns the ids that were removed so the caller can clean up the
    /// LocalStore + .eml files for them.
    pub async fn prune_unknown_folders(
        &self,
        known: &std::collections::HashSet<String>,
    ) -> Vec<String> {
        let mut removed = Vec::new();
        let mut folders = self.folders.write().await;
        folders.retain(|fid, _| {
            if known.contains(fid) {
                true
            } else {
                removed.push(fid.clone());
                false
            }
        });
        drop(folders);
        if !removed.is_empty() {
            self.bump_generation();
        }
        removed
    }

    /// Drop a mail from every folder it appears in (handles DELETE events).
    pub async fn remove_mail_everywhere(&self, element_id: &str) {
        let mut folders = self.folders.write().await;
        let mut changed = false;
        for mails in folders.values_mut() {
            let before = mails.len();
            mails.retain(|m| {
                m.mail
                    ._id
                    .as_ref()
                    .map(|id| id.element_id.to_string())
                    .as_deref()
                    != Some(element_id)
            });
            if mails.len() != before {
                changed = true;
            }
        }
        drop(folders);
        if changed {
            self.bump_generation();
        }
    }

    pub(crate) async fn update_mail_details(
        &self,
        folder_id: &str,
        element_id: &str,
        details: MailDetails,
        rfc2822: String,
        attachments_pending: bool,
    ) {
        let mut folders = self.folders.write().await;
        if let Some(folder) = folders.get_mut(folder_id) {
            if let Some(m) = folder.iter_mut().find(|m| {
                m.mail
                    ._id
                    .as_ref()
                    .map(|id| id.element_id.to_string())
                    .as_deref()
                    == Some(element_id)
            }) {
                m.details = Some(details);
                m.rfc2822 = Some(rfc2822);
                m.attachments_pending = attachments_pending;
            }
        }
        drop(folders);
        self.bump_generation();
    }

    /// Rewrite just the cached RFC 2822 for a mail (and clear its pending
    /// flag) after a successful attachment-only retry. The mail's details
    /// are already in store from the original prefetch; we only need to
    /// refresh the body so the next IMAP FETCH BODY[] returns the
    /// multipart envelope.
    async fn update_mail_rfc2822(&self, folder_id: &str, element_id: &str, rfc2822: String) {
        let mut folders = self.folders.write().await;
        if let Some(folder) = folders.get_mut(folder_id) {
            if let Some(m) = folder.iter_mut().find(|m| {
                m.mail
                    ._id
                    .as_ref()
                    .map(|id| id.element_id.to_string())
                    .as_deref()
                    == Some(element_id)
            }) {
                m.rfc2822 = Some(rfc2822);
                m.attachments_pending = false;
            }
        }
        drop(folders);
        self.bump_generation();
    }

    fn bump_generation(&self) {
        let gen = self
            .gen_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        self.generation.send_replace(gen);
    }
}

/// Tells the event handler that the syncer's bootstrap — cache loaded,
/// folders listed — is over. Events applied before that race it: a folder
/// load or listing taken earlier overwrites what the handler just did, and
/// mail vanishes or lands in the wrong folder. Sent on drop too, so an
/// early return can never leave the handler waiting.
pub struct BootstrapDone(watch::Sender<bool>);

impl BootstrapDone {
    pub fn channel() -> (Self, watch::Receiver<bool>) {
        let (tx, rx) = watch::channel(false);
        (Self(tx), rx)
    }

    fn signal(&self) {
        let _ = self.0.send(true);
    }
}

impl Drop for BootstrapDone {
    fn drop(&mut self) {
        self.signal();
    }
}

pub async fn run_syncer(
    store: Arc<MailStore>,
    local_store: Arc<LocalStore>,
    backend: Arc<dyn MailBackend>,
    sync_limit: usize,
    shutdown: watch::Receiver<bool>,
    bootstrap_done: BootstrapDone,
) {
    info!(
        "Mail syncer started (body prefetch depth={})",
        if sync_limit == 0 {
            "all".to_string()
        } else {
            sync_limit.to_string()
        }
    );

    // Fetch the folder list first; everything is keyed off it.
    let folders = match retry(|| backend.list_folders()).await {
        Ok(folders) => folders,
        Err(e) => {
            warn!("Could not load folder list: {e}");
            Vec::new()
        }
    };
    store.set_folder_list(folders.clone()).await;

    // Labels ride the same server-side MailSets list as folders but never
    // appear in the IMAP mailbox tree — they feed the keyword registry
    // instead. Failure is not fatal: mail sync works without labels, the
    // keywords just stay absent until the next MailSet event refresh.
    match retry(|| backend.list_labels()).await {
        Ok(labels) => store.set_labels(labels).await,
        Err(e) => warn!("Could not load label list: {e}"),
    }

    // Phase 0: load cached mails from the local store into memory.
    for folder in &folders {
        match load_cached_folder(&store, &local_store, folder).await {
            Ok(count) if count > 0 => {
                info!("Loaded {} cached mails for {}", count, folder.imap_path);
            }
            Ok(_) => {}
            Err(e) => warn!("Failed to load cache for {}: {}", folder.imap_path, e),
        }
    }

    // We run a one-shot full **metadata** sync (the whole mail list of every
    // folder) when either:
    //   * there's no cached event-bus state (fresh install / cache wiped), or
    //   * we've never completed a full-metadata sync before — the marker
    //     below. This second case migrates existing installs that were synced
    //     under the old `sync_limit`-truncated model up to a complete mailbox.
    // After it runs once, the event bus keeps the list current; we don't
    // re-list every launch (the metadata is persisted + loaded in Phase 0).
    const FULL_METADATA_MARKER: &str = "full_metadata_synced_v1";
    let needs_bootstrap = match local_store.load_event_bus_state() {
        Ok(s) => s.is_empty(),
        Err(e) => {
            warn!("Could not read event_bus_state ({e}); assuming bootstrap needed");
            true
        }
    };
    let full_metadata_done = local_store.get_meta(FULL_METADATA_MARKER).is_some();
    let do_full_sync = (needs_bootstrap || !full_metadata_done) && !folders.is_empty();

    if do_full_sync {
        if needs_bootstrap {
            info!("Bootstrap sync (no cached event-bus state)");
        } else {
            info!("One-time full-metadata sync (completing the mailbox view)");
        }
        let mut all_ok = true;
        for folder in &folders {
            if *shutdown.borrow() {
                return;
            }
            if let Err(e) = sync_folder(&store, &local_store, &*backend, folder).await {
                warn!("Full-metadata sync failed for {}: {}", folder.imap_path, e);
                all_ok = false;
            }
            tokio::time::sleep(INTER_FOLDER_DELAY).await;
        }
        // Only set the marker if every folder synced, so a transient failure
        // gets retried on the next launch rather than silently leaving the
        // mailbox incomplete.
        if all_ok {
            if let Err(e) = local_store.set_meta(FULL_METADATA_MARKER, "1") {
                warn!("Could not persist full-metadata marker: {e}");
            }
        }
    } else {
        debug!("Skipping full-metadata sync — already complete, event bus reconciles");
    }
    bootstrap_done.signal();

    // One-time backfill of the full-text body index from bodies that were
    // already cached (downloaded before the index existed). Bodies fetched from
    // here on are indexed inline by `prefetch_details`, so this only ever runs
    // once per install.
    const FTS_BACKFILL_MARKER: &str = "body_fts_indexed_v1";
    if local_store.get_meta(FTS_BACKFILL_MARKER).is_none() && !folders.is_empty() {
        info!("Backfilling full-text body index from cached messages…");
        let mut indexed = 0usize;
        let mut all_ok = true;
        for folder in &folders {
            if *shutdown.borrow() {
                return;
            }
            // Same reasoning as `load_cached_folder`: reading and decrypting
            // every cached body is CPU-bound work that must not run on an async
            // worker, or it starves the network accept loops. Index one folder
            // per blocking task; the shutdown check stays on the async side
            // between folders.
            let ls = local_store.clone();
            let fid = folder.id.clone();
            let fpath = folder.imap_path.clone();
            let (folder_indexed, folder_ok) =
                tokio::task::spawn_blocking(move || -> (usize, bool) {
                    let mut indexed = 0usize;
                    let mut ok = true;
                    match ls.load_folder_metadata(&fid) {
                        Ok(metas) => {
                            for meta in metas.iter().filter(|m| m.has_details) {
                                match ls.read_eml(&meta.element_id) {
                                    Ok(Some(rfc)) => {
                                        let text = extract_body_text(&rfc);
                                        if let Err(e) = ls.index_body(&meta.element_id, &text) {
                                            warn!(
                                                "FTS backfill failed for {}: {e}",
                                                meta.element_id
                                            );
                                            ok = false;
                                        } else {
                                            indexed += 1;
                                        }
                                    }
                                    Ok(None) => {}
                                    Err(e) => {
                                        warn!(
                                            "FTS backfill read failed for {}: {e}",
                                            meta.element_id
                                        );
                                        ok = false;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("FTS backfill: no metadata for {fpath}: {e}");
                            ok = false;
                        }
                    }
                    (indexed, ok)
                })
                .await
                .unwrap_or_else(|e| {
                    warn!("FTS backfill task failed: {e}");
                    (0, false)
                });
            indexed += folder_indexed;
            if !folder_ok {
                all_ok = false;
            }
        }
        // Only mark done if nothing errored, so a partial run retries next boot.
        if all_ok {
            if let Err(e) = local_store.set_meta(FTS_BACKFILL_MARKER, "1") {
                warn!("Could not persist FTS backfill marker: {e}");
            }
        }
        info!("Full-text body index backfill complete ({indexed} messages)");
    }

    // From here on the syncer only owns the slow body prefetch (capped at
    // `sync_limit` — the body-prefetch depth). Folder / new-mail refresh is
    // driven by the event bus + `event_handler`.
    prefetch_loop(
        &store,
        &local_store,
        &*backend,
        sync_limit,
        shutdown.clone(),
    )
    .await;
    info!("Mail syncer shutting down");
}

/// Event-driven background prefetch. Wakes whenever the `MailStore`'s
/// generation counter changes (a new mail arrived, a sync finished, …) and
/// catches up any folder that still has bodies missing. When the store is
/// quiet — every Mail has its `.eml` cached, no folder mutations in flight —
/// the loop sleeps indefinitely on the watch channel; no timer-driven
/// polling.
async fn prefetch_loop(
    store: &MailStore,
    local_store: &LocalStore,
    backend: &dyn MailBackend,
    body_prefetch_limit: usize,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut store_watch = store.subscribe();
    // Per-mail throttle for attachment retries — keys are element ids,
    // values are the instant we last attempted the retry. We hold this map
    // in the prefetch_loop's stack so it survives across store generations
    // but resets on bridge restart. The session-key-transient race typically
    // resolves within a couple of minutes, so a 60s minimum gap is plenty.
    let mut attachment_retry_history: AttachmentRetries = HashMap::new();
    loop {
        if *shutdown.borrow() {
            return;
        }
        for folder in store.list_folders().await {
            if *shutdown.borrow() {
                return;
            }
            prefetch_details(
                store,
                local_store,
                backend,
                &folder,
                body_prefetch_limit,
                &mut attachment_retry_history,
            )
            .await;
        }

        // If any attachment retry is still in flight (throttle is set) we
        // must wake up after the throttle window even if nothing else
        // touches the store — otherwise the retry loop relies on another
        // mail arriving to be re-triggered.
        let next_tick = if attachment_retry_history.is_empty() {
            None
        } else {
            Some(ATTACHMENT_RETRY_THROTTLE)
        };
        tokio::select! {
            _ = store_watch.changed() => {}
            _ = shutdown.changed() => return,
            _ = async {
                match next_tick {
                    Some(d) => tokio::time::sleep(d).await,
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
    }
}

/// Interval before the first retry of a mail's attachments after a
/// transient failure; it doubles with each further attempt, up to
/// `ATTACHMENT_RETRY_MAX_DELAY`. Recovers within ~1 minute from the
/// session-key race, without re-downloading a mail's attachments every
/// minute forever when one keeps failing.
const ATTACHMENT_RETRY_THROTTLE: Duration = Duration::from_secs(60);
const ATTACHMENT_RETRY_MAX_DELAY: Duration = Duration::from_secs(6 * 60 * 60);
/// After this many attempts a transient failure is treated as permanent:
/// the body is kept without the attachments.
pub(crate) const ATTACHMENT_RETRY_MAX_ATTEMPTS: u32 = 10;
/// Pending longer than this, a transient failure is treated as permanent
/// too: the attempt count is in memory, the age survives restarts.
pub(crate) const ATTACHMENT_RETRY_MAX_AGE: Duration = Duration::from_secs(3 * 24 * 60 * 60);

/// Per mail: when its attachments were last tried and how often.
pub(crate) type AttachmentRetries = HashMap<String, AttachmentRetry>;

#[derive(Clone, Copy)]
pub(crate) struct AttachmentRetry {
    last: std::time::Instant,
    attempts: u32,
}

impl AttachmentRetry {
    fn first(at: std::time::Instant) -> Self {
        Self {
            last: at,
            attempts: 1,
        }
    }

    /// A retry `attempts` deep whose backoff has long run out.
    #[cfg(test)]
    pub(crate) fn long_ago(attempts: u32) -> Self {
        Self {
            last: std::time::Instant::now() - ATTACHMENT_RETRY_MAX_DELAY,
            attempts,
        }
    }

    fn due(&self, now: std::time::Instant) -> bool {
        let backoff = ATTACHMENT_RETRY_THROTTLE
            .saturating_mul(1 << self.attempts.saturating_sub(1).min(16))
            .min(ATTACHMENT_RETRY_MAX_DELAY);
        now.duration_since(self.last) >= backoff
    }
}

pub(crate) async fn load_cached_folder(
    store: &MailStore,
    local_store: &Arc<LocalStore>,
    folder: &FolderInfo,
) -> Result<usize, String> {
    // Decoding a cached folder means deserializing every metadata row and, for
    // each mail, reading and decrypting its `.eml.enc` body (AES-CBC + an
    // HMAC-SHA256 verification). For a large folder that is seconds of pure CPU
    // with no `.await` in between. Run inline on a tokio worker it would keep
    // that worker (and the IO driver it owns) busy for the whole loop, which
    // stalls the IMAP/SMTP accept loops until the folder finishes loading. So
    // do the decode on the blocking pool and only touch the async store once
    // the `Vec` is built.
    let ls = local_store.clone();
    let folder_id = folder.id.clone();
    let stored_mails = tokio::task::spawn_blocking(move || -> Result<Vec<StoredMail>, String> {
        let metas = ls
            .load_folder_metadata(&folder_id)
            .map_err(|e| format!("{e}"))?;

        // Restored, so the retry pass picks up where it was before a restart.
        let pending = ls.attachments_pending_in(&folder_id).unwrap_or_default();
        let mut stored_mails = Vec::with_capacity(metas.len());
        for meta in &metas {
            let mail: Mail = serde_json::from_str(&meta.mail_json)
                .map_err(|e| format!("Bad cached mail {}: {e}", meta.element_id))?;

            // Always try to recover the full body from disk first: the `.eml`
            // file is the source of truth and may exist even when the metadata
            // row says otherwise (a schema migration drops the `mails` table but
            // keeps the encrypted `.eml.enc` files, so `has_details` is reset to
            // 0 on first boot after the migration). Self-heal the row when we
            // find an orphaned body, so the prefetch loop knows to skip it on
            // the next sweep.
            let rfc2822 = match ls.read_eml(&meta.element_id) {
                Ok(Some(eml)) => {
                    if !meta.has_details {
                        if let Err(e) = ls.mark_has_details(&meta.element_id) {
                            warn!("Failed to heal has_details for {}: {e}", meta.element_id);
                        }
                    }
                    Some(eml)
                }
                // No cached body: leave `rfc2822` empty rather than baking in a
                // placeholder. A placeholder would look like a real body to the
                // IMAP layer and suppress the on-demand fetch; `None` is what tells
                // it the body still has to be pulled the first time it's opened.
                Ok(None) => None,
                Err(e) => {
                    warn!("Failed to read cached eml {}: {e}", meta.element_id);
                    None
                }
            };

            stored_mails.push(StoredMail {
                mail,
                details: None,
                rfc2822,
                uid: meta.uid as u32,
                attachments_pending: pending.contains(&meta.element_id),
            });
        }
        Ok(stored_mails)
    })
    .await
    .map_err(|e| format!("cache load task failed: {e}"))??;

    let count = stored_mails.len();
    store.set_folder(&folder.id, stored_mails).await;
    Ok(count)
}

/// Sync a folder's full mail-list **metadata** (subject / sender / date /
/// flags) — every message, not a `sync_limit`-capped slice. This is what
/// makes the whole mailbox visible over IMAP; message *bodies* are fetched
/// separately and lazily (see [`prefetch_details`] + on-demand FETCH).
pub(crate) async fn sync_folder(
    store: &MailStore,
    local_store: &LocalStore,
    backend: &dyn MailBackend,
    folder: &FolderInfo,
) -> Result<(), String> {
    // `0` = load every entry (the SDK paginates). Metadata is cheap relative
    // to bodies (no blob fetch), so we never truncate the list.
    let new_mails = retry(|| backend.load_mail_ids_for_folder(folder, 0)).await?;

    let existing = store.get_folder(&folder.id).await;
    let existing_map: HashMap<String, StoredMail> = existing
        .into_iter()
        .filter_map(|m| {
            let eid = m.mail._id.as_ref()?.element_id.to_string();
            Some((eid, m))
        })
        .collect();

    // UIDs come from the persisted per-folder map, not from memory: memory
    // may not be loaded yet, and the event handler assigns concurrently.
    // `new_mails` is newest-first; reverse it so the oldest new mail gets the
    // lowest new UID.
    let element_ids: Vec<String> = new_mails
        .iter()
        .rev()
        .filter_map(|m| m._id.as_ref().map(|id| id.element_id.to_string()))
        .collect();
    let refs: Vec<&str> = element_ids.iter().map(|s| s.as_str()).collect();
    // Without UIDs nothing can be published; the folder stays as it is
    // rather than being replaced by an empty one.
    let uids = local_store
        .assign_folder_uids(&folder.id, &refs)
        .map_err(|e| format!("could not assign UIDs: {e}"))?;

    let mut updated = Vec::with_capacity(new_mails.len());
    let mut metas_to_upsert = Vec::with_capacity(new_mails.len());

    for mail in &new_mails {
        let elem_id = mail._id.as_ref().map(|id| id.element_id.to_string());
        // No UID, no message: UID 0 is not valid IMAP. It is listed again on
        // the next sync.
        let Some(uid) = elem_id.as_ref().and_then(|id| uids.get(id).copied()) else {
            continue;
        };

        if let Some(existing) = elem_id.as_ref().and_then(|id| existing_map.get(id)) {
            updated.push(StoredMail {
                mail: mail.clone(),
                details: existing.details.clone(),
                rfc2822: existing.rfc2822.clone(),
                uid,
                attachments_pending: existing.attachments_pending,
            });
        } else {
            // New mail, body not fetched yet — leave `rfc2822` empty so the
            // IMAP layer fetches it on demand (a placeholder would mask that).
            // A mail new to this folder only (moved in) that still waits for
            // attachments keeps the flag and its cached body: the retry pass
            // only takes mails with a body.
            let attachments_pending = elem_id.as_ref().is_some_and(|eid| {
                local_store
                    .attachments_pending_since(eid)
                    .ok()
                    .flatten()
                    .is_some()
            });
            let rfc2822 = match (&elem_id, attachments_pending) {
                (Some(eid), true) => local_store.read_eml(eid).ok().flatten(),
                _ => None,
            };
            updated.push(StoredMail {
                mail: mail.clone(),
                details: None,
                rfc2822,
                uid,
                attachments_pending,
            });
        }

        metas_to_upsert.push(mail_to_metadata(mail, &folder.id, uid));
    }

    if let Err(e) = local_store.upsert_mail_metadata_batch(&metas_to_upsert) {
        warn!("Failed to persist metadata for {}: {}", folder.imap_path, e);
    }

    let current_ids: Vec<&str> = new_mails
        .iter()
        .filter_map(|m| m._id.as_ref().map(|id| id.element_id.as_str()))
        .collect();
    match local_store.delete_mails_not_in(&folder.id, &current_ids) {
        Ok(deleted) => {
            for eid in &deleted {
                if let Err(e) = local_store.delete_eml(eid) {
                    warn!("Failed to delete cached eml {}: {}", eid, e);
                }
                if let Err(e) = local_store.unindex_body(eid) {
                    warn!("Failed to unindex body {}: {}", eid, e);
                }
            }
            if !deleted.is_empty() {
                debug!(
                    "Removed {} deleted mails from {} cache",
                    deleted.len(),
                    folder.imap_path
                );
            }
        }
        Err(e) => warn!(
            "Failed to clean up deleted mails for {}: {}",
            folder.imap_path, e
        ),
    }

    store.set_folder(&folder.id, updated).await;

    Ok(())
}

pub(crate) async fn prefetch_details(
    store: &MailStore,
    local_store: &LocalStore,
    backend: &dyn MailBackend,
    folder: &FolderInfo,
    body_prefetch_limit: usize,
    attachment_retry_history: &mut AttachmentRetries,
) {
    let mails = store.get_folder(&folder.id).await;

    // Body prefetch is the *capped* part: eagerly pull bodies only for the
    // newest `body_prefetch_limit` messages (the store is newest-first).
    // `0` = no cap (prefetch every body). Bodies beyond the window are fetched
    // on demand when the client FETCHes them. (Metadata for the whole folder
    // is always present — see `sync_folder`.)
    let prefetch_window: &[StoredMail] = if body_prefetch_limit == 0 {
        &mails
    } else {
        &mails[..mails.len().min(body_prefetch_limit)]
    };

    // First pass — messages in the prefetch window still missing their `.eml`.
    let api_needed: Vec<Mail> = prefetch_window
        .iter()
        .filter(|m| m.details.is_none())
        .filter_map(|m| {
            let eid = m.mail._id.as_ref()?.element_id.to_string();
            if local_store.has_eml(&eid) {
                None
            } else {
                Some(m.mail.clone())
            }
        })
        .collect();

    // Second pass — mails whose body is already cached but whose attachments
    // failed to load on the first try because the server hadn't propagated
    // their session-key metadata yet. Throttled per element id so we don't
    // hammer the server every store mutation.
    let now = std::time::Instant::now();
    // Only mails whose body is here: the retry adds attachments to it. One
    // without (a dropped or unreadable rendition) gets its body from the
    // first pass or an on-demand fetch first. Details may be missing — after
    // a restart the cache holds only the rendition — and are loaded again.
    let attachment_retry_needed: Vec<(StoredMail, Option<MailDetails>)> = mails
        .iter()
        .filter_map(|m| {
            if !m.attachments_pending || m.rfc2822.is_none() {
                return None;
            }
            let eid = m.mail._id.as_ref()?.element_id.to_string();
            if let Some(retry) = attachment_retry_history.get(&eid) {
                if !retry.due(now) {
                    return None;
                }
            }
            Some((m.clone(), m.details.clone()))
        })
        .collect();

    if api_needed.is_empty() && attachment_retry_needed.is_empty() {
        return;
    }

    if !api_needed.is_empty() {
        debug!(
            "Pre-fetching {} mail details for {}",
            api_needed.len(),
            folder.imap_path
        );
    }
    if !attachment_retry_needed.is_empty() {
        debug!(
            "Retrying attachments for {} mail(s) in {}",
            attachment_retry_needed.len(),
            folder.imap_path
        );
    }

    for mail in &api_needed {
        tokio::time::sleep(INTER_REQUEST_DELAY).await;

        let result = retry(|| backend.load_mail_details(mail)).await;
        match result {
            Ok(Some(details)) => {
                let mut attachments_pending = false;
                let attachments_owned = if mail.attachments.is_empty() {
                    Vec::new()
                } else {
                    match backend.load_attachments(mail).await {
                        Ok(atts) => atts,
                        Err(e) => {
                            attachments_pending = is_transient_attachment_error(&e);
                            warn!(
                                "Failed to load attachments for {}: {e} (will {})",
                                mail._id
                                    .as_ref()
                                    .map(|id| id.element_id.to_string())
                                    .unwrap_or_default(),
                                if attachments_pending {
                                    "retry on next prefetch sweep"
                                } else {
                                    "ship body-only"
                                }
                            );
                            Vec::new()
                        }
                    }
                };
                let attachment_refs: Vec<(&TutanotaFile, &[u8])> = attachments_owned
                    .iter()
                    .map(|(f, d)| (f, d.as_slice()))
                    .collect();
                let rfc2822 = mail_to_rfc2822(mail, Some(&details), &attachment_refs);
                if let Some(id) = mail._id.as_ref() {
                    let eid = id.element_id.to_string();

                    if let Err(e) = local_store.write_eml(&eid, &rfc2822) {
                        warn!("Failed to cache eml {}: {}", eid, e);
                    }
                    if let Err(e) = local_store.mark_has_details(&eid) {
                        warn!("Failed to mark has_details {}: {}", eid, e);
                    }
                    // Index the plain-text body for full-text search.
                    let body_html = details
                        .body
                        .compressedText
                        .as_deref()
                        .or(details.body.text.as_deref())
                        .unwrap_or("");
                    if let Err(e) = local_store.index_body(&eid, &strip_html(body_html)) {
                        warn!("Failed to index body {}: {}", eid, e);
                    }
                    if attachments_pending {
                        attachment_retry_history.insert(eid.clone(), AttachmentRetry::first(now));
                    } else {
                        attachment_retry_history.remove(&eid);
                    }
                    // Set or cleared: a re-render with all attachments ends a
                    // pending state the database may still hold.
                    if let Err(e) = local_store.set_attachments_pending(&eid, attachments_pending) {
                        warn!("Failed to record attachments pending {}: {}", eid, e);
                    }

                    store
                        .update_mail_details(
                            &folder.id,
                            &eid,
                            details,
                            rfc2822,
                            attachments_pending,
                        )
                        .await;
                }
            }
            Ok(None) => {
                // The mail references neither a `MailDetailsBlob` nor a
                // `MailDetailsDraft` (legacy / malformed). Persist a
                // headers-only `.eml` and mark the row done so we don't
                // re-attempt every prefetch sweep.
                let rfc2822 = mail_to_rfc2822(mail, None, &[]);
                if let Some(id) = mail._id.as_ref() {
                    let eid = id.element_id.to_string();
                    if let Err(e) = local_store.write_eml(&eid, &rfc2822) {
                        warn!("Failed to cache headers-only eml {}: {}", eid, e);
                    }
                    if let Err(e) = local_store.mark_has_details(&eid) {
                        warn!("Failed to mark has_details {}: {}", eid, e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to prefetch details for {:?}: {}", mail.subject, e);
            }
        }
    }

    // Attachment-only retries. We already have the body & details cached
    // in the store; only the multipart envelope needs rebuilding.
    for (stored, details) in &attachment_retry_needed {
        tokio::time::sleep(INTER_REQUEST_DELAY).await;
        let eid = match stored.mail._id.as_ref() {
            Some(id) => id.element_id.to_string(),
            None => continue,
        };
        let attempts = attachment_retry_history
            .get(&eid)
            .map_or(1, |retry| retry.attempts + 1);
        attachment_retry_history.insert(
            eid.clone(),
            AttachmentRetry {
                last: std::time::Instant::now(),
                attempts,
            },
        );
        let details = match details {
            Some(details) => details.clone(),
            None => match backend.load_mail_details(&stored.mail).await {
                Ok(Some(details)) => details,
                // No details to render with: nothing a retry can add.
                Ok(None) => {
                    if let Err(e) = local_store.set_attachments_pending(&eid, false) {
                        warn!("Failed to clear attachments pending {}: {}", eid, e);
                    }
                    store
                        .update_mail_rfc2822(
                            &folder.id,
                            &eid,
                            stored.rfc2822.clone().unwrap_or_default(),
                        )
                        .await;
                    attachment_retry_history.remove(&eid);
                    continue;
                }
                Err(e) => {
                    debug!("Attachment retry for {eid}: details not loaded: {e}");
                    continue;
                }
            },
        };
        let details = &details;

        // On the last allowed attempt, or once pending for longer than
        // ATTACHMENT_RETRY_MAX_AGE (persisted, so restarts do not reset it),
        // a transient failure counts as permanent.
        let pending_for_ms = local_store
            .attachments_pending_since(&eid)
            .ok()
            .flatten()
            // A bare 1 is the column's earlier boolean form (unreleased
            // 93fe631): pending, age unknown — not "since 1970".
            .filter(|&since| since > 1)
            .and_then(|since| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|now| now.as_millis() as i64 - since)
            })
            .unwrap_or(0);
        let give_up = attempts >= ATTACHMENT_RETRY_MAX_ATTEMPTS
            || pending_for_ms >= ATTACHMENT_RETRY_MAX_AGE.as_millis() as i64;
        match backend.load_attachments(&stored.mail).await {
            Ok(attachments) => {
                let refs: Vec<(&TutanotaFile, &[u8])> =
                    attachments.iter().map(|(f, d)| (f, d.as_slice())).collect();
                let rfc2822 = mail_to_rfc2822(&stored.mail, Some(details), &refs);
                if let Err(e) = local_store.write_eml(&eid, &rfc2822) {
                    warn!("Failed to rewrite eml {}: {}", eid, e);
                } else {
                    // A mail first fetched on demand reaches this pass with
                    // neither done: it was not persisted without attachments.
                    if let Err(e) = local_store.mark_has_details(&eid) {
                        warn!("Failed to mark has_details {}: {}", eid, e);
                    }
                    if let Err(e) = local_store.index_body(&eid, &strip_html(body_html(details))) {
                        warn!("Failed to index body {}: {}", eid, e);
                    }
                }
                store.update_mail_rfc2822(&folder.id, &eid, rfc2822).await;
                if let Err(e) = local_store.set_attachments_pending(&eid, false) {
                    warn!("Failed to clear attachments pending {}: {}", eid, e);
                }
                attachment_retry_history.remove(&eid);
                debug!("Attachment retry succeeded for {}", eid);
            }
            Err(e) if is_transient_attachment_error(&e) && !give_up => {
                debug!("Attachment retry {attempts} for {eid} still transient: {e}");
            }
            Err(e) => {
                warn!(
                    "Attachment retry for {} failed permanently: {e} — giving up",
                    eid
                );
                // A mail first fetched on demand has its body only in
                // memory: keep it, body-only, as prefetch does on a
                // permanent failure. (A prefetched one is already on disk.)
                if !local_store.has_eml(&eid) {
                    if let Some(rfc) = stored.rfc2822.as_deref() {
                        if let Err(e) = local_store.write_eml(&eid, rfc) {
                            warn!("Failed to cache eml {}: {}", eid, e);
                        } else {
                            if let Err(e) = local_store.mark_has_details(&eid) {
                                warn!("Failed to mark has_details {}: {}", eid, e);
                            }
                            if let Err(e) =
                                local_store.index_body(&eid, &strip_html(body_html(details)))
                            {
                                warn!("Failed to index body {}: {}", eid, e);
                            }
                        }
                    }
                }
                // Clear the pending flag so we don't keep retrying a
                // permanent failure (e.g. server returned 404).
                if let Err(e) = local_store.set_attachments_pending(&eid, false) {
                    warn!("Failed to clear attachments pending {}: {}", eid, e);
                }
                store
                    .update_mail_rfc2822(
                        &folder.id,
                        &eid,
                        stored.rfc2822.clone().unwrap_or_default(),
                    )
                    .await;
                attachment_retry_history.remove(&eid);
            }
        }
    }
}

/// True when an attachment-load failure may succeed later, so the mail
/// waits for the retry pass instead of shipping body-only for good (a
/// body-only rendition on disk is never refetched). Matched on the SDK's
/// error text (`ApiCallError` / `HttpError` Display), which keeps us
/// decoupled from its variant tree:
/// - the session-key race on a freshly created File;
/// - throttling, server-side and network trouble (429, 503, 408, 502,
///   500, 423, an expired session, a failed request).
///
/// Anything else (e.g. "Not Found") is taken as permanent.
pub(crate) fn is_transient_attachment_error(err: &str) -> bool {
    const TRANSIENT: [&str; 11] = [
        "missing owner key/group data",
        "Session key resolution failure",
        "Too Many Requests",
        "Service Unavailable",
        "Request Timeout",
        "Bad gateway",
        "Internal Server",
        "Locked",
        "Session Expired",
        "Rest client error",
        // 474: Tuta retired this client version; a redeploy fixes it.
        "Invalid Software Version",
    ];
    TRANSIENT.iter().any(|marker| err.contains(marker))
}

async fn retry<F, Fut, T>(mut f: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let mut delay = Duration::from_secs(1);
    for attempt in 0..=MAX_RETRIES {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < MAX_RETRIES => {
                warn!(
                    "Attempt {} failed: {}, retrying in {:?}",
                    attempt + 1,
                    e,
                    delay
                );
                tokio::time::sleep(delay).await;
                delay = backoff(delay);
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

/// A mail's HTML body as Tuta stores it (compressed or not).
pub(crate) fn body_html(details: &MailDetails) -> &str {
    details
        .body
        .compressedText
        .as_deref()
        .or(details.body.text.as_deref())
        .unwrap_or("")
}

pub(crate) fn mail_to_metadata(mail: &Mail, folder_id: &str, uid: u32) -> MailMetadata {
    let (list_id, element_id) = mail
        ._id
        .as_ref()
        .map(|id| (id.list_id.to_string(), id.element_id.to_string()))
        .unwrap_or_default();

    let mail_json = serde_json::to_string(mail).unwrap_or_default();

    MailMetadata {
        list_id,
        element_id,
        folder_id: folder_id.to_string(),
        subject: mail.subject.clone(),
        sender_name: mail.sender.name.clone(),
        sender_address: mail.sender.address.clone(),
        received_date_ms: mail.receivedDate.as_millis() as i64,
        unread: mail.unread,
        has_details: false,
        uid: uid as i64,
        mail_json,
    }
}

fn backoff(current: Duration) -> Duration {
    let next = if current.is_zero() {
        Duration::from_secs(1)
    } else {
        current * 2
    };
    next.min(Duration::from_secs(120))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tutasdk::date::DateTime;
    use tutasdk::entities::generated::tutanota::MailAddress;
    use tutasdk::{GeneratedId, IdTupleGenerated};

    fn id(s: &str) -> GeneratedId {
        GeneratedId(s.to_string())
    }

    /// Minimal `Mail` fixture for `MailStore` tests. Only the `_id` and a
    /// couple of metadata fields are read by the helpers under test; the rest
    /// is filled with defaults.
    pub(crate) fn make_mail(list: &str, element: &str, subject: &str, unread: bool) -> Mail {
        Mail {
            _id: Some(IdTupleGenerated::new(id(list), id(element))),
            _permissions: id("perm"),
            _format: 0,
            _ownerEncSessionKey: None,
            subject: subject.to_string(),
            receivedDate: DateTime::from_millis(1735130245000),
            state: 2,
            unread,
            confidential: false,
            replyType: 0,
            _ownerGroup: None,
            differentEnvelopeSender: None,
            listUnsubscribe: false,
            movedTime: None,
            phishingStatus: 0,
            authStatus: None,
            method: 0,
            recipientCount: 1,
            encryptionAuthStatus: None,
            _ownerKeyVersion: None,
            processingState: 0,
            processNeeded: false,
            sendAt: None,
            serverClassificationData: None,
            _kdfNonce: None,
            sender: MailAddress {
                _id: None,
                name: "Sender".to_string(),
                address: "sender@tuta.com".to_string(),
                contact: None,
                _errors: Default::default(),
            },
            attachments: vec![],
            conversationEntry: IdTupleGenerated::new(id("conv_list"), id("conv_elem")),
            firstRecipient: None,
            mailDetails: None,
            mailDetailsDraft: None,
            bucketKey: None,
            sets: vec![],
            clientSpamClassifierResult: None,
            _errors: Default::default(),
        }
    }

    pub(crate) fn stored(mail: Mail, uid: u32) -> StoredMail {
        StoredMail {
            mail,
            details: None,
            rfc2822: None,
            uid,
            attachments_pending: false,
        }
    }

    #[test]
    fn body_fetch_cooldown_blocks_then_expires() {
        let store = MailStore::new();
        assert!(!store.body_fetch_on_cooldown("mail-a"));
        store.mark_body_fetch_failed("mail-a");
        assert!(store.body_fetch_on_cooldown("mail-a"));
        // A different mail is unaffected.
        assert!(!store.body_fetch_on_cooldown("mail-b"));
        // An elapsed entry is treated as expired and dropped lazily.
        crate::util::lock_recover(&store.body_fetch_cooldown).insert(
            "mail-a".to_string(),
            Instant::now() - Duration::from_secs(1),
        );
        assert!(!store.body_fetch_on_cooldown("mail-a"));
    }

    #[tokio::test]
    async fn refresh_mail_in_place_updates_metadata_in_every_folder() {
        let store = MailStore::new();
        // Same mail referenced in two folders (Tuta's model allows this via
        // MailSet membership). Both rows must be updated when the entity
        // changes — e.g. an "unread" toggle from the webmail.
        let m_a = make_mail("L1", "M1", "Hello", true);
        let m_b = m_a.clone();
        store.set_folder("folderA", vec![stored(m_a, 7)]).await;
        store.set_folder("folderB", vec![stored(m_b, 12)]).await;

        let mut updated = make_mail("L1", "M1", "Hello [updated]", false);
        // also tweak subject to verify the whole entity is swapped in.
        updated.subject = "Hello [updated]".into();
        store.refresh_mail_in_place(&updated).await;

        let a = store.get_folder("folderA").await;
        let b = store.get_folder("folderB").await;
        assert_eq!(a[0].mail.subject, "Hello [updated]");
        assert!(!a[0].mail.unread);
        assert_eq!(
            a[0].uid, 7,
            "UID is per-folder state, must survive a refresh"
        );
        assert_eq!(b[0].mail.subject, "Hello [updated]");
        assert_eq!(b[0].uid, 12);
    }

    #[tokio::test]
    async fn refresh_mail_in_place_no_match_is_noop() {
        let store = MailStore::new();
        store
            .set_folder("folderA", vec![stored(make_mail("L1", "M1", "S", true), 1)])
            .await;
        let stranger = make_mail("L1", "OTHER", "X", false);
        store.refresh_mail_in_place(&stranger).await;
        let a = store.get_folder("folderA").await;
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].mail.subject, "S"); // unchanged
    }

    #[tokio::test]
    async fn remove_mail_everywhere_drops_from_all_folders() {
        let store = MailStore::new();
        store
            .set_folder(
                "folderA",
                vec![
                    stored(make_mail("L1", "keep", "k", true), 1),
                    stored(make_mail("L1", "gone", "g", true), 2),
                ],
            )
            .await;
        store
            .set_folder(
                "folderB",
                vec![stored(make_mail("L1", "gone", "g", true), 5)],
            )
            .await;
        store.remove_mail_everywhere("gone").await;

        let a = store.get_folder("folderA").await;
        let b = store.get_folder("folderB").await;
        assert_eq!(a.len(), 1);
        assert_eq!(
            a[0].mail._id.as_ref().unwrap().element_id.to_string(),
            "keep"
        );
        assert!(b.is_empty());
    }

    #[tokio::test]
    async fn remove_mail_everywhere_unknown_id_is_noop() {
        let store = MailStore::new();
        store
            .set_folder("folderA", vec![stored(make_mail("L1", "M1", "s", true), 1)])
            .await;
        store.remove_mail_everywhere("unknown").await;
        assert_eq!(store.get_folder("folderA").await.len(), 1);
    }

    #[tokio::test]
    async fn find_mail_anywhere_returns_first_match() {
        let store = MailStore::new();
        store
            .set_folder("A", vec![stored(make_mail("L1", "shared", "x", true), 7)])
            .await;
        store
            .set_folder("B", vec![stored(make_mail("L1", "shared", "x", true), 11)])
            .await;
        let found = store.find_mail_anywhere("shared").await.expect("must find");
        assert!(found.0 == "A" || found.0 == "B");
        assert_eq!(
            found.1.mail._id.as_ref().unwrap().element_id.to_string(),
            "shared"
        );
        assert!(store.find_mail_anywhere("missing").await.is_none());
    }

    #[tokio::test]
    async fn is_mail_anywhere_reflects_presence() {
        let store = MailStore::new();
        store
            .set_folder("A", vec![stored(make_mail("L1", "e1", "s", true), 1)])
            .await;
        assert!(store.is_mail_anywhere("e1").await);
        assert!(!store.is_mail_anywhere("e2").await);
    }

    #[tokio::test]
    async fn remove_mail_from_folder_only_touches_that_folder() {
        let store = MailStore::new();
        store
            .set_folder(
                "A",
                vec![
                    stored(make_mail("L1", "k", "keep", true), 1),
                    stored(make_mail("L1", "g", "gone", true), 2),
                ],
            )
            .await;
        store
            .set_folder("B", vec![stored(make_mail("L1", "g", "gone", true), 5)])
            .await;

        let removed = store.remove_mail_from_folder("A", "g").await;
        assert!(removed);
        assert_eq!(store.get_folder("A").await.len(), 1);
        // B still has the mail — `remove_mail_from_folder` is scoped.
        assert_eq!(store.get_folder("B").await.len(), 1);
        // Idempotent: re-removing the same mail from A is a no-op.
        assert!(!store.remove_mail_from_folder("A", "g").await);
    }

    #[tokio::test]
    async fn upsert_mail_in_folder_replaces_existing_by_element_id() {
        let store = MailStore::new();
        store
            .set_folder("A", vec![stored(make_mail("L1", "e1", "old", true), 4)])
            .await;
        store
            .upsert_mail_in_folder("A", stored(make_mail("L1", "e1", "new", false), 4))
            .await;
        let mails = store.get_folder("A").await;
        // Same element_id → replaced in place, no duplicate.
        assert_eq!(mails.len(), 1);
        assert_eq!(mails[0].mail.subject, "new");
        assert!(!mails[0].mail.unread);
    }

    #[tokio::test]
    async fn upsert_mail_in_folder_appends_when_new() {
        let store = MailStore::new();
        store
            .set_folder("A", vec![stored(make_mail("L1", "e1", "one", true), 1)])
            .await;
        store
            .upsert_mail_in_folder("A", stored(make_mail("L1", "e2", "two", true), 2))
            .await;
        assert_eq!(store.get_folder("A").await.len(), 2);
    }

    #[tokio::test]
    async fn set_labels_populates_registry_and_bumps_generation() {
        let store = MailStore::new();
        assert!(store.label_registry().await.is_empty());
        let watch = store.subscribe();
        store
            .set_labels(vec![crate::labels::LabelInfo {
                id: "l1".into(),
                list_id: "labels".into(),
                name: "Package Tracking".into(),
                color: Some("#ff0000".into()),
            }])
            .await;
        // IDLE sessions wait on the generation channel; a registry change
        // must wake them like any other store mutation.
        assert!(watch.has_changed().unwrap());
        let reg = store.label_registry().await;
        assert_eq!(reg.keyword_for_label("l1"), Some("Package_Tracking"));
    }

    #[tokio::test]
    async fn prune_unknown_folders_drops_disappeared_ones() {
        let store = MailStore::new();
        store
            .set_folder("keep", vec![stored(make_mail("L1", "M1", "k", true), 1)])
            .await;
        store
            .set_folder("gone", vec![stored(make_mail("L1", "M2", "g", true), 2)])
            .await;
        let known: std::collections::HashSet<String> = ["keep".to_string()].into_iter().collect();
        let removed = store.prune_unknown_folders(&known).await;
        assert_eq!(removed, vec!["gone".to_string()]);
        assert_eq!(store.get_folder("keep").await.len(), 1);
        assert!(store.get_folder("gone").await.is_empty());
    }
}
