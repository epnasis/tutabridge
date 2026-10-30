use log::{debug, info, warn};
use std::sync::Arc;
use tutasdk::entities::generated::tutanota::{Mail, MailAddress, MailDetails, TutanotaFile};

use crate::imap::search::{self, MsgView};
use crate::labels::{LabelInfo, LabelRegistry};
use crate::mail::rfc2822::{extract_headers, format_address, format_internal_date};
use crate::mail::{mail_to_rfc2822, strip_html};
use crate::store::LocalStore;
use crate::sync::MailStore;
use crate::tuta::{FolderInfo, MailBackend};

#[derive(Debug, Clone, PartialEq)]
enum State {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

struct CachedMail {
    mail: Mail,
    details: Option<MailDetails>,
    rfc2822: Option<String>,
    /// `rfc2822` always carries the real headers, but for messages outside the
    /// body-prefetch window it holds a placeholder body. `body_loaded` tracks
    /// whether the *body* is final: `true` once we have real details (or have
    /// confirmed the message has no body source), `false` while a body FETCH
    /// still needs to pull it on demand.
    body_loaded: bool,
    uid: u32,
    deleted: bool,
}

pub struct ImapSession {
    store: Arc<MailStore>,
    backend: Arc<dyn MailBackend>,
    /// The on-disk store, used for full-text body search. `None` in unit tests
    /// (body terms then simply don't match).
    local_store: Option<Arc<LocalStore>>,
    state: State,
    selected_folder: Option<FolderInfo>,
    mails: Vec<CachedMail>,
    uid_next: u32,
    idle_tag: Option<String>,
    auth_tag: Option<String>,
    password_hash: Option<String>,
}

impl ImapSession {
    pub fn new(
        store: Arc<MailStore>,
        backend: Arc<dyn MailBackend>,
        password_hash: Option<String>,
        local_store: Option<Arc<LocalStore>>,
    ) -> Self {
        Self {
            store,
            backend,
            local_store,
            state: State::NotAuthenticated,
            selected_folder: None,
            mails: Vec::new(),
            uid_next: 1,
            idle_tag: None,
            auth_tag: None,
            password_hash,
        }
    }

    pub fn is_logout(&self) -> bool {
        self.state == State::Logout
    }

    pub fn is_idle(&self) -> bool {
        self.idle_tag.is_some()
    }

    pub fn is_awaiting_auth(&self) -> bool {
        self.auth_tag.is_some()
    }

    pub fn handle_auth_response(&mut self, line: &str) -> Vec<String> {
        let tag = match self.auth_tag.take() {
            Some(t) => t,
            None => return vec![],
        };

        let decoded =
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, line.trim()) {
                Ok(d) => d,
                Err(_) => {
                    return vec![format!(
                        "{} NO [AUTHENTICATIONFAILED] Invalid base64\r\n",
                        tag
                    )];
                }
            };

        // PLAIN format: \0authcid\0password (authzid is empty)
        let parts: Vec<&[u8]> = decoded.splitn(3, |&b| b == 0).collect();
        let password = if parts.len() == 3 {
            String::from_utf8_lossy(parts[2]).to_string()
        } else if parts.len() == 2 {
            String::from_utf8_lossy(parts[1]).to_string()
        } else {
            return vec![format!(
                "{} NO [AUTHENTICATIONFAILED] Invalid PLAIN data\r\n",
                tag
            )];
        };

        if let Some(ref expected) = self.password_hash {
            if password != *expected {
                return vec![format!(
                    "{} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n",
                    tag
                )];
            }
        }

        self.state = State::Authenticated;
        info!("IMAP client authenticated via AUTHENTICATE PLAIN");
        vec![format!("{} OK AUTHENTICATE completed\r\n", tag)]
    }

    pub fn end_idle(&mut self) -> Vec<String> {
        if let Some(tag) = self.idle_tag.take() {
            vec![format!("{} OK IDLE terminated\r\n", tag)]
        } else {
            vec![]
        }
    }

    pub async fn check_new_mail(&mut self) -> Vec<String> {
        let folder = match self.selected_folder.clone() {
            Some(f) => f,
            None => return vec![],
        };

        // Compare the new authoritative list against our session view by
        // element id. Count-only diffing is not enough — a MOVE between two
        // folders that share the same `sync_limit` window keeps the count
        // constant while swapping one mail for another. We must detect set
        // changes and signal them to the client (EXPUNGE for departed
        // mails, EXISTS for the new count so the client refetches).
        let new_list = self.store.get_folder(&folder.id).await;
        let new_eids: std::collections::HashSet<String> = new_list
            .iter()
            .filter_map(|m| m.mail._id.as_ref().map(|id| id.element_id.to_string()))
            .collect();

        // EXPUNGE seqnos must reference the message numbers as they were
        // **before** this update, so compute them against `self.mails`.
        let mut expunges: Vec<u32> = Vec::new();
        for (idx, m) in self.mails.iter().enumerate() {
            if let Some(eid) = m.mail._id.as_ref().map(|id| id.element_id.to_string()) {
                if !new_eids.contains(&eid) {
                    expunges.push((idx as u32) + 1);
                }
            }
        }

        let old_eids: std::collections::HashSet<String> = self
            .mails
            .iter()
            .filter_map(|m| m.mail._id.as_ref().map(|id| id.element_id.to_string()))
            .collect();
        let added = new_list
            .iter()
            .filter(|m| {
                m.mail
                    ._id
                    .as_ref()
                    .map(|id| !old_eids.contains(&id.element_id.to_string()))
                    .unwrap_or(false)
            })
            .count();

        let membership_changed =
            !expunges.is_empty() || added > 0 || new_list.len() != self.mails.len();

        // Apply the new view even when there is nothing to signal: flag-level
        // changes (read/unread toggles, label membership) alter no message
        // ids, but this session's next FETCH must still see them. RFC 3501:
        // EXPUNGEs go in descending seqno order so subsequent values are not
        // shifted.
        let _ = self.refresh_mails(&folder.id).await;
        if !membership_changed {
            return vec![];
        }

        let mut responses = Vec::with_capacity(expunges.len() + 1);
        expunges.sort_unstable_by(|a, b| b.cmp(a));
        for s in expunges {
            responses.push(format!("* {} EXPUNGE\r\n", s));
        }
        responses.push(format!("* {} EXISTS\r\n", self.mails.len()));
        responses
    }

    /// `(UIDVALIDITY, UIDNEXT)` of a folder. Both come from its persisted
    /// counter, which every UID was assigned from; `memory_next` (one past
    /// the highest UID loaded) only guards against a store that lags. Without
    /// a local store (tests) UIDs never outlive the process, so a constant
    /// UIDVALIDITY is as good as any.
    ///
    /// A store error is an error, not a guess: a made-up UIDVALIDITY would make
    /// a client drop its cache now and again when the real one returns.
    fn uid_state(&self, folder_id: &str, memory_next: u32) -> Result<(u32, u32), String> {
        match self
            .local_store
            .as_ref()
            .map(|local_store| local_store.folder_uid_state(folder_id))
        {
            Some(Ok((validity, next))) => Ok((validity, next.max(memory_next))),
            Some(Err(e)) => {
                log::warn!("UID state of {folder_id} unavailable: {e}");
                Err(e.to_string())
            }
            None => Ok((1, memory_next)),
        }
    }

    pub async fn handle_command(&mut self, line: &str) -> Vec<String> {
        let (tag, cmd, args) = parse_command(line);

        match cmd.to_uppercase().as_str() {
            "CAPABILITY" => self.cmd_capability(&tag),
            "NOOP" => vec![format!("{} OK NOOP completed\r\n", tag)],
            "LOGOUT" => self.cmd_logout(&tag),
            "LOGIN" => self.cmd_login(&tag, &args),
            "AUTHENTICATE" => {
                if args.trim().eq_ignore_ascii_case("PLAIN") {
                    self.auth_tag = Some(tag.clone());
                    vec!["+ \r\n".to_string()]
                } else {
                    vec![format!("{} NO Unsupported mechanism\r\n", tag)]
                }
            }
            "LIST" => self.cmd_list(&tag, &args, ListKind::List).await,
            "LSUB" => self.cmd_list(&tag, &args, ListKind::Lsub).await,
            "SUBSCRIBE" => self.cmd_subscribe(&tag, &args, true).await,
            "UNSUBSCRIBE" => self.cmd_subscribe(&tag, &args, false).await,
            "SELECT" => self.cmd_select(&tag, &args).await,
            "EXAMINE" => self.cmd_select(&tag, &args).await,
            "STATUS" => self.cmd_status(&tag, &args).await,
            "FETCH" => self.cmd_fetch(&tag, &args, false).await,
            "UID" => self.cmd_uid(&tag, &args).await,
            "CLOSE" => self.cmd_close(&tag),
            "EXPUNGE" => self.cmd_expunge(&tag).await,
            "SEARCH" => self.cmd_search(&tag, &args, false).await,
            "STORE" => self.cmd_store(&tag, &args, false).await,
            "MOVE" => self.cmd_move(&tag, &args, false).await,
            "COPY" => self.cmd_copy(&tag),
            "CREATE" | "DELETE" | "RENAME" => vec![format!(
                "{} NO [CANNOT] {} is not supported: manage folders in Tuta; MOVE to existing folders (Trash, Archive, ...) works\r\n",
                tag,
                cmd.to_uppercase()
            )],
            "IDLE" => {
                self.idle_tag = Some(tag.clone());
                vec!["+ idling\r\n".to_string()]
            }
            "NAMESPACE" => vec![
                "* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n".to_string(),
                format!("{} OK NAMESPACE completed\r\n", tag),
            ],
            _ => vec![format!("{} BAD Unknown command\r\n", tag)],
        }
    }

    /// `true` if `mailbox` resolves to the Sent folder. Tuta saves sent mail
    /// server-side, so an `APPEND` there is a no-op (see `handle_append` in the
    /// connection loop), which is what lets a client's "save to Sent" succeed
    /// without creating a duplicate.
    pub(crate) async fn append_targets_sent(&self, mailbox: &str) -> bool {
        let name = super::utf7::decode(mailbox).unwrap_or_else(|| mailbox.to_string());
        self.store
            .folder_by_imap_path(&name)
            .await
            .map(|f| f.special_use.as_deref() == Some("\\Sent"))
            .unwrap_or(false)
    }

    fn cmd_capability(&self, tag: &str) -> Vec<String> {
        vec![
            "* CAPABILITY IMAP4rev1 AUTH=PLAIN IDLE NAMESPACE UIDPLUS MOVE\r\n".to_string(),
            format!("{} OK CAPABILITY completed\r\n", tag),
        ]
    }

    fn cmd_logout(&mut self, tag: &str) -> Vec<String> {
        self.state = State::Logout;
        vec![
            "* BYE TutaBridge signing off\r\n".to_string(),
            format!("{} OK LOGOUT completed\r\n", tag),
        ]
    }

    fn cmd_login(&mut self, tag: &str, args: &str) -> Vec<String> {
        if let Some(ref expected) = self.password_hash {
            let (_, password) = parse_login_args(args);
            if password != *expected {
                return vec![format!(
                    "{} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n",
                    tag
                )];
            }
        }
        self.state = State::Authenticated;
        info!("IMAP client authenticated (bridge session)");
        vec![format!("{} OK LOGIN completed\r\n", tag)]
    }

    /// LIST / LSUB (RFC 3501 §6.3.8-9): the reference and pattern select
    /// which folders are named — `*` matches any run, `%` any run without
    /// the `/` delimiter, `INBOX` in any case.
    async fn cmd_list(&self, tag: &str, args: &str, kind: ListKind) -> Vec<String> {
        if self.state == State::NotAuthenticated {
            return vec![format!("{} NO Not authenticated\r\n", tag)];
        }
        let name = kind.name();
        let mut args = args.trim();
        // LIST-EXTENDED (RFC 5258) is not advertised, but a client may send
        // its forms anyway. Options that change the answer are applied;
        // anything else is refused rather than ignored.
        let mut subscribed_only = false;
        let mut special_use_only = false;
        if let (ListKind::List, Some(rest)) = (kind, args.strip_prefix('(')) {
            let Some((options, rest)) = rest.split_once(')') else {
                return vec![format!("{tag} BAD unbalanced selection options\r\n")];
            };
            for option in options.split_whitespace() {
                match option.to_ascii_uppercase().as_str() {
                    "SUBSCRIBED" => subscribed_only = true,
                    "SPECIAL-USE" => special_use_only = true,
                    other => {
                        return vec![format!(
                            "{tag} BAD selection option {} is not supported\r\n",
                            other.escape_default()
                        )]
                    }
                }
            }
            args = rest.trim_start();
        }
        let (reference, rest) = parse_imap_token(args);
        if args.is_empty() || rest.trim_start().is_empty() {
            return vec![format!(
                "{tag} BAD {name} needs a reference and a mailbox pattern\r\n"
            )];
        }
        let (pattern, rest) = parse_imap_token(rest.trim_start());
        let mut return_subscribed = false;
        let mut return_children = false;
        let rest = rest.trim();
        if !rest.is_empty() {
            let options = match (kind, return_options(rest)) {
                (ListKind::List, Some(options)) => options,
                _ => {
                    return vec![format!(
                        "{tag} BAD unexpected arguments after the pattern\r\n"
                    )]
                }
            };
            for option in options {
                match option.to_ascii_uppercase().as_str() {
                    "SUBSCRIBED" => return_subscribed = true,
                    "CHILDREN" => return_children = true,
                    // Special-use flags are always returned.
                    "SPECIAL-USE" => {}
                    other => {
                        return vec![format!(
                            "{tag} BAD return option {} is not supported\r\n",
                            other.escape_default()
                        )]
                    }
                }
            }
        }

        // An empty pattern asks only for the hierarchy delimiter.
        if pattern.is_empty() {
            return vec![
                format!("* {name} (\\Noselect) \"/\" \"\"\r\n"),
                format!("{tag} OK {name} completed\r\n"),
            ];
        }

        let decode = |s: &str| super::utf7::decode(s).unwrap_or_else(|| s.to_string());
        let pattern = format!("{}{}", decode(&reference), decode(&pattern));
        let only_subscribed = kind == ListKind::Lsub || subscribed_only;
        let unsubscribed = match (only_subscribed || return_subscribed, &self.local_store) {
            (true, Some(local_store)) => local_store.unsubscribed_folders(),
            _ => Default::default(),
        };
        let folders = self.store.list_folders().await;
        let mut responses = Vec::new();
        for folder in &folders {
            if !mailbox_matches(&pattern, &folder.imap_path) {
                continue;
            }
            if special_use_only && folder.special_use.is_none() {
                continue;
            }
            let mut flags: Vec<&str> = folder.special_use.iter().map(String::as_str).collect();
            let prefix = format!("{}/", folder.imap_path);
            let subscribed = !unsubscribed.contains(&folder.id);
            if only_subscribed && !subscribed {
                // RFC 3501 §6.3.9: an unsubscribed name is listed (as
                // \Noselect) only when a subscribed name under it exists that
                // the pattern itself cannot reach — `%` stopping at it.
                let unreached_below = folders.iter().any(|f| {
                    f.imap_path.starts_with(&prefix)
                        && !unsubscribed.contains(&f.id)
                        && !mailbox_matches(&pattern, &f.imap_path)
                });
                if kind == ListKind::List || !unreached_below {
                    continue;
                }
                flags = vec!["\\Noselect"];
            } else if (subscribed_only || return_subscribed) && subscribed {
                flags.push("\\Subscribed");
            }
            if return_children {
                let has_children = folders.iter().any(|f| f.imap_path.starts_with(&prefix));
                flags.push(if has_children {
                    "\\HasChildren"
                } else {
                    "\\HasNoChildren"
                });
            }
            responses.push(format!(
                "* {name} ({}) \"/\" {}\r\n",
                flags.join(" "),
                imap_string(&super::utf7::encode(&folder.imap_path))
            ));
        }
        responses.push(format!("{tag} OK {name} completed\r\n"));
        responses
    }

    /// SUBSCRIBE / UNSUBSCRIBE. Persisted, so LSUB answers what the client
    /// asked for — an OK that LSUB then contradicted would be a false success.
    async fn cmd_subscribe(&self, tag: &str, args: &str, subscribe: bool) -> Vec<String> {
        let cmd = if subscribe {
            "SUBSCRIBE"
        } else {
            "UNSUBSCRIBE"
        };
        if self.state == State::NotAuthenticated {
            return vec![format!("{tag} NO Not authenticated\r\n")];
        }
        let (raw_name, _) = parse_imap_token(args.trim());
        if raw_name.is_empty() {
            return vec![format!("{tag} BAD {cmd} needs a mailbox name\r\n")];
        }
        let name = super::utf7::decode(&raw_name).unwrap_or(raw_name);
        let Some(folder) = self.store.folder_by_imap_path(&name).await else {
            // Not subscribed to a name that does not exist: nothing to undo.
            if !subscribe {
                return vec![format!("{tag} OK {cmd} completed\r\n")];
            }
            return vec![format!("{tag} NO [NONEXISTENT] Mailbox does not exist\r\n")];
        };
        let Some(local_store) = &self.local_store else {
            return vec![format!(
                "{tag} NO [UNAVAILABLE] subscriptions need the local store\r\n"
            )];
        };
        match local_store.set_subscribed(&folder.id, subscribe) {
            Ok(()) => vec![format!("{tag} OK {cmd} completed\r\n")],
            Err(e) => {
                log::warn!("{cmd} {}: {e}", folder.imap_path);
                vec![format!(
                    "{tag} NO [UNAVAILABLE] {cmd} could not be saved (see the bridge log)\r\n"
                )]
            }
        }
    }

    async fn cmd_select(&mut self, tag: &str, args: &str) -> Vec<String> {
        if self.state == State::NotAuthenticated {
            return vec![format!("{} NO Not authenticated\r\n", tag)];
        }

        // A quoted name may carry escapes (`"Say \\"hi\\""`), as LIST sends it.
        let (raw_name, _) = parse_imap_token(args.trim());
        let folder_name = super::utf7::decode(&raw_name).unwrap_or_else(|| raw_name.clone());
        let folder = match self.store.folder_by_imap_path(&folder_name).await {
            Some(f) => f,
            None => {
                return vec![format!(
                    "{} NO [NONEXISTENT] Mailbox does not exist\r\n",
                    tag
                )];
            }
        };
        let folder_id = folder.id.clone();
        self.selected_folder = Some(folder);
        self.state = State::Selected;
        // UIDNEXT is per mailbox: the previous one's must not carry over.
        self.uid_next = 1;

        match self.refresh_mails(&folder_id).await {
            Ok(()) => {
                let count = self.mails.len();
                let first_unseen = self
                    .mails
                    .iter()
                    .position(|m| m.mail.unread)
                    .map(|i| i + 1)
                    .unwrap_or(0);

                let labels = self.store.label_registry().await;
                let (uid_validity, uid_next) = match self.uid_state(&folder_id, self.uid_next) {
                    Ok(state) => state,
                    Err(_) => {
                        self.selected_folder = None;
                        self.state = State::Authenticated;
                        return vec![format!(
                            "{tag} NO [UNAVAILABLE] mailbox UID state could not be read (see the bridge log)\r\n"
                        )];
                    }
                };
                let mut resp = vec![
                    format!("* {} EXISTS\r\n", count),
                    "* 0 RECENT\r\n".to_string(),
                    flags_advertisement(&labels),
                    permanent_flags_advertisement(&labels),
                    format!("* OK [UIDVALIDITY {uid_validity}] UIDs valid\r\n"),
                    format!("* OK [UIDNEXT {uid_next}] Predicted next UID\r\n"),
                ];
                if first_unseen > 0 {
                    resp.push(format!("* OK [UNSEEN {}] First unseen\r\n", first_unseen));
                }
                resp.push(format!("{} OK [READ-WRITE] SELECT completed\r\n", tag));
                resp
            }
            Err(e) => {
                log::error!("Failed to load mails for {}: {}", folder_name, e);
                vec![
                    "* 0 EXISTS\r\n".to_string(),
                    "* 0 RECENT\r\n".to_string(),
                    format!("{} OK [READ-WRITE] SELECT completed\r\n", tag),
                ]
            }
        }
    }

    async fn cmd_status(&self, tag: &str, args: &str) -> Vec<String> {
        if self.state == State::NotAuthenticated {
            return vec![format!("{} NO Not authenticated\r\n", tag)];
        }
        let (raw_name, _) = parse_imap_token(args.trim());
        let folder_name = super::utf7::decode(&raw_name).unwrap_or_else(|| raw_name.clone());
        let Some(folder) = self.store.folder_by_imap_path(&folder_name).await else {
            return vec![format!("{tag} NO [NONEXISTENT] Mailbox does not exist\r\n")];
        };
        let stored = self.store.get_folder(&folder.id).await;
        let count = stored.len();
        let unseen = stored.iter().filter(|m| m.mail.unread).count();
        // The asked-for mailbox's own state, not the selected one's.
        let memory_next = stored.iter().map(|m| m.uid + 1).max().unwrap_or(1);
        let Ok((uid_validity, uid_next)) = self.uid_state(&folder.id, memory_next) else {
            return vec![format!(
                "{tag} NO [UNAVAILABLE] mailbox UID state could not be read (see the bridge log)\r\n"
            )];
        };
        vec![
            format!(
                "* STATUS {} (MESSAGES {} UNSEEN {} RECENT 0 UIDNEXT {} UIDVALIDITY {})\r\n",
                // The client's (modified UTF-7) name, quoted and escaped again.
                imap_string(&raw_name),
                count,
                unseen,
                uid_next,
                uid_validity
            ),
            format!("{} OK STATUS completed\r\n", tag),
        ]
    }

    async fn cmd_fetch(&mut self, tag: &str, args: &str, uid_mode: bool) -> Vec<String> {
        if self.state != State::Selected {
            return vec![format!("{} NO No mailbox selected\r\n", tag)];
        }

        let (seq_set, items) = parse_fetch_args(args);
        let Some(indices) = self.resolve_sequence_set(&seq_set, uid_mode) else {
            return vec![format!("{tag} BAD invalid sequence set\r\n")];
        };
        // One registry snapshot per FETCH command: label keywords in the
        // FLAGS items stay consistent across the whole response.
        let labels = self.store.label_registry().await;

        let mut responses = Vec::new();

        for idx in indices {
            if idx >= self.mails.len() {
                continue;
            }

            // Make sure we have a renderable body before answering a body
            // FETCH. The mailbox lists every message, but only the newest
            // `sync_limit` bodies are pre-warmed — older ones are fetched
            // here, on demand, the first time a client opens them.
            if needs_body(&items) && !self.mails[idx].body_loaded {
                let elem_id = self.mails[idx]
                    .mail
                    ._id
                    .as_ref()
                    .map(|id| id.element_id.to_string());

                if self.mails[idx].details.is_some() {
                    // Have details already, just render the envelope.
                    let rfc = mail_to_rfc2822(
                        &self.mails[idx].mail,
                        self.mails[idx].details.as_ref(),
                        &[],
                    );
                    self.mails[idx].rfc2822 = Some(rfc);
                    self.mails[idx].body_loaded = true;
                } else if let Some((details, rfc)) = match (&elem_id, &self.selected_folder) {
                    // The syncer may have filled it in since our snapshot.
                    (Some(eid), Some(folder)) => self.store.get_details(&folder.id, eid).await,
                    _ => None,
                } {
                    self.mails[idx].details = Some(details);
                    self.mails[idx].rfc2822 = Some(rfc);
                    self.mails[idx].body_loaded = true;
                } else {
                    // Out of the prefetch window: fetch the body on demand,
                    // unless this mail is in a post-failure cooldown (do not
                    // re-hit a throttled server on every client redraw).
                    if let Some(eid) = &elem_id {
                        if self.store.body_fetch_on_cooldown(eid) {
                            return vec![format!(
                                "{} NO [UNAVAILABLE] message body not fetched: the last attempt failed and the bridge waits before retrying (see the bridge log for that error)\r\n",
                                tag
                            )];
                        }
                    }
                    let mail = self.mails[idx].mail.clone();
                    match self.backend.load_mail_details(&mail).await {
                        Ok(Some(details)) => {
                            let (atts, attachments_complete) =
                                match self.backend.load_attachments(&mail).await {
                                    Ok(atts) => (atts, true),
                                    Err(_) => (Vec::new(), false),
                                };
                            let refs: Vec<(&TutanotaFile, &[u8])> =
                                atts.iter().map(|(f, d)| (f, d.as_slice())).collect();
                            let rfc = mail_to_rfc2822(&mail, Some(&details), &refs);
                            // Persist it like a prefetched body, so it survives a
                            // restart and SEARCH BODY finds it. A rendition missing
                            // its attachments stays memory-only: once on disk,
                            // prefetch takes `has_eml` to mean done.
                            if let (true, Some(eid), Some(ls)) =
                                (attachments_complete, &elem_id, &self.local_store)
                            {
                                if let Err(e) = ls.write_eml(eid, &rfc) {
                                    warn!("Failed to cache eml {eid}: {e}");
                                } else if let Err(e) = ls.mark_has_details(eid) {
                                    warn!("Failed to mark has_details {eid}: {e}");
                                }
                                let body_html = details
                                    .body
                                    .compressedText
                                    .as_deref()
                                    .or(details.body.text.as_deref())
                                    .unwrap_or("");
                                if let Err(e) = ls.index_body(eid, &strip_html(body_html)) {
                                    warn!("Failed to index body {eid}: {e}");
                                }
                            }
                            // Share into the in-memory store so other
                            // connections (and stats) see it too.
                            if let (Some(eid), Some(folder)) = (&elem_id, &self.selected_folder) {
                                self.store
                                    .update_mail_details(
                                        &folder.id,
                                        eid,
                                        details.clone(),
                                        rfc.clone(),
                                        false,
                                    )
                                    .await;
                            }
                            self.mails[idx].details = Some(details);
                            self.mails[idx].rfc2822 = Some(rfc);
                            self.mails[idx].body_loaded = true;
                        }
                        Ok(None) => {
                            // Legacy mail with no body reference — headers only.
                            // Mark loaded so we don't re-hit the network on
                            // every body FETCH of a message that has no body.
                            self.mails[idx].body_loaded = true;
                            debug!("uid={} has no body source", self.mails[idx].uid);
                        }
                        Err(e) => {
                            log::warn!(
                                "On-demand body fetch failed for uid={}: {e}",
                                self.mails[idx].uid
                            );
                            if let Some(eid) = &elem_id {
                                self.store.mark_body_fetch_failed(eid);
                            }
                            return vec![format!(
                                "{} NO [UNAVAILABLE] could not fetch message body from Tuta: {}\r\n",
                                tag,
                                single_line(&e.to_string())
                            )];
                        }
                    }
                }
            }

            let cached = &self.mails[idx];
            let seq = idx + 1;
            let resp = build_fetch_response(seq, cached, &items, uid_mode, &labels);
            responses.push(resp);
        }

        let cmd_name = if uid_mode { "UID FETCH" } else { "FETCH" };
        responses.push(format!("{} OK {} completed\r\n", tag, cmd_name));
        responses
    }

    async fn cmd_search(&self, tag: &str, args: &str, uid_mode: bool) -> Vec<String> {
        if self.state != State::Selected {
            return vec![format!("{} NO No mailbox selected\r\n", tag)];
        }

        let query = search::parse(args);
        if let Some(reason) = query.invalid_reason() {
            return vec![format!("{tag} BAD {reason}\r\n")];
        }
        if query.bad_charset().is_some() {
            return vec![format!(
                "{tag} NO [BADCHARSET ({})] charset not supported\r\n",
                search::SUPPORTED_CHARSETS.join(" ")
            )];
        }
        let ctx = match self.resolve_body_search(&query) {
            Ok(ctx) => ctx,
            Err(reason) => return vec![format!("{tag} NO {reason}\r\n")],
        };
        let labels = self.store.label_registry().await;

        let ids: Vec<u32> = self
            .mails
            .iter()
            .enumerate()
            .filter(|(i, cached)| {
                let view = Self::build_search_view(*i, cached, &labels);
                search::matches(&query, &view, &ctx)
            })
            .map(|(i, cached)| if uid_mode { cached.uid } else { (i + 1) as u32 })
            .collect();

        // `"SEARCH" *(SP nz-number)`: no trailing space when nothing matched.
        let id_str: String = ids.iter().map(|id| format!(" {id}")).collect();

        let cmd = if uid_mode { "UID SEARCH" } else { "SEARCH" };
        vec![
            format!("* SEARCH{}\r\n", id_str),
            format!("{} OK {} completed\r\n", tag, cmd),
        ]
    }

    /// Project a cached message onto the fields IMAP SEARCH compares. Derived
    /// strings (From / To / Cc / Bcc / headers) are owned by the [`MsgView`];
    /// the cheap ones (subject, body) borrow straight from `cached`.
    fn build_search_view<'a>(
        idx: usize,
        cached: &'a CachedMail,
        labels: &'a LabelRegistry,
    ) -> MsgView<'a> {
        let headers = cached
            .rfc2822
            .as_deref()
            .map(extract_headers)
            .unwrap_or_default();

        // To/Cc/Bcc come from details when the body is loaded; otherwise only
        // the envelope `firstRecipient` (rendered as To) is available.
        let (to, cc, bcc) = match cached.details.as_ref() {
            Some(d) => (
                join_addrs(&d.recipients.toRecipients),
                join_addrs(&d.recipients.ccRecipients),
                join_addrs(&d.recipients.bccRecipients),
            ),
            None => (
                cached
                    .mail
                    .firstRecipient
                    .as_ref()
                    .map(format_address)
                    .unwrap_or_default(),
                String::new(),
                String::new(),
            ),
        };

        let sent_ms = cached
            .details
            .as_ref()
            .map(|d| d.sentDate.as_millis())
            .unwrap_or_else(|| cached.mail.receivedDate.as_millis());

        let element_id = cached
            .mail
            ._id
            .as_ref()
            .map(|id| id.element_id.0.as_str())
            .unwrap_or("");

        MsgView {
            seq: (idx + 1) as u32,
            uid: cached.uid,
            element_id,
            subject: &cached.mail.subject,
            from: format_address(&cached.mail.sender),
            to,
            cc,
            bcc,
            headers,
            date_ms: cached.mail.receivedDate.as_millis(),
            sent_ms,
            unread: cached.mail.unread,
            deleted: cached.deleted,
            size: cached.rfc2822.as_ref().map(|r| r.len() as u64).unwrap_or(0),
            // Same resolution as FETCH FLAGS: only label ids are in the
            // registry, so the folder entry of `Mail.sets` drops out.
            keywords: cached
                .mail
                .sets
                .iter()
                .filter_map(|set| labels.keyword_for_label(set.element_id.0.as_str()))
                .collect(),
        }
    }

    /// Resolve the `BODY`/`TEXT` terms against the full-text index, once per
    /// distinct term. An index failure, or a term with no alphanumeric
    /// character (`char::is_alphanumeric`), is an error: "no hits" would be an
    /// empty success that is not true. The index's tokenizer drops a few more
    /// characters than that test (some combining marks, superscripts), so a
    /// term made only of those still answers empty. With no local store (unit
    /// tests) body terms match nothing.
    fn resolve_body_search(
        &self,
        query: &search::SearchKey,
    ) -> Result<search::SearchContext, String> {
        let mut ctx = search::SearchContext::empty();
        ctx.max_seq = self.mails.len() as u32;
        ctx.max_uid = self.mails.iter().map(|m| m.uid).max().unwrap_or(0);
        let Some(local_store) = &self.local_store else {
            return Ok(ctx);
        };
        for term in search::collect_body_terms(query) {
            if term.is_empty() {
                continue; // matches every message; see `body_matches`
            }
            if crate::store::fts_match_expr(&term).is_empty() {
                return Err(format!(
                    "[CANNOT] body search needs letters or digits, not \"{}\"",
                    term.escape_default()
                ));
            }
            match local_store.search_body(&term) {
                Ok(ids) => {
                    ctx.body_hits.insert(term, ids.into_iter().collect());
                }
                Err(e) => {
                    log::warn!("FTS body search failed for {term:?}: {e}");
                    return Err("[UNAVAILABLE] body search failed (see the bridge log)".to_owned());
                }
            }
        }
        Ok(ctx)
    }

    async fn cmd_store(&mut self, tag: &str, args: &str, uid_mode: bool) -> Vec<String> {
        if self.state != State::Selected {
            return vec![format!("{} NO No mailbox selected\r\n", tag)];
        }
        let cmd = if uid_mode { "UID STORE" } else { "STORE" };

        let Some(store_args) = parse_store_args(args) else {
            return vec![format!("{} BAD Invalid STORE arguments\r\n", tag)];
        };
        let Some(indices) = self.resolve_sequence_set(&store_args.seq_set, uid_mode) else {
            return vec![format!("{tag} BAD invalid sequence set\r\n")];
        };
        let mut labels = self.store.label_registry().await;

        // Bucket the flag list: the system flags Tuta can express, keywords
        // that map to labels, and unknown keywords. \Answered / \Flagged /
        // \Draft have no Tuta backing — accepted and dropped, as before.
        let mut wants_seen = false;
        let mut wants_deleted = false;
        let mut requested: Vec<LabelInfo> = Vec::new();
        let mut unknown: Vec<String> = Vec::new();
        for flag in &store_args.flags {
            if flag.eq_ignore_ascii_case("\\Seen") {
                wants_seen = true;
            } else if flag.eq_ignore_ascii_case("\\Deleted") {
                wants_deleted = true;
            } else if flag.starts_with('\\') {
                // System flag without Tuta backing.
            } else if let Some(info) = labels.label_for_keyword(flag) {
                requested.push(info.clone());
            } else {
                unknown.push(flag.clone());
            }
        }

        // Unknown keywords create labels (we advertise `\*`) — but only when
        // the STORE would add them; removing a keyword no label backs is a
        // no-op. Only keywords the sanitizer maps back onto themselves are
        // eligible: for any other name the created label's atom would differ
        // from what the client stored, leaving a keyword that never matches.
        if store_args.op != StoreOp::Remove && !unknown.is_empty() {
            let mut created = false;
            for kw in &unknown {
                if crate::labels::sanitize_keyword(kw) != *kw {
                    log::warn!(
                        "STORE: not creating a label for keyword {kw:?} — \
                         its atom would not round-trip"
                    );
                    continue;
                }
                match self
                    .backend
                    .create_label(kw, crate::labels::DEFAULT_LABEL_COLOR)
                    .await
                {
                    Ok(fresh) => {
                        log::info!("STORE: created Tuta label {kw:?} for new keyword");
                        self.store.set_labels(fresh).await;
                        created = true;
                    }
                    Err(e) => log::warn!("STORE: creating label {kw:?} failed: {e}"),
                }
            }
            if created {
                // Re-resolve against the refreshed registry so the new
                // labels join this STORE's apply pass.
                labels = self.store.label_registry().await;
                for kw in &unknown {
                    if let Some(info) = labels.label_for_keyword(kw) {
                        requested.push(info.clone());
                    }
                }
            }
        } else if !unknown.is_empty() {
            log::warn!("STORE: ignoring unknown keyword(s) {unknown:?} in -FLAGS");
        }

        // \Seen. Replace mode (bare FLAGS) derives the state from the
        // flag's presence in the list, per RFC 3501 §6.4.6.
        if wants_seen || store_args.op == StoreOp::Replace {
            let unread = match store_args.op {
                StoreOp::Add => false,
                StoreOp::Remove => true,
                StoreOp::Replace => !wants_seen,
            };
            for &idx in &indices {
                if let Some(m) = self.mails.get_mut(idx) {
                    m.mail.unread = unread;
                }
            }
            let mail_ids: Vec<_> = indices
                .iter()
                .filter_map(|&i| self.mails.get(i))
                .filter_map(|m| m.mail._id.clone())
                .collect();
            if !mail_ids.is_empty() {
                if let Err(e) = self.backend.set_unread_status(mail_ids, unread).await {
                    log::warn!("Failed to update read status on server: {}", e);
                }
            }
        }

        // \Deleted — session-local until EXPUNGE, as before.
        if wants_deleted || store_args.op == StoreOp::Replace {
            let deleted = match store_args.op {
                StoreOp::Add => true,
                StoreOp::Remove => false,
                StoreOp::Replace => wants_deleted,
            };
            for &idx in &indices {
                if let Some(m) = self.mails.get_mut(idx) {
                    m.deleted = deleted;
                }
            }
        }

        // Label keywords → ApplyLabelService.
        match store_args.op {
            StoreOp::Add | StoreOp::Remove => {
                if !requested.is_empty() {
                    let tuples: Vec<_> = requested.iter().map(|l| l.id_tuple()).collect();
                    let (added, removed) = if store_args.op == StoreOp::Add {
                        (tuples, Vec::new())
                    } else {
                        (Vec::new(), tuples)
                    };
                    let mail_ids: Vec<_> = indices
                        .iter()
                        .filter_map(|&i| self.mails.get(i))
                        .filter_map(|m| m.mail._id.clone())
                        .collect();
                    if !mail_ids.is_empty() {
                        self.apply_labels_optimistically(&indices, mail_ids, added, removed)
                            .await;
                    }
                }
            }
            StoreOp::Replace => {
                // Replace-mode diffs start from each mail's own label set,
                // so this is one service call per mail — acceptable for a
                // client path that mainstream clients don't use for tags.
                for &idx in &indices {
                    let Some(m) = self.mails.get(idx) else {
                        continue;
                    };
                    let Some(id) = m.mail._id.clone() else {
                        continue;
                    };
                    let current: Vec<_> = m
                        .mail
                        .sets
                        .iter()
                        .filter(|s| labels.keyword_for_label(s.element_id.0.as_str()).is_some())
                        .cloned()
                        .collect();
                    let added: Vec<_> = requested
                        .iter()
                        .filter(|l| !current.iter().any(|c| c.element_id.0 == l.id))
                        .map(|l| l.id_tuple())
                        .collect();
                    let removed: Vec<_> = current
                        .into_iter()
                        .filter(|c| !requested.iter().any(|l| l.id == c.element_id.0))
                        .collect();
                    if added.is_empty() && removed.is_empty() {
                        continue;
                    }
                    self.apply_labels_optimistically(&[idx], vec![id], added, removed)
                        .await;
                }
            }
        }

        // RFC 3501 §6.4.6: answer with the new flags as untagged FETCH
        // responses unless the client asked for .SILENT.
        let mut responses = Vec::new();
        if !store_args.silent {
            for &idx in &indices {
                if let Some(m) = self.mails.get(idx) {
                    responses.push(build_fetch_response(
                        idx + 1,
                        m,
                        "(FLAGS)",
                        uid_mode,
                        &labels,
                    ));
                }
            }
        }
        responses.push(format!("{} OK {} completed\r\n", tag, cmd));
        responses
    }

    /// Send one label diff to the server and, on success, mirror it into the
    /// session view and the shared store — FETCHes reflect the change
    /// immediately, the event bus delivers the authoritative state later.
    async fn apply_labels_optimistically(
        &mut self,
        indices: &[usize],
        mail_ids: Vec<tutasdk::IdTupleGenerated>,
        added: Vec<tutasdk::IdTupleGenerated>,
        removed: Vec<tutasdk::IdTupleGenerated>,
    ) {
        if let Err(e) = self
            .backend
            .apply_labels(mail_ids, added.clone(), removed.clone())
            .await
        {
            log::warn!("Failed to apply labels on server: {e}");
            return;
        }
        let mut refreshed = Vec::with_capacity(indices.len());
        for &idx in indices {
            if let Some(m) = self.mails.get_mut(idx) {
                apply_label_sets(&mut m.mail.sets, &added, &removed);
                refreshed.push(m.mail.clone());
            }
        }
        for mail in &refreshed {
            self.store.refresh_mail_in_place(mail).await;
        }
    }

    async fn cmd_uid(&mut self, tag: &str, args: &str) -> Vec<String> {
        if self.state != State::Selected {
            return vec![format!("{} NO No mailbox selected\r\n", tag)];
        }

        let parts: Vec<&str> = args.splitn(2, ' ').collect();
        let subcmd = parts.first().map(|s| s.to_uppercase()).unwrap_or_default();
        let subargs = parts.get(1).unwrap_or(&"");

        match subcmd.as_str() {
            "FETCH" => self.cmd_fetch(tag, subargs, true).await,
            "SEARCH" => self.cmd_search(tag, subargs, true).await,
            "STORE" => self.cmd_store(tag, subargs, true).await,
            "MOVE" => self.cmd_move(tag, subargs, true).await,
            "COPY" => self.cmd_copy(tag),
            _ => vec![format!("{} BAD Unknown UID subcommand\r\n", tag)],
        }
    }

    fn cmd_close(&mut self, tag: &str) -> Vec<String> {
        self.state = State::Authenticated;
        self.selected_folder = None;
        self.mails.clear();
        vec![format!("{} OK CLOSE completed\r\n", tag)]
    }

    async fn cmd_expunge(&mut self, tag: &str) -> Vec<String> {
        if self.state != State::Selected {
            return vec![format!("{} NO No mailbox selected\r\n", tag)];
        }

        let deleted_ids: Vec<_> = self
            .mails
            .iter()
            .filter(|m| m.deleted)
            .filter_map(|m| m.mail._id.clone())
            .collect();

        if !deleted_ids.is_empty() {
            if let Err(e) = self.backend.trash_mails(deleted_ids).await {
                log::warn!("Failed to trash mails: {}", e);
            }
        }

        let mut responses = Vec::new();
        let mut seq = 1u32;
        let mut i = 0;
        while i < self.mails.len() {
            if self.mails[i].deleted {
                responses.push(format!("* {} EXPUNGE\r\n", seq));
                self.mails.remove(i);
            } else {
                seq += 1;
                i += 1;
            }
        }

        responses.push(format!("{} OK EXPUNGE completed\r\n", tag));
        responses
    }

    /// MOVE / UID MOVE (RFC 6851): move messages to another mailbox. Tuta
    /// folders are exclusive, so this maps directly to a server-side move; the
    /// messages are then expunged from the source view.
    async fn cmd_move(&mut self, tag: &str, args: &str, uid_mode: bool) -> Vec<String> {
        let label = if uid_mode { "UID MOVE" } else { "MOVE" };
        if self.state != State::Selected {
            return vec![format!("{} NO No mailbox selected\r\n", tag)];
        }

        let (seq_set, rest) = args.trim().split_once(' ').unwrap_or((args.trim(), ""));
        let (raw_name, _) = parse_imap_token(rest.trim());
        let folder_name = super::utf7::decode(&raw_name).unwrap_or_else(|| raw_name.clone());
        let target = match self.store.folder_by_imap_path(&folder_name).await {
            Some(f) => f,
            None => return vec![format!("{} NO [TRYCREATE] Mailbox does not exist\r\n", tag)],
        };

        let Some(indices) = self.resolve_sequence_set(seq_set, uid_mode) else {
            return vec![format!("{tag} BAD invalid sequence set\r\n")];
        };
        let mail_ids: Vec<_> = indices
            .iter()
            .filter_map(|&i| self.mails.get(i))
            .filter_map(|m| m.mail._id.clone())
            .collect::<Vec<_>>();

        if mail_ids.is_empty() {
            return vec![format!("{} OK {} completed\r\n", tag, label)];
        }

        let moved: std::collections::HashSet<String> = mail_ids
            .iter()
            .map(|id| id.element_id.to_string())
            .collect();

        if let Err(e) = self.backend.move_mails(mail_ids, &target).await {
            log::warn!("{} to {} failed: {}", label, folder_name, e);
            return vec![format!("{} NO {} failed\r\n", tag, label)];
        }

        // Expunge the moved messages from the source view (RFC 6851).
        let mut responses = Vec::new();
        let mut seq = 1u32;
        let mut i = 0;
        while i < self.mails.len() {
            let is_moved = self.mails[i]
                .mail
                ._id
                .as_ref()
                .map(|id| moved.contains(&id.element_id.to_string()))
                .unwrap_or(false);
            if is_moved {
                responses.push(format!("* {} EXPUNGE\r\n", seq));
                self.mails.remove(i);
            } else {
                seq += 1;
                i += 1;
            }
        }
        responses.push(format!("{} OK {} completed\r\n", tag, label));
        responses
    }

    /// COPY is not supported: Tuta folders are exclusive (no duplication).
    /// Clients should use MOVE, which we advertise.
    fn cmd_copy(&self, tag: &str) -> Vec<String> {
        vec![format!(
            "{} NO [CANNOT] COPY is not supported; use MOVE\r\n",
            tag
        )]
    }

    async fn refresh_mails(&mut self, folder_id: &str) -> Result<(), String> {
        let stored = self.store.get_folder(folder_id).await;

        // Carry over already-loaded details/rfc for this session.
        let old_cache: std::collections::HashMap<String, (Option<MailDetails>, Option<String>)> =
            self.mails
                .iter()
                .filter_map(|m| {
                    let eid = m.mail._id.as_ref()?.element_id.to_string();
                    Some((eid, (m.details.clone(), m.rfc2822.clone())))
                })
                .collect();

        self.mails.clear();
        // UIDs are stable and assigned by the store; sort ascending so message
        // sequence order matches UID order, as IMAP clients expect.
        let mut stored = stored;
        stored.sort_by_key(|m| m.uid);

        for sm in stored {
            let elem_id = sm.mail._id.as_ref().map(|id| id.element_id.to_string());
            let (old_details, old_rfc) = elem_id
                .as_ref()
                .and_then(|eid| old_cache.get(eid))
                .cloned()
                .unwrap_or((None, None));

            let uid = sm.uid;
            if uid >= self.uid_next {
                self.uid_next = uid + 1;
            }

            let details = sm.details.or(old_details);
            // The body is final if we have real details, or a previously
            // rendered rfc2822 (from the store or this session) — those always
            // carry a real body. With none of those, the rfc2822 we render
            // below has a placeholder body, so the body still needs an
            // on-demand fetch the first time a client opens the message.
            let body_loaded = details.is_some() || sm.rfc2822.is_some() || old_rfc.is_some();
            let rfc2822 = sm
                .rfc2822
                .or(old_rfc)
                .unwrap_or_else(|| mail_to_rfc2822(&sm.mail, details.as_ref(), &[]));

            self.mails.push(CachedMail {
                mail: sm.mail,
                details,
                rfc2822: Some(rfc2822),
                body_loaded,
                uid,
                deleted: false,
            });
        }

        debug!(
            "Refreshed {} mails for {} from store",
            self.mails.len(),
            folder_id
        );
        Ok(())
    }

    /// Indices of the messages a sequence set (or UID set) names, or `None`
    /// when it is not RFC 3501 grammar. Membership is tested per message, so
    /// `1:4294967295` costs one pass over the mailbox, not four billion.
    fn resolve_sequence_set(&self, seq_set: &str, uid_mode: bool) -> Option<Vec<usize>> {
        let set = search::parse_seqset(seq_set.trim())?;
        let max = if uid_mode {
            self.mails.iter().map(|m| m.uid).max().unwrap_or(0)
        } else {
            self.mails.len() as u32
        };
        Some(
            self.mails
                .iter()
                .enumerate()
                .filter(|(i, m)| {
                    let number = if uid_mode { m.uid } else { (*i + 1) as u32 };
                    set.contains(number, max)
                })
                .map(|(i, _)| i)
                .collect(),
        )
    }
}

/// Join a recipient list into a single comparable string for SEARCH.
fn join_addrs(addrs: &[MailAddress]) -> String {
    addrs
        .iter()
        .map(format_address)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The untagged FLAGS advertisement: the fixed system flags plus one keyword
/// per Tuta label. One helper so SELECT and (later) STORE's untagged FETCH
/// responses can never drift apart.
fn flags_advertisement(labels: &LabelRegistry) -> String {
    let mut flags = vec!["\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft"];
    flags.extend(labels.keywords());
    format!("* FLAGS ({})\r\n", flags.join(" "))
}

/// PERMANENTFLAGS: what a client may STORE persistently. Label keywords are
/// writable (STORE routes them to `ApplyLabelService`), and `\*` tells
/// clients they may invent new keywords — STORE creates the backing label.
fn permanent_flags_advertisement(labels: &LabelRegistry) -> String {
    let mut flags = vec!["\\Seen", "\\Flagged"];
    flags.extend(labels.keywords());
    flags.push("\\*");
    format!("* OK [PERMANENTFLAGS ({})] Limited\r\n", flags.join(" "))
}

fn build_fetch_response(
    seq: usize,
    cached: &CachedMail,
    items: &str,
    uid_mode: bool,
    labels: &LabelRegistry,
) -> String {
    let items_upper = items.to_uppercase();
    let mut parts = Vec::new();

    if uid_mode || items_upper.contains("UID") {
        parts.push(format!("UID {}", cached.uid));
    }

    if items_upper.contains("FLAGS") {
        let mut flags = Vec::new();
        if !cached.mail.unread {
            flags.push("\\Seen");
        }
        if cached.deleted {
            flags.push("\\Deleted");
        }
        // `Mail.sets` lists every MailSet the mail belongs to — its folder
        // and its labels. Only label ids resolve in the registry; the folder
        // id is skipped by the lookup.
        for set in &cached.mail.sets {
            if let Some(keyword) = labels.keyword_for_label(set.element_id.0.as_str()) {
                flags.push(keyword);
            }
        }
        parts.push(format!("FLAGS ({})", flags.join(" ")));
    }

    if items_upper.contains("INTERNALDATE") {
        let date = format_internal_date(cached.mail.receivedDate.as_millis());
        parts.push(format!("INTERNALDATE \"{}\"", date));
    }

    if items_upper.contains("RFC822.SIZE") {
        let size = cached.rfc2822.as_ref().map(|r| r.len()).unwrap_or(0);
        parts.push(format!("RFC822.SIZE {}", size));
    }

    if items_upper.contains("ENVELOPE") {
        parts.push(format!("ENVELOPE {}", build_envelope(cached)));
    }

    if items_upper.contains("BODYSTRUCTURE") {
        let bs = cached
            .rfc2822
            .as_ref()
            .map(|r| crate::mail::compute_bodystructure(r))
            .unwrap_or_else(|| {
                "(\"TEXT\" \"HTML\" (\"CHARSET\" \"UTF-8\") NIL NIL \"BASE64\" 0 0)".to_owned()
            });
        parts.push(format!("BODYSTRUCTURE {}", bs));
    }

    if items_upper.contains("BODY[]") || items_upper.contains("BODY.PEEK[]") {
        if let Some(ref rfc) = cached.rfc2822 {
            parts.push(format!("BODY[] {{{}}}\r\n{}", rfc.len(), rfc));
        }
    } else if let Some((section, fields, negate)) = parse_header_fields_section(items) {
        if let Some(ref rfc) = cached.rfc2822 {
            let headers = filter_header_fields(rfc, &fields, negate);
            parts.push(format!(
                "BODY[{}] {{{}}}\r\n{}",
                section,
                headers.len(),
                headers
            ));
        }
    } else if items_upper.contains("HEADER") {
        // Bare BODY[HEADER] / BODY.PEEK[HEADER] / RFC822.HEADER.
        if let Some(ref rfc) = cached.rfc2822 {
            let headers = extract_headers(rfc);
            let item = if items_upper.contains("RFC822.HEADER") {
                "RFC822.HEADER"
            } else {
                "BODY[HEADER]"
            };
            parts.push(format!("{} {{{}}}\r\n{}", item, headers.len(), headers));
        }
    }

    let has_rfc822_full = items_upper
        .split_whitespace()
        .any(|t| t.trim_matches(|c| c == '(' || c == ')') == "RFC822");
    if has_rfc822_full {
        if let Some(ref rfc) = cached.rfc2822 {
            parts.push(format!("RFC822 {{{}}}\r\n{}", rfc.len(), rfc));
        }
    }

    format!("* {} FETCH ({})\r\n", seq, parts.join(" "))
}

/// Parse `HEADER.FIELDS (...)` / `HEADER.FIELDS.NOT (...)` out of a FETCH item
/// list. Returns the section echoed as the client sent it, the field names
/// uppercased for matching, and whether the match is negated.
///
/// Clients match FETCH data items to their pending request by the literal
/// section string (RFC 3501 §7.4.2), so the response must echo the requested
/// field list — answering with a rewritten list makes strict clients (Apple
/// Mail) drop the data on the floor.
fn parse_header_fields_section(items: &str) -> Option<(String, Vec<String>, bool)> {
    let upper = items.to_uppercase();
    let start = upper.find("HEADER.FIELDS")?;
    let negate = upper[start..].starts_with("HEADER.FIELDS.NOT");
    let open = start + upper[start..].find('(')?;
    let close = open + upper[open..].find(')')?;
    let keyword = if negate {
        "HEADER.FIELDS.NOT"
    } else {
        "HEADER.FIELDS"
    };
    let section = format!("{} {}", keyword, &items[open..=close]);
    let fields = upper[open + 1..close]
        .split_whitespace()
        .map(|f| f.trim_matches('"').to_string())
        .collect();
    Some((section, fields, negate))
}

/// Header lines matching (or, when negated, not matching) `fields` — with
/// continuation lines kept attached to their header — terminated by the blank
/// line that delimits a HEADER.FIELDS section.
fn filter_header_fields(rfc: &str, fields: &[String], negate: bool) -> String {
    let header_len = rfc.find("\r\n\r\n").map(|p| p + 2).unwrap_or(rfc.len());
    let mut out = String::new();
    let mut keep = false;
    for line in rfc[..header_len].split_inclusive("\r\n") {
        if !line.starts_with(' ') && !line.starts_with('\t') {
            let name = line.split(':').next().unwrap_or("").trim().to_uppercase();
            keep = fields.iter().any(|f| *f == name) != negate;
        }
        if keep {
            out.push_str(line);
        }
    }
    out.push_str("\r\n");
    out
}

fn build_envelope(cached: &CachedMail) -> String {
    let mail = &cached.mail;
    let date = format_internal_date(mail.receivedDate.as_millis());
    let subject = imap_string(&mail.subject);

    let from = format_envelope_addr(&mail.sender);
    let to = cached
        .details
        .as_ref()
        .map(|d| {
            d.recipients
                .toRecipients
                .iter()
                .map(format_envelope_addr)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .or_else(|| mail.firstRecipient.as_ref().map(format_envelope_addr))
        .unwrap_or_else(|| "NIL".to_string());

    let msg_id = mail
        ._id
        .as_ref()
        .map(|id| format!("<{}.{}@tutabridge.local>", id.list_id, id.element_id))
        .unwrap_or_default();
    let msg_id = imap_string(&msg_id);

    format!("(\"{date}\" {subject} ({from}) ({from}) ({from}) ({to}) NIL NIL NIL {msg_id})")
}

/// Encode a string as an IMAP nstring. Safe 7-bit text becomes a quoted string;
/// a value holding CR, LF, or 8-bit bytes becomes a server-side literal
/// ({N}CRLF<octets>), since a quoted string may not contain any of those. An
/// empty value becomes "". Without this, a mail subject or sender name with an
/// embedded newline produces a malformed FETCH response and the client cannot
/// parse the message list (an empty mailbox in Thunderbird).
fn imap_string(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".to_string();
    }
    if s.bytes().any(|b| b == b'\r' || b == b'\n' || b >= 0x80) {
        format!("{{{}}}\r\n{}", s.len(), s)
    } else {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn format_envelope_addr(addr: &tutasdk::entities::generated::tutanota::MailAddress) -> String {
    let (user, domain) = addr.address.split_once('@').unwrap_or((&addr.address, ""));
    let name = if addr.name.is_empty() {
        "NIL".to_string()
    } else {
        imap_string(&addr.name)
    };
    format!(
        "({} NIL {} {})",
        name,
        imap_string(user),
        imap_string(domain)
    )
}

/// The sequence set is the first word; a set never holds a space or a `(`,
/// while a single unparenthesised item can (`BODY.PEEK[HEADER.FIELDS (FROM)]`).
fn parse_fetch_args(args: &str) -> (String, String) {
    let args = args.trim();
    match args.split_once(|c: char| c == ' ' || c == '(') {
        Some((seq, _)) => (seq.to_string(), args[seq.len()..].trim().to_string()),
        None => (args.to_string(), String::new()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum StoreOp {
    Add,
    Remove,
    Replace,
}

#[derive(Debug)]
struct StoreArgs {
    seq_set: String,
    op: StoreOp,
    silent: bool,
    flags: Vec<String>,
}

/// Parse STORE arguments: `<sequence set> <±FLAGS[.SILENT]> (flag ...)`.
/// The parentheses around the flag list are optional per RFC 3501. `None`
/// when the data item is not a FLAGS variant.
fn parse_store_args(args: &str) -> Option<StoreArgs> {
    let mut parts = args.trim().splitn(3, char::is_whitespace);
    let seq_set = parts.next()?.to_string();
    let (op, silent) = match parts.next()?.to_uppercase().as_str() {
        "FLAGS" => (StoreOp::Replace, false),
        "FLAGS.SILENT" => (StoreOp::Replace, true),
        "+FLAGS" => (StoreOp::Add, false),
        "+FLAGS.SILENT" => (StoreOp::Add, true),
        "-FLAGS" => (StoreOp::Remove, false),
        "-FLAGS.SILENT" => (StoreOp::Remove, true),
        _ => return None,
    };
    let flags = parts
        .next()
        .unwrap_or("")
        .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    Some(StoreArgs {
        seq_set,
        op,
        silent,
        flags,
    })
}

/// Optimistically apply a label diff to a mail's `sets` list. Idempotent —
/// re-applying the same diff leaves the list unchanged; the event bus
/// delivers the authoritative version later.
fn apply_label_sets(
    sets: &mut Vec<tutasdk::IdTupleGenerated>,
    added: &[tutasdk::IdTupleGenerated],
    removed: &[tutasdk::IdTupleGenerated],
) {
    sets.retain(|s| !removed.iter().any(|r| r.element_id.0 == s.element_id.0));
    for a in added {
        if !sets.iter().any(|s| s.element_id.0 == a.element_id.0) {
            sets.push(a.clone());
        }
    }
}

/// Whether a FETCH item list requires the real message body to be loaded.
///
/// Only full-body content does: `BODY[]` / `BODY.PEEK[]`, a numbered MIME part
/// (`BODY[1]`), `BODY[TEXT]`, or a standalone `RFC822` / `RFC822.TEXT`. Items the
/// bridge answers from metadata alone must NOT trigger an on-demand fetch:
/// `ENVELOPE`, `BODY[HEADER...]`, `BODYSTRUCTURE`, `RFC822.SIZE`, `FLAGS`, etc.
/// Treating header/envelope requests as body requests made the client's
/// list-building (one such fetch per message) download the entire mailbox.
/// Whether a FETCH item list requires the real message body to be loaded.
///
/// The bridge serves the full message for `BODY[]` / `BODY.PEEK[]` and a
/// standalone `RFC822`; only those need the body. Envelope, header, size and
/// structure items (`ENVELOPE`, `BODY[HEADER...]`, `RFC822.SIZE`,
/// `BODYSTRUCTURE`, `FLAGS`, ...) are answered from metadata and must NOT
/// trigger an on-demand fetch. Treating header/envelope requests as body
/// requests made the client's list-building (one such fetch per message)
/// download the entire mailbox.
/// An error message made safe to embed in an IMAP response line: a CR or LF
/// would end the line early and desynchronise the client.
fn single_line(text: &str) -> String {
    text.split(['\r', '\n'])
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn needs_body(items: &str) -> bool {
    let u = items.to_uppercase();
    if u.contains("BODY[]") || u.contains("BODY.PEEK[]") {
        return true;
    }
    // Standalone RFC822 (a full message), but not RFC822.SIZE / .HEADER / .TEXT.
    u.split(|c: char| c == '(' || c == ')' || c.is_whitespace())
        .any(|token| token == "RFC822")
}

fn parse_login_args(args: &str) -> (String, String) {
    let args = args.trim();
    let (user, rest) = parse_imap_token(args);
    let (pass, _) = parse_imap_token(rest.trim_start());
    (user, pass)
}

/// The option names of a trailing `RETURN (opt …)` (RFC 5258), or `None`
/// when the text is anything else.
fn return_options(text: &str) -> Option<Vec<&str>> {
    let keyword = text.get(..6)?;
    if !keyword.eq_ignore_ascii_case("RETURN") {
        return None;
    }
    let list = text[6..]
        .trim_start()
        .strip_prefix('(')?
        .strip_suffix(')')?;
    Some(list.split_whitespace().collect())
}

#[derive(Clone, Copy, PartialEq)]
enum ListKind {
    List,
    Lsub,
}

impl ListKind {
    fn name(self) -> &'static str {
        match self {
            ListKind::List => "LIST",
            ListKind::Lsub => "LSUB",
        }
    }
}

/// RFC 3501 LIST wildcards over `/`-delimited names. `INBOX` is matched in
/// any case, as the protocol treats that one name case-insensitively.
fn mailbox_matches(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    // `INBOX` is the one case-insensitive name: its first five characters
    // compare without case, wherever the pattern's wildcards put them.
    let inbox_prefix = name == "INBOX" || name.starts_with("INBOX/");
    let same = |pc: char, j: usize| {
        n[j] == pc || (inbox_prefix && j < 5 && n[j].eq_ignore_ascii_case(&pc))
    };
    // Dynamic programming, not backtracking: the pattern is client input,
    // and `*a*a*a…` would make naive recursion exponential.
    // reach[j]: the pattern prefix read so far can end at name[..j].
    let mut reach = vec![false; n.len() + 1];
    reach[0] = true;
    for &c in &p {
        let mut next = vec![false; n.len() + 1];
        match c {
            '*' | '%' => {
                for j in 0..=n.len() {
                    next[j] = reach[j] || (j > 0 && next[j - 1] && (c == '*' || n[j - 1] != '/'));
                }
            }
            _ => {
                for j in 1..=n.len() {
                    next[j] = reach[j - 1] && same(c, j - 1);
                }
            }
        }
        reach = next;
    }
    reach[n.len()]
}

fn parse_imap_token(s: &str) -> (String, &str) {
    if s.starts_with('"') {
        let mut result = String::new();
        let mut chars = s[1..].char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => {
                    if let Some((_, escaped)) = chars.next() {
                        result.push(escaped);
                    }
                }
                '"' => return (result, &s[i + 2..]),
                _ => result.push(c),
            }
        }
        (result, "")
    } else {
        let end = s.find(char::is_whitespace).unwrap_or(s.len());
        (
            s[..end].to_string(),
            if end < s.len() { &s[end..] } else { "" },
        )
    }
}

fn parse_command(line: &str) -> (String, String, String) {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    let tag = parts.first().unwrap_or(&"*").to_string();
    let cmd = parts.get(1).unwrap_or(&"").to_string();
    let args = parts.get(2).unwrap_or(&"").to_string();
    (tag, cmd, args)
}

/// A parsed `APPEND` command: the tag, the target mailbox, and the size of the
/// trailing `{N}` message literal the client is about to send.
pub(crate) struct AppendRequest {
    pub tag: String,
    pub mailbox: String,
    pub literal_size: usize,
}

/// Parse an `APPEND` command line. Returns `None` if it is not a well-formed
/// APPEND (so the caller falls back to normal command handling). The literal
/// reading itself happens at the socket level, since the session is line based.
pub(crate) fn parse_append(line: &str) -> Option<AppendRequest> {
    let (tag, cmd, args) = parse_command(line);
    if !cmd.eq_ignore_ascii_case("APPEND") {
        return None;
    }
    let mailbox = append_first_token(&args)?;
    let literal_size = append_literal_size(&args)?;
    Some(AppendRequest {
        tag,
        mailbox,
        literal_size,
    })
}

/// The first argument token of an APPEND (the mailbox), honoring quoting.
fn append_first_token(args: &str) -> Option<String> {
    let s = args.trim_start();
    if let Some(rest) = s.strip_prefix('"') {
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    } else {
        let end = s.find(char::is_whitespace).unwrap_or(s.len());
        (end > 0).then(|| s[..end].to_string())
    }
}

/// The size declared by the trailing `{N}` (or non-sync `{N+}`) literal.
fn append_literal_size(args: &str) -> Option<usize> {
    let open = args.rfind('{')?;
    let close = args[open..].find('}')? + open;
    args[open + 1..close]
        .trim_end_matches('+')
        .parse::<usize>()
        .ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn single_line_keeps_a_one_line_error_intact() {
        assert_eq!(
            super::single_line("ServerResponseError: Invalid Software Version"),
            "ServerResponseError: Invalid Software Version"
        );
    }

    #[test]
    fn single_line_cannot_end_the_response_early() {
        assert_eq!(
            super::single_line("first\r\n* BYE injected\nlast"),
            "first * BYE injected last"
        );
    }

    use super::*;
    use base64::Engine;
    use tutasdk::date::DateTime;
    use tutasdk::entities::generated::tutanota::MailAddress;
    use tutasdk::GeneratedId;
    use tutasdk::IdTupleGenerated;

    fn test_id(s: &str) -> GeneratedId {
        GeneratedId(s.to_string())
    }

    fn make_test_mail(uid: u32, subject: &str, unread: bool) -> CachedMail {
        CachedMail {
            mail: Mail {
                _id: Some(IdTupleGenerated::new(
                    test_id("mail_list"),
                    test_id("mail_elem"),
                )),
                _permissions: test_id("perm1"),
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
                conversationEntry: IdTupleGenerated::new(
                    test_id("conv_list"),
                    test_id("conv_elem"),
                ),
                firstRecipient: Some(MailAddress {
                    _id: None,
                    name: "Recip".to_string(),
                    address: "recip@test.com".to_string(),
                    contact: None,
                    _errors: Default::default(),
                }),
                mailDetails: None,
                mailDetailsDraft: None,
                bucketKey: None,
                sets: vec![],
                clientSpamClassifierResult: None,
                _errors: Default::default(),
            },
            details: None,
            rfc2822: Some("Date: Wed, 25 Dec 2024 12:30:45 +0000\r\nFrom: sender@tuta.com\r\nSubject: Test\r\n\r\nBody\r\n".to_string()),
            body_loaded: true,
            uid,
            deleted: false,
        }
    }

    // --- imap_string / ENVELOPE encoding ---

    #[test]
    fn imap_string_quotes_plain_ascii() {
        assert_eq!(imap_string("Hello world"), "\"Hello world\"");
    }

    #[test]
    fn imap_string_escapes_quote_and_backslash() {
        assert_eq!(imap_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn imap_string_empty_is_empty_quotes() {
        assert_eq!(imap_string(""), "\"\"");
    }

    #[test]
    fn imap_string_uses_literal_for_newline() {
        // A quoted string may not contain CR/LF, so it must become a literal.
        let s = "La\nselection";
        assert_eq!(imap_string(s), format!("{{{}}}\r\n{}", s.len(), s));
    }

    #[test]
    fn imap_string_uses_literal_for_8bit() {
        let s = "sélection"; // UTF-8 'é' is 8-bit
        assert_eq!(imap_string(s), format!("{{{}}}\r\n{}", s.len(), s));
    }

    #[test]
    fn build_envelope_newline_subject_uses_literal() {
        // Regression: a newline in the subject used to be emitted as a quoted
        // string, producing a malformed FETCH response that broke the client's
        // parse of the message list (an empty mailbox in Thunderbird).
        let subj = "La\nselection Courtois - Le bien du mois";
        let env = build_envelope(&make_test_mail(1, subj, false));
        assert!(
            env.contains(&format!("{{{}}}\r\n{}", subj.len(), subj)),
            "subject must be a literal, got: {env}"
        );
        assert!(
            !env.contains("\"La"),
            "subject must not be a quoted string holding the newline: {env}"
        );
    }

    // --- parse_command ---

    #[test]
    fn test_parse_command_full() {
        let (tag, cmd, args) = parse_command("A001 LOGIN user pass");
        assert_eq!(tag, "A001");
        assert_eq!(cmd, "LOGIN");
        assert_eq!(args, "user pass");
    }

    #[test]
    fn test_parse_command_no_args() {
        let (tag, cmd, args) = parse_command("A002 NOOP");
        assert_eq!(tag, "A002");
        assert_eq!(cmd, "NOOP");
        assert_eq!(args, "");
    }

    #[test]
    fn test_parse_command_tag_only() {
        let (tag, cmd, args) = parse_command("A003");
        assert_eq!(tag, "A003");
        assert_eq!(cmd, "");
        assert_eq!(args, "");
    }

    #[test]
    fn test_parse_command_empty() {
        let (tag, cmd, args) = parse_command("");
        assert_eq!(tag, "");
        assert_eq!(cmd, "");
        assert_eq!(args, "");
    }

    // --- parse_fetch_args ---

    #[test]
    fn test_parse_fetch_args_with_parens() {
        let (seq, items) = parse_fetch_args("1:* (FLAGS UID)");
        assert_eq!(seq, "1:*");
        assert_eq!(items, "(FLAGS UID)");
    }

    #[test]
    fn parse_fetch_args_single_item_with_brackets() {
        let (seq, items) = parse_fetch_args("1 BODY.PEEK[HEADER.FIELDS (FROM)]");
        assert_eq!(seq, "1");
        assert_eq!(items, "BODY.PEEK[HEADER.FIELDS (FROM)]");
        let (seq, items) = parse_fetch_args("1:*(FLAGS)");
        assert_eq!((seq.as_str(), items.as_str()), ("1:*", "(FLAGS)"));
    }

    #[test]
    fn test_parse_fetch_args_without_parens() {
        let (seq, items) = parse_fetch_args("1 FLAGS");
        assert_eq!(seq, "1");
        assert_eq!(items, "FLAGS");
    }

    #[test]
    fn test_parse_fetch_args_complex() {
        let (seq, items) = parse_fetch_args("1:5 (BODY.PEEK[HEADER.FIELDS (DATE FROM)])");
        assert_eq!(seq, "1:5");
        assert_eq!(items, "(BODY.PEEK[HEADER.FIELDS (DATE FROM)])");
    }

    // --- parse_store_args ---

    #[test]
    fn test_parse_store_args() {
        let a = parse_store_args("1:3 +FLAGS (\\Seen)").unwrap();
        assert_eq!(a.seq_set, "1:3");
        assert_eq!(a.op, StoreOp::Add);
        assert!(!a.silent);
        assert_eq!(a.flags, vec!["\\Seen"]);
    }

    // --- needs_body ---

    #[test]
    fn test_needs_body() {
        assert!(needs_body("(BODY[])"));
        assert!(needs_body("(BODY.PEEK[])"));
        assert!(needs_body("(RFC822)"));
        assert!(!needs_body("(ENVELOPE)"));
        assert!(needs_body("(FLAGS BODY[])"));
        assert!(!needs_body("(FLAGS)"));
        assert!(!needs_body("(FLAGS UID INTERNALDATE)"));
        assert!(!needs_body("(RFC822.SIZE)"));
        assert!(!needs_body("(BODYSTRUCTURE)"));
    }

    // --- build_fetch_response ---

    #[test]
    fn test_build_fetch_response_flags_only() {
        let cached = make_test_mail(1, "Test", false);
        let resp = build_fetch_response(1, &cached, "(FLAGS)", false, &LabelRegistry::default());
        assert_eq!(resp, "* 1 FETCH (FLAGS (\\Seen))\r\n");
    }

    #[test]
    fn test_build_fetch_response_flags_unread() {
        let cached = make_test_mail(1, "Test", true);
        let resp = build_fetch_response(1, &cached, "(FLAGS)", false, &LabelRegistry::default());
        assert_eq!(resp, "* 1 FETCH (FLAGS ())\r\n");
    }

    #[test]
    fn test_build_fetch_response_uid_mode() {
        let cached = make_test_mail(42, "Test", false);
        let resp = build_fetch_response(3, &cached, "(FLAGS)", true, &LabelRegistry::default());
        assert!(resp.contains("UID 42"));
        assert!(resp.contains("FLAGS (\\Seen)"));
    }

    #[test]
    fn test_build_fetch_response_internaldate() {
        let cached = make_test_mail(1, "Test", false);
        let resp = build_fetch_response(
            1,
            &cached,
            "(INTERNALDATE)",
            false,
            &LabelRegistry::default(),
        );
        assert!(resp.contains("INTERNALDATE \"25-Dec-2024 12:37:25 +0000\""));
    }

    #[test]
    fn test_build_fetch_response_rfc822_size() {
        let cached = make_test_mail(1, "Test", false);
        let resp = build_fetch_response(
            1,
            &cached,
            "(RFC822.SIZE)",
            false,
            &LabelRegistry::default(),
        );
        let rfc_len = cached.rfc2822.as_ref().unwrap().len();
        assert!(resp.contains(&format!("RFC822.SIZE {}", rfc_len)));
    }

    #[test]
    fn test_build_fetch_response_envelope() {
        let cached = make_test_mail(1, "Hello World", false);
        let resp = build_fetch_response(1, &cached, "(ENVELOPE)", false, &LabelRegistry::default());
        assert!(resp.contains("ENVELOPE"));
        assert!(resp.contains("Hello World"));
        assert!(resp.contains("\"sender\" \"tuta.com\""));
    }

    #[test]
    fn test_build_fetch_response_body_peek() {
        let cached = make_test_mail(1, "Test", false);
        let resp = build_fetch_response(
            1,
            &cached,
            "(BODY.PEEK[])",
            false,
            &LabelRegistry::default(),
        );
        assert!(resp.contains("BODY[] {"));
        assert!(resp.contains("From: sender@tuta.com"));
    }

    #[test]
    fn test_build_fetch_response_rfc822_full() {
        let cached = make_test_mail(1, "Test", false);
        let resp = build_fetch_response(1, &cached, "(RFC822)", false, &LabelRegistry::default());
        assert!(resp.contains("RFC822 {"));
        assert!(resp.contains("From: sender@tuta.com"));
    }

    // --- format_envelope_addr ---

    #[test]
    fn test_format_envelope_addr_with_name() {
        let addr = MailAddress {
            _id: None,
            name: "John Doe".to_string(),
            address: "john@example.com".to_string(),
            contact: None,
            _errors: Default::default(),
        };
        assert_eq!(
            format_envelope_addr(&addr),
            "(\"John Doe\" NIL \"john\" \"example.com\")"
        );
    }

    #[test]
    fn test_format_envelope_addr_no_name() {
        let addr = MailAddress {
            _id: None,
            name: "".to_string(),
            address: "john@example.com".to_string(),
            contact: None,
            _errors: Default::default(),
        };
        assert_eq!(
            format_envelope_addr(&addr),
            "(NIL NIL \"john\" \"example.com\")"
        );
    }

    #[test]
    fn test_format_envelope_addr_no_domain() {
        let addr = MailAddress {
            _id: None,
            name: "".to_string(),
            address: "localonly".to_string(),
            contact: None,
            _errors: Default::default(),
        };
        assert_eq!(format_envelope_addr(&addr), "(NIL NIL \"localonly\" \"\")");
    }

    #[test]
    fn test_format_envelope_addr_quotes_in_name() {
        let addr = MailAddress {
            _id: None,
            name: "John \"JD\" Doe".to_string(),
            address: "john@example.com".to_string(),
            contact: None,
            _errors: Default::default(),
        };
        let result = format_envelope_addr(&addr);
        // Inner quotes are backslash-escaped inside the IMAP quoted string.
        assert_eq!(
            result,
            "(\"John \\\"JD\\\" Doe\" NIL \"john\" \"example.com\")"
        );
    }

    // --- extract_headers (via rfc2822 module) ---

    #[test]
    fn test_extract_headers_from_rfc() {
        let rfc = "Date: Mon, 01 Jan 2024\r\nFrom: a@b.com\r\n\r\nBody content";
        let headers = extract_headers(rfc);
        assert_eq!(headers, "Date: Mon, 01 Jan 2024\r\nFrom: a@b.com\r\n\r\n");
    }

    // --- parse_command edge cases ---

    #[test]
    fn test_parse_command_with_extra_spaces() {
        let (tag, cmd, args) = parse_command("A1 FETCH 1:* (FLAGS UID)");
        assert_eq!(tag, "A1");
        assert_eq!(cmd, "FETCH");
        assert_eq!(args, "1:* (FLAGS UID)");
    }

    // --- build_fetch_response: combined items ---

    #[test]
    fn test_build_fetch_response_multiple_items() {
        let cached = make_test_mail(5, "Multi", true);
        let resp = build_fetch_response(
            3,
            &cached,
            "(FLAGS UID INTERNALDATE)",
            false,
            &LabelRegistry::default(),
        );
        assert!(resp.starts_with("* 3 FETCH ("));
        assert!(resp.contains("FLAGS ()"));
        assert!(resp.contains("UID 5"));
        assert!(resp.contains("INTERNALDATE"));
    }

    // --- needs_body: RFC822 not matching RFC822.HEADER etc ---

    #[test]
    fn test_needs_body_rfc822_variants() {
        assert!(needs_body("(RFC822)"));
        assert!(!needs_body("(RFC822.SIZE)"));
        assert!(!needs_body("(RFC822.HEADER)"));
        assert!(!needs_body("(RFC822.TEXT)"));
        assert!(needs_body("(RFC822.SIZE RFC822)"));
        assert!(needs_body("(FLAGS RFC822)"));
    }

    // --- parse_fetch_args: edge cases ---

    #[test]
    fn test_parse_fetch_args_star_range() {
        let (seq, items) = parse_fetch_args("1:* (FLAGS)");
        assert_eq!(seq, "1:*");
        assert_eq!(items, "(FLAGS)");
    }

    // --- build_envelope: subject with quotes ---

    #[test]
    fn test_build_envelope_subject_with_quotes() {
        let cached = make_test_mail(1, "Re: \"Important\" stuff", false);
        let resp = build_fetch_response(1, &cached, "(ENVELOPE)", false, &LabelRegistry::default());
        assert!(resp.contains("\\\"Important\\\""));
        assert!(!resp.contains("\"\"Important\"\""));
    }

    // --- HEADER.FIELDS: section echo and field filtering ---

    #[test]
    fn header_fields_response_echoes_requested_list_verbatim() {
        let cached = make_test_mail(1, "Test", false);
        // Apple Mail-style request: long list, lowercase, includes fields the
        // message doesn't have. The response section must echo this list.
        let resp = build_fetch_response(
            1,
            &cached,
            "(BODY.PEEK[HEADER.FIELDS (date subject from x-priority x-universally-unique-identifier)])",
            false,
            &LabelRegistry::default(),
        );
        assert!(
            resp.contains(
                "BODY[HEADER.FIELDS (date subject from x-priority x-universally-unique-identifier)]"
            ),
            "section must echo the client's field list: {resp}"
        );
        assert!(resp.contains("Subject: Test"));
        assert!(resp.contains("From: sender@tuta.com"));
    }

    #[test]
    fn header_fields_filters_to_requested_fields() {
        let rfc = "Date: Wed, 25 Dec 2024 12:30:45 +0000\r\nFrom: a@b.c\r\nX-Long: first\r\n\tcontinued\r\nSubject: Hi\r\n\r\nBody\r\n";
        let got = filter_header_fields(rfc, &["SUBJECT".into(), "X-LONG".into()], false);
        assert_eq!(got, "X-Long: first\r\n\tcontinued\r\nSubject: Hi\r\n\r\n");
        // Negated: everything except the listed fields.
        let not = filter_header_fields(rfc, &["X-LONG".into(), "DATE".into()], true);
        assert_eq!(not, "From: a@b.c\r\nSubject: Hi\r\n\r\n");
    }

    #[test]
    fn parse_header_fields_section_variants() {
        let (section, fields, negate) =
            parse_header_fields_section("(BODY.PEEK[HEADER.FIELDS (From To)])").unwrap();
        assert_eq!(section, "HEADER.FIELDS (From To)");
        assert_eq!(fields, vec!["FROM".to_string(), "TO".to_string()]);
        assert!(!negate);

        let (section, fields, negate) =
            parse_header_fields_section("(BODY[HEADER.FIELDS.NOT (received)])").unwrap();
        assert_eq!(section, "HEADER.FIELDS.NOT (received)");
        assert_eq!(fields, vec!["RECEIVED".to_string()]);
        assert!(negate);

        assert!(parse_header_fields_section("(FLAGS UID)").is_none());
    }

    #[test]
    fn bare_header_fetch_returns_all_headers() {
        let cached = make_test_mail(1, "Test", false);
        let resp = build_fetch_response(
            1,
            &cached,
            "(BODY.PEEK[HEADER])",
            false,
            &LabelRegistry::default(),
        );
        assert!(resp.contains("BODY[HEADER] {"), "got: {resp}");
        assert!(resp.contains("Subject: Test"));
        let resp = build_fetch_response(
            1,
            &cached,
            "(RFC822.HEADER)",
            false,
            &LabelRegistry::default(),
        );
        assert!(resp.contains("RFC822.HEADER {"), "got: {resp}");
    }

    // --- needs_body: only real body content triggers an on-demand fetch ---

    #[test]
    fn needs_body_skips_metadata_and_header_fetches() {
        // List-building items are answered from metadata, no fetch.
        assert!(!needs_body("(FLAGS UID)"));
        assert!(!needs_body("(ENVELOPE)"));
        assert!(!needs_body("(FLAGS UID RFC822.SIZE ENVELOPE)"));
        assert!(!needs_body(
            "(BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE)])"
        ));
        assert!(!needs_body("(UID RFC822.SIZE BODYSTRUCTURE FLAGS)"));
        assert!(!needs_body("(RFC822.HEADER)"));
        assert!(!needs_body("(BODY.PEEK[1.MIME])"));
    }

    #[test]
    fn needs_body_triggers_for_body_content() {
        assert!(needs_body("(BODY[])"));
        assert!(needs_body("(BODY.PEEK[])"));
        assert!(needs_body("(RFC822)"));
        assert!(needs_body("(FLAGS BODY.PEEK[])"));
        assert!(needs_body("BODY[]"));
    }

    // =================================================================
    // Integration tests with MockBackend
    // =================================================================

    use crate::mail::ParsedMessage;
    use crate::sync::MailStore;
    use crate::tuta::MailBackend;
    use std::sync::Mutex;
    use tutasdk::entities::generated::tutanota::{Body, Recipients};

    struct MockBackend {
        mails: Mutex<Vec<Mail>>,
        details: Mutex<std::collections::HashMap<String, MailDetails>>,
        trashed: Mutex<Vec<IdTupleGenerated>>,
        unread_calls: Mutex<Vec<(Vec<IdTupleGenerated>, bool)>>,
        sent: Mutex<Vec<ParsedMessage>>,
        moved: Mutex<Vec<(Vec<IdTupleGenerated>, String)>>,
        /// Recorded `apply_labels` calls: (mails, added, removed).
        #[allow(clippy::type_complexity)]
        labels_applied: Mutex<
            Vec<(
                Vec<IdTupleGenerated>,
                Vec<IdTupleGenerated>,
                Vec<IdTupleGenerated>,
            )>,
        >,
        /// Backend-side label list; `create_label` appends here.
        labels: Mutex<Vec<crate::labels::LabelInfo>>,
        fail_details: Mutex<bool>,
        fail_attachments: Mutex<bool>,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                mails: Mutex::new(Vec::new()),
                details: Mutex::new(std::collections::HashMap::new()),
                trashed: Mutex::new(Vec::new()),
                unread_calls: Mutex::new(Vec::new()),
                sent: Mutex::new(Vec::new()),
                moved: Mutex::new(Vec::new()),
                labels_applied: Mutex::new(Vec::new()),
                labels: Mutex::new(Vec::new()),
                fail_details: Mutex::new(false),
                fail_attachments: Mutex::new(false),
            }
        }

        fn set_fail_details(&self, v: bool) {
            *self.fail_details.lock().unwrap() = v;
        }

        fn with_mails(mails: Vec<Mail>) -> Self {
            let m = Self::new();
            *m.mails.lock().unwrap() = mails;
            m
        }

        fn add_details(&self, element_id: &str, details: MailDetails) {
            self.details
                .lock()
                .unwrap()
                .insert(element_id.to_string(), details);
        }
    }

    use crate::sync::StoredMail;
    use crate::tuta::FolderInfo;
    use tutasdk::folder_system::MailSetKind;

    fn inbox_folder() -> FolderInfo {
        FolderInfo {
            id: "inbox".to_string(),
            list_id: "folders".to_string(),
            entries_list_id: "inbox_entries".to_string(),
            kind: MailSetKind::Inbox,
            imap_path: "INBOX".to_string(),
            special_use: None,
        }
    }

    #[tokio::test]
    async fn select_and_status_serve_the_stored_uid_validity() {
        use crypto_primitives::aes::Aes256Key;
        use crypto_primitives::key::GenericAesKey;
        use crypto_primitives::randomizer_facade::RandomizerFacade;

        let tmp = std::env::temp_dir().join(format!("tutabridge_test_{}", rand::random::<u64>()));
        let key = GenericAesKey::Aes256(Aes256Key::generate(&RandomizerFacade::from_core(
            rand_core::OsRng,
        )));
        let local_store =
            Arc::new(LocalStore::open(&tmp.join("s.db"), &tmp.join("mails"), key).unwrap());
        let (validity, _) = local_store.folder_uid_state("inbox").unwrap();
        local_store.assign_folder_uids("inbox", &["e1"]).unwrap();

        let backend = Arc::new(MockBackend::with_mails(vec![make_mail("e1", "s", true)]));
        let store = MailStore::new();
        store.set_folder_list(vec![inbox_folder()]).await;
        let mut session = ImapSession::new(store, backend, None, Some(local_store));
        session.handle_command("a LOGIN u p").await;
        let resp = session.handle_command("b SELECT INBOX").await;
        assert!(
            resp.iter()
                .any(|r| r.contains(&format!("[UIDVALIDITY {validity}]"))),
            "{resp:?}"
        );
        let resp = session.handle_command("c STATUS INBOX (UIDVALIDITY)").await;
        assert!(
            resp[0].contains(&format!("UIDNEXT 2 UIDVALIDITY {validity})")),
            "{resp:?}"
        );
    }

    fn temp_local_store() -> Arc<LocalStore> {
        use crypto_primitives::aes::Aes256Key;
        use crypto_primitives::key::GenericAesKey;
        use crypto_primitives::randomizer_facade::RandomizerFacade;

        let tmp = std::env::temp_dir().join(format!("tutabridge_test_{}", rand::random::<u64>()));
        let key = GenericAesKey::Aes256(Aes256Key::generate(&RandomizerFacade::from_core(
            rand_core::OsRng,
        )));
        Arc::new(LocalStore::open(&tmp.join("s.db"), &tmp.join("mails"), key).unwrap())
    }

    #[tokio::test]
    async fn a_failed_uid_assignment_leaves_the_folder_as_it_was() {
        let local_store = temp_local_store();
        let mails = vec![make_mail("e1", "s", true), make_mail("e2", "s", true)];
        let backend = Arc::new(MockBackend::with_mails(mails.clone()));
        let store = MailStore::new();
        populate_store(&store, &mails[..1]).await;

        // A transaction someone else holds open makes the assignment's
        // BEGIN fail.
        local_store.exec_for_test("BEGIN");
        let result =
            crate::sync::sync_folder(&store, &local_store, &*backend, &inbox_folder()).await;
        local_store.exec_for_test("ROLLBACK");

        assert!(result.is_err());
        let held = store.get_folder("inbox").await;
        assert_eq!(held.len(), 1, "the folder must not be emptied");
        assert_eq!(held[0].uid, 1);
    }

    #[tokio::test]
    async fn select_and_status_answer_no_when_the_uid_state_is_unreadable() {
        let local_store = temp_local_store();
        local_store.exec_for_test("DROP TABLE sync_state");
        let backend = Arc::new(MockBackend::with_mails(vec![]));
        let store = MailStore::new();
        store.set_folder_list(vec![inbox_folder()]).await;
        let mut session = ImapSession::new(store, backend, None, Some(local_store));
        session.handle_command("a LOGIN u p").await;

        let resp = session.handle_command("b SELECT INBOX").await;
        assert!(resp[0].starts_with("b NO [UNAVAILABLE]"), "{resp:?}");
        let resp = session.handle_command("c FETCH 1 (FLAGS)").await;
        assert!(
            resp[0].starts_with("c NO"),
            "SELECT failed, so nothing is selected: {resp:?}"
        );
        let resp = session.handle_command("d STATUS INBOX (UIDVALIDITY)").await;
        assert!(resp[0].starts_with("d NO [UNAVAILABLE]"), "{resp:?}");
    }

    #[tokio::test]
    async fn events_wait_for_the_syncer_bootstrap() {
        use tutasdk::event_bus::{
            EntityUpdateBatch, EntityUpdateEvent, EventBusMessage, Operation,
        };

        let local_store = temp_local_store();
        let mails = vec![make_mail("m1", "s", true)];
        let backend = Arc::new(MockBackend::with_mails(mails.clone()));
        let store = MailStore::new();
        populate_store(&store, &mails).await;

        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (bootstrap_done, bootstrap_rx) = crate::sync::BootstrapDone::channel();
        let bus_ids = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let handler = tokio::spawn(crate::event_handler::run_event_handler(
            store.clone(),
            local_store.clone(),
            backend,
            bus_ids.clone(),
            rx,
            shutdown_rx,
            bootstrap_rx,
        ));
        let delete_m1 = EventBusMessage::EntityUpdate(EntityUpdateBatch {
            batch_id: "b1".to_string(),
            group_id: "g".to_string(),
            updates: vec![EntityUpdateEvent {
                application: "tutanota".to_string(),
                type_id: 97, // Mail
                instance_list_id: "L".to_string(),
                instance_id: "m1".to_string(),
                operation: Operation::Delete,
                instance: None,
                blob_instance: None,
            }],
        });
        tx.send(delete_m1).await.unwrap();
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            store.get_folder("inbox").await.len(),
            1,
            "applied before bootstrap"
        );
        // Held, yet a reconnect resumes after it; only the persisted id waits.
        assert_eq!(
            bus_ids.lock().unwrap().get("g").map(String::as_str),
            Some("b1")
        );
        assert!(local_store.load_event_bus_state().unwrap().is_empty());

        drop(bootstrap_done);
        for _ in 0..200 {
            if store.get_folder("inbox").await.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            store.get_folder("inbox").await.is_empty(),
            "held event never applied"
        );
        drop(tx);
        handler.await.unwrap();
    }

    #[tokio::test]
    async fn events_stop_waiting_once_too_many_are_held() {
        use tutasdk::event_bus::{
            EntityUpdateBatch, EntityUpdateEvent, EventBusMessage, Operation,
        };

        let mails = vec![make_mail("m1", "s", true)];
        let backend = Arc::new(MockBackend::with_mails(mails.clone()));
        let store = MailStore::new();
        populate_store(&store, &mails).await;
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        // Bootstrap never ends.
        let (_bootstrap_done, bootstrap_rx) = crate::sync::BootstrapDone::channel();
        let handler = tokio::spawn(crate::event_handler::run_event_handler(
            store.clone(),
            temp_local_store(),
            backend,
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            rx,
            shutdown_rx,
            bootstrap_rx,
        ));
        // Other bus messages are not held, so they do not count.
        for _ in 0..crate::event_handler::BOOTSTRAP_HOLD_LIMIT {
            tx.send(EventBusMessage::InitialSyncDone).await.unwrap();
        }
        for n in 0..crate::event_handler::BOOTSTRAP_HOLD_LIMIT - 1 {
            tx.send(EventBusMessage::EntityUpdate(EntityUpdateBatch {
                batch_id: format!("empty{n}"),
                group_id: "g".to_string(),
                updates: vec![],
            }))
            .await
            .unwrap();
        }
        tokio::task::yield_now().await;
        assert_eq!(
            store.get_folder("inbox").await.len(),
            1,
            "gave up too early"
        );
        tx.send(EventBusMessage::EntityUpdate(EntityUpdateBatch {
            batch_id: "b1".to_string(),
            group_id: "g".to_string(),
            updates: vec![EntityUpdateEvent {
                application: "tutanota".to_string(),
                type_id: 97, // Mail
                instance_list_id: "L".to_string(),
                instance_id: "m1".to_string(),
                operation: Operation::Delete,
                instance: None,
                blob_instance: None,
            }],
        }))
        .await
        .unwrap();
        drop(tx);
        handler.await.unwrap();
        assert!(store.get_folder("inbox").await.is_empty());
    }

    #[tokio::test]
    async fn status_reports_the_asked_mailbox_not_the_selected_one() {
        let backend = Arc::new(MockBackend::with_mails(vec![]));
        let store = MailStore::new();
        let work = FolderInfo {
            id: "work".to_string(),
            list_id: "folders".to_string(),
            entries_list_id: "work_entries".to_string(),
            kind: MailSetKind::Custom,
            imap_path: "Work".to_string(),
            special_use: None,
        };
        store.set_folder_list(vec![inbox_folder(), work]).await;
        let high = |eid: &str, uid| StoredMail {
            mail: make_mail(eid, "s", true),
            details: None,
            rfc2822: None,
            uid,
            attachments_pending: false,
        };
        store.set_folder("inbox", vec![high("i1", 40)]).await;
        store.set_folder("work", vec![high("w1", 7)]).await;
        let mut session = ImapSession::new(store, backend, None, None);
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        let resp = session.handle_command("c STATUS Work (UIDNEXT)").await;
        assert!(resp[0].contains("UIDNEXT 8 "), "{resp:?}");
        // Nor does SELECT carry INBOX's UIDNEXT over.
        let resp = session.handle_command("d SELECT Work").await;
        assert!(resp.iter().any(|r| r.contains("[UIDNEXT 8]")), "{resp:?}");
        let resp = session.handle_command("e STATUS Nope (UIDNEXT)").await;
        assert!(resp[0].starts_with("e NO [NONEXISTENT]"), "{resp:?}");
    }

    #[tokio::test]
    async fn move_to_trash_and_archive_by_their_served_names() {
        use crate::tuta::{system_imap_name, system_special_use};
        let system_folder = |id: &str, kind: MailSetKind| FolderInfo {
            id: id.to_string(),
            list_id: "folders".to_string(),
            entries_list_id: format!("{id}_entries"),
            kind,
            imap_path: system_imap_name(kind).unwrap().to_string(),
            special_use: system_special_use(kind).map(str::to_string),
        };
        let mails = vec![make_mail("e1", "one", false), make_mail("e2", "two", false)];
        let backend = Arc::new(MockBackend::with_mails(mails.clone()));
        let store = MailStore::new();
        // Seeds INBOX only, so the folder list is set after it.
        populate_store(&store, &mails).await;
        store
            .set_folder_list(vec![
                inbox_folder(),
                system_folder("trash", MailSetKind::Trash),
                system_folder("archive", MailSetKind::Archive),
            ])
            .await;
        let mut session = ImapSession::new(store, backend.clone(), None, None);
        session.handle_command("a LOGIN u p").await;

        // The folders a client must find to move into, with RFC 6154 roles.
        let resp = session.handle_command("b LIST \"\" \"*\"").await;
        assert!(
            resp.iter()
                .any(|r| r.contains("\\Trash") && r.contains("\"Trash\"")),
            "{resp:?}"
        );
        assert!(
            resp.iter()
                .any(|r| r.contains("\\Archive") && r.contains("\"Archive\"")),
            "{resp:?}"
        );

        session.handle_command("c SELECT INBOX").await;
        let resp = session.handle_command("d UID MOVE 1 Trash").await;
        assert!(resp.last().unwrap().contains("OK UID MOVE"), "{resp:?}");
        let resp = session.handle_command("e UID MOVE 2 Archive").await;
        assert!(resp.last().unwrap().contains("OK UID MOVE"), "{resp:?}");

        let moved = backend.moved.lock().unwrap();
        let targets: Vec<&str> = moved.iter().map(|(_, target)| target.as_str()).collect();
        assert_eq!(targets, ["trash", "archive"]);
    }

    #[tokio::test]
    async fn folder_management_answers_no_not_bad() {
        let backend = Arc::new(MockBackend::with_mails(vec![]));
        let (_, mut session) = make_session(backend).await;
        session.handle_command("a LOGIN u p").await;
        for cmd in ["CREATE Archive2", "DELETE Work", "RENAME Work Play"] {
            let resp = session.handle_command(&format!("t {cmd}")).await;
            assert!(resp[0].starts_with("t NO [CANNOT]"), "{cmd}: {resp:?}");
        }
        let resp = session.handle_command("t COPY 1 Trash").await;
        assert!(resp[0].starts_with("t NO [CANNOT]"), "{resp:?}");
    }

    #[test]
    fn mailbox_patterns_follow_rfc_3501() {
        assert!(mailbox_matches("*", "Work/Projects"));
        assert!(mailbox_matches("%", "Work"));
        assert!(!mailbox_matches("%", "Work/Projects"));
        assert!(mailbox_matches("Work/%", "Work/Projects"));
        assert!(!mailbox_matches("Work/%", "Work"));
        assert!(mailbox_matches("Work*", "Work/Projects/2026"));
        assert!(mailbox_matches("inbox", "INBOX"));
        assert!(mailbox_matches("Inbox/%", "INBOX/Sub"));
        assert!(!mailbox_matches("work", "Work"), "only INBOX ignores case");
        assert!(mailbox_matches("inb%", "INBOX"));
        assert!(mailbox_matches("inbox*", "INBOX/Sub"));
        assert!(mailbox_matches("*BOX", "INBOX"));
        assert!(!mailbox_matches("inb%", "Inbound"));
        assert!(!mailbox_matches("Trash", "Trash2"));
        // Client input: must not go exponential.
        let started = std::time::Instant::now();
        let pattern = "*a".repeat(40) + "b";
        assert!(!mailbox_matches(&pattern, &"a".repeat(200)));
        assert!(started.elapsed() < std::time::Duration::from_millis(200));
    }

    fn folder(id: &str, path: &str) -> FolderInfo {
        FolderInfo {
            id: id.to_string(),
            list_id: "folders".to_string(),
            entries_list_id: format!("{id}_entries"),
            kind: MailSetKind::Custom,
            imap_path: path.to_string(),
            special_use: None,
        }
    }

    #[tokio::test]
    async fn list_honours_reference_and_pattern() {
        let backend = Arc::new(MockBackend::with_mails(vec![]));
        let store = MailStore::new();
        store
            .set_folder_list(vec![
                inbox_folder(),
                folder("w", "Work"),
                folder("wp", "Work/Projects"),
                folder("q", "Say \"hi\""),
            ])
            .await;
        let mut session = ImapSession::new(store, backend, None, None);
        session.handle_command("a LOGIN u p").await;
        let names = |resp: Vec<String>| -> Vec<String> {
            resp.iter()
                .filter(|r| r.starts_with("* LIST"))
                .map(|r| r.rsplit_once(" \"/\" ").unwrap().1.trim_end().to_string())
                .collect()
        };
        assert_eq!(
            names(session.handle_command("b LIST \"\" \"*\"").await).len(),
            4
        );
        assert_eq!(
            names(session.handle_command("c LIST \"\" INBOX").await),
            ["\"INBOX\""]
        );
        assert_eq!(
            names(session.handle_command("d LIST \"\" %").await),
            ["\"INBOX\"", "\"Work\"", "\"Say \\\"hi\\\"\""]
        );
        assert_eq!(
            names(session.handle_command("e LIST Work/ %").await),
            ["\"Work/Projects\""]
        );
        let resp = session.handle_command("f LIST \"\" \"\"").await;
        assert_eq!(resp[0], "* LIST (\\Noselect) \"/\" \"\"\r\n");
        let resp = session.handle_command("g LIST \"\" Nope").await;
        assert_eq!(resp, ["g OK LIST completed\r\n"]);
        let resp = session.handle_command("h LIST").await;
        assert!(resp[0].starts_with("h BAD"), "{resp:?}");
    }

    #[tokio::test]
    async fn mailbox_lookup_is_exact_except_for_inbox() {
        let store = MailStore::new();
        store
            .set_folder_list(vec![
                inbox_folder(),
                folder("lower", "Work"),
                folder("upper", "WORK"),
            ])
            .await;
        assert_eq!(store.folder_by_imap_path("WORK").await.unwrap().id, "upper");
        assert_eq!(store.folder_by_imap_path("Work").await.unwrap().id, "lower");
        assert!(store.folder_by_imap_path("work").await.is_none());
        assert_eq!(
            store.folder_by_imap_path("inbox").await.unwrap().id,
            "inbox"
        );

        // The exact name wins, so a custom "Inbox" tree still opens; a unique
        // case-insensitive match still finds hand-typed system names.
        let store = MailStore::new();
        store
            .set_folder_list(vec![
                inbox_folder(),
                folder("ci", "Inbox"),
                folder("cc", "Inbox/Child"),
                folder("sent", "Sent"),
            ])
            .await;
        assert_eq!(
            store.folder_by_imap_path("Inbox/Child").await.unwrap().id,
            "cc"
        );
        assert_eq!(store.folder_by_imap_path("Inbox").await.unwrap().id, "ci");
        assert_eq!(
            store.folder_by_imap_path("INBOX").await.unwrap().id,
            "inbox"
        );
        assert_eq!(store.folder_by_imap_path("sent").await.unwrap().id, "sent");
    }

    #[tokio::test]
    async fn extended_list_forms_filter_or_answer_bad() {
        let local_store = temp_local_store();
        local_store.set_subscribed("w", false).unwrap();
        let backend = Arc::new(MockBackend::with_mails(vec![]));
        let store = MailStore::new();
        let mut trash = folder("t", "Trash");
        trash.special_use = Some("\\Trash".to_string());
        store
            .set_folder_list(vec![inbox_folder(), folder("w", "Work"), trash])
            .await;
        let mut session = ImapSession::new(store, backend, None, Some(local_store));
        session.handle_command("a LOGIN u p").await;
        let listed = |resp: &[String]| -> Vec<String> {
            resp.iter()
                .filter(|r| r.starts_with("* LIST"))
                .map(|r| r.trim_end().to_string())
                .collect()
        };
        let resp = session
            .handle_command("b LIST (SUBSCRIBED) \"\" \"*\"")
            .await;
        assert_eq!(
            listed(&resp),
            [
                "* LIST (\\Subscribed) \"/\" \"INBOX\"",
                "* LIST (\\Trash \\Subscribed) \"/\" \"Trash\""
            ]
        );
        let resp = session
            .handle_command("c LIST (SPECIAL-USE) \"\" \"*\"")
            .await;
        assert_eq!(listed(&resp), ["* LIST (\\Trash) \"/\" \"Trash\""]);
        let resp = session
            .handle_command("d LIST \"\" \"*\" RETURN (SPECIAL-USE)")
            .await;
        assert_eq!(listed(&resp).len(), 3);
        let resp = session.handle_command("e LIST (REMOTE) \"\" \"*\"").await;
        assert!(resp[0].starts_with("e BAD"), "{resp:?}");
        let resp = session
            .handle_command("e2 LIST \"\" \"*\" RETURN (SUBSCRIBED CHILDREN)")
            .await;
        assert_eq!(
            listed(&resp),
            [
                "* LIST (\\Subscribed \\HasNoChildren) \"/\" \"INBOX\"",
                "* LIST (\\HasNoChildren) \"/\" \"Work\"",
                "* LIST (\\Trash \\Subscribed \\HasNoChildren) \"/\" \"Trash\""
            ]
        );
        for cmd in [
            "LIST \"\" \"*\" RETURNX (SUBSCRIBED)",
            "LIST \"\" \"*\" RETURN",
            "LIST \"\" \"*\" RETURN (FOO)",
            "LIST \"\"",
            "LIST \"\" * aaaaa\u{e9}",
        ] {
            let resp = session.handle_command(&format!("t {cmd}")).await;
            assert!(resp[0].starts_with("t BAD"), "{cmd}: {resp:?}");
        }
        let resp = session.handle_command("f LSUB \"\" \"*\" RETURN ()").await;
        assert!(
            resp[0].starts_with("f BAD"),
            "LSUB takes no RETURN: {resp:?}"
        );
    }

    #[tokio::test]
    async fn lsub_keeps_an_unsubscribed_parent_as_noselect() {
        let local_store = temp_local_store();
        local_store.set_subscribed("w", false).unwrap();
        let backend = Arc::new(MockBackend::with_mails(vec![]));
        let store = MailStore::new();
        store
            .set_folder_list(vec![folder("w", "Work"), folder("wp", "Work/Projects")])
            .await;
        let mut session = ImapSession::new(store, backend, None, Some(local_store));
        session.handle_command("a LOGIN u p").await;
        let resp = session.handle_command("b LSUB \"\" %").await;
        assert_eq!(resp[0], "* LSUB (\\Noselect) \"/\" \"Work\"\r\n");
        // With `*` the pattern reaches the child itself: only it is listed.
        let resp = session.handle_command("b2 LSUB \"\" *").await;
        assert_eq!(resp[0], "* LSUB () \"/\" \"Work/Projects\"\r\n");
        assert_eq!(resp.len(), 2, "{resp:?}");
        let resp = session.handle_command("c UNSUBSCRIBE Gone").await;
        assert_eq!(resp, ["c OK UNSUBSCRIBE completed\r\n"]);
        let resp = session.handle_command("d SUBSCRIBE").await;
        assert!(resp[0].starts_with("d BAD"), "{resp:?}");
    }

    #[tokio::test]
    async fn names_with_quotes_round_trip_through_select_and_status() {
        let backend = Arc::new(MockBackend::with_mails(vec![]));
        let store = MailStore::new();
        store
            .set_folder_list(vec![
                inbox_folder(),
                folder("q", "Say \"hi\""),
                folder("b", "a\\b"),
            ])
            .await;
        let mut session = ImapSession::new(store, backend, None, None);
        session.handle_command("a LOGIN u p").await;
        let resp = session.handle_command("b SELECT \"Say \\\"hi\\\"\"").await;
        assert!(resp.last().unwrap().starts_with("b OK"), "{resp:?}");
        let resp = session.handle_command("c EXAMINE \"a\\\\b\"").await;
        assert!(resp.last().unwrap().starts_with("c OK"), "{resp:?}");
        let resp = session
            .handle_command("d STATUS \"Say \\\"hi\\\"\" (MESSAGES)")
            .await;
        assert!(
            resp[0].starts_with("* STATUS \"Say \\\"hi\\\"\" ("),
            "{resp:?}"
        );
        // RECURSIVEMATCH needs CHILDINFO, which is not implemented: refused.
        let resp = session
            .handle_command("e LIST (SUBSCRIBED RECURSIVEMATCH) \"\" %")
            .await;
        assert!(resp[0].starts_with("e BAD"), "{resp:?}");
    }

    #[tokio::test]
    async fn subscriptions_persist_and_shape_lsub() {
        let local_store = temp_local_store();
        let backend = Arc::new(MockBackend::with_mails(vec![]));
        let store = MailStore::new();
        store
            .set_folder_list(vec![inbox_folder(), folder("w", "Work")])
            .await;
        let mut session = ImapSession::new(
            store.clone(),
            backend.clone(),
            None,
            Some(local_store.clone()),
        );
        session.handle_command("a LOGIN u p").await;

        // Every folder starts subscribed; LSUB answers with LSUB lines.
        let resp = session.handle_command("b LSUB \"\" *").await;
        assert_eq!(resp.iter().filter(|r| r.starts_with("* LSUB")).count(), 2);
        assert!(resp.last().unwrap().starts_with("b OK LSUB"));

        let resp = session.handle_command("c UNSUBSCRIBE Work").await;
        assert_eq!(resp, ["c OK UNSUBSCRIBE completed\r\n"]);
        let resp = session.handle_command("d LSUB \"\" *").await;
        assert!(!resp.iter().any(|r| r.contains("Work")), "{resp:?}");
        // LIST still shows it: unsubscribing hides nothing on the server.
        let resp = session.handle_command("e LIST \"\" *").await;
        assert!(resp.iter().any(|r| r.contains("Work")), "{resp:?}");

        // Persisted: a new session sees the same.
        let mut later = ImapSession::new(store, backend, None, Some(local_store));
        later.handle_command("a LOGIN u p").await;
        let resp = later.handle_command("b LSUB \"\" *").await;
        assert!(!resp.iter().any(|r| r.contains("Work")), "{resp:?}");
        let resp = later.handle_command("c SUBSCRIBE Work").await;
        assert_eq!(resp, ["c OK SUBSCRIBE completed\r\n"]);
        let resp = later.handle_command("d LSUB \"\" *").await;
        assert!(resp.iter().any(|r| r.contains("Work")), "{resp:?}");

        let resp = later.handle_command("e SUBSCRIBE Nope").await;
        assert!(resp[0].starts_with("e NO [NONEXISTENT]"), "{resp:?}");
    }

    #[tokio::test]
    async fn uid_move_moves_to_target_and_expunges() {
        let m1 = make_mail("e1", "one", false);
        let m2 = make_mail("e2", "two", false);
        let backend = Arc::new(MockBackend::with_mails(vec![m1.clone(), m2.clone()]));
        let store = MailStore::new();
        let target = FolderInfo {
            id: "cust".to_string(),
            list_id: "folders".to_string(),
            entries_list_id: "cust_entries".to_string(),
            kind: MailSetKind::Custom,
            imap_path: "Work".to_string(),
            special_use: None,
        };
        store.set_folder_list(vec![inbox_folder(), target]).await;
        store
            .set_folder(
                "inbox",
                vec![
                    StoredMail {
                        mail: m1,
                        details: None,
                        rfc2822: None,
                        uid: 1,
                        attachments_pending: false,
                    },
                    StoredMail {
                        mail: m2,
                        details: None,
                        rfc2822: None,
                        uid: 2,
                        attachments_pending: false,
                    },
                ],
            )
            .await;
        let mut session = ImapSession::new(store, backend.clone(), None, None);
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        let resp = session.handle_command("c UID MOVE 1 Work").await;
        assert!(
            resp.iter().any(|r| r.contains("EXPUNGE")),
            "expected EXPUNGE, got {resp:?}"
        );
        assert!(resp.last().unwrap().contains("OK UID MOVE"));

        let moved = backend.moved.lock().unwrap();
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].1, "cust");
        assert_eq!(moved[0].0.len(), 1);
    }

    /// Fetch one not-yet-loaded mail on demand through a session backed by a
    /// real `LocalStore`; returns the FETCH response, the backend and the store.
    async fn on_demand_fetch(
        fail_attachments: bool,
    ) -> (Vec<String>, Arc<MockBackend>, Arc<LocalStore>) {
        use crypto_primitives::aes::Aes256Key;
        use crypto_primitives::key::GenericAesKey;
        use crypto_primitives::randomizer_facade::RandomizerFacade;

        let tmp = std::env::temp_dir().join(format!("tutabridge_test_{}", rand::random::<u64>()));
        let key = GenericAesKey::Aes256(Aes256Key::generate(&RandomizerFacade::from_core(
            rand_core::OsRng,
        )));
        let local_store =
            Arc::new(LocalStore::open(&tmp.join("s.db"), &tmp.join("mails"), key).unwrap());

        let mail = make_mail("od", "subj", true);
        local_store
            .upsert_mail_metadata(&crate::sync::mail_to_metadata(&mail, "inbox", 1))
            .unwrap();
        let backend = Arc::new(MockBackend::with_mails(vec![mail.clone()]));
        backend.add_details("od", make_details("<p>quokka</p>"));
        *backend.fail_attachments.lock().unwrap() = fail_attachments;
        let store = MailStore::new();
        store.set_folder_list(vec![inbox_folder()]).await;
        store
            .set_folder(
                "inbox",
                vec![StoredMail {
                    mail,
                    details: None,
                    rfc2822: None,
                    uid: 1,
                    attachments_pending: false,
                }],
            )
            .await;
        let mut session = ImapSession::new(store, backend.clone(), None, Some(local_store.clone()));
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;
        let resp = session.handle_command("c UID FETCH 1 (BODY.PEEK[])").await;
        (resp, backend, local_store)
    }

    #[tokio::test]
    async fn on_demand_body_fetch_persists_and_indexes_the_rendition() {
        let (resp, backend, local_store) = on_demand_fetch(false).await;
        assert!(resp.last().unwrap().contains("OK"), "{resp:?}");
        assert!(
            resp[0].contains("BODY[] {") && resp[0].contains("\r\nX-Tutabridge-Authentication: "),
            "{resp:?}"
        );
        // PEEK reads without marking the mail read.
        assert!(backend.unread_calls.lock().unwrap().is_empty());

        let cached = local_store.read_eml("od").unwrap().unwrap();
        assert!(cached.starts_with("X-Tutabridge-Authentication: "));
        assert!(local_store.load_folder_metadata("inbox").unwrap()[0].has_details);
        assert_eq!(
            local_store.search_body("quokka").unwrap(),
            vec!["od".to_string()]
        );
    }

    #[tokio::test]
    async fn on_demand_body_fetch_with_failed_attachments_is_not_persisted() {
        let (resp, _, local_store) = on_demand_fetch(true).await;
        assert!(resp.last().unwrap().contains("OK"), "{resp:?}");
        // Served from memory, but not written: on disk, prefetch would take
        // it as done and the attachments would never be retried.
        assert!(!local_store.has_eml("od"));
        assert!(!local_store.load_folder_metadata("inbox").unwrap()[0].has_details);
    }

    #[tokio::test]
    async fn on_demand_body_fetch_failure_returns_no_and_cooldowns() {
        let mail = make_mail("ed", "subj", false);
        let backend = Arc::new(MockBackend::with_mails(vec![mail.clone()]));
        backend.set_fail_details(true);
        let store = MailStore::new();
        store.set_folder_list(vec![inbox_folder()]).await;
        store
            .set_folder(
                "inbox",
                vec![StoredMail {
                    mail,
                    details: None,
                    rfc2822: None,
                    uid: 1,
                    attachments_pending: false,
                }],
            )
            .await;
        let mut session = ImapSession::new(store.clone(), backend.clone(), None, None);
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        // A failed on-demand body fetch returns NO [UNAVAILABLE] (not a fake
        // body) and arms the shared cooldown.
        let resp = session.handle_command("c UID FETCH 1 (BODY[])").await;
        assert!(
            resp.last().unwrap().contains("NO [UNAVAILABLE]"),
            "expected NO on failure, got {resp:?}"
        );
        assert!(store.body_fetch_on_cooldown("ed"));

        // While cooling down, a repeat fetch is short-circuited to NO without
        // touching the backend, even though it would now succeed.
        backend.set_fail_details(false);
        let resp2 = session.handle_command("d UID FETCH 1 (BODY[])").await;
        assert!(
            resp2.last().unwrap().contains("NO [UNAVAILABLE]"),
            "cooldown should keep returning NO, got {resp2:?}"
        );
    }

    #[tokio::test]
    async fn copy_is_rejected() {
        let backend = Arc::new(MockBackend::with_mails(vec![]));
        let (_store, mut session) = make_session(backend).await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;
        let resp = session.handle_command("c UID COPY 1 Work").await;
        assert!(
            resp[0].contains("NO"),
            "COPY should be rejected, got {resp:?}"
        );
    }

    #[test]
    fn parse_append_extracts_mailbox_and_size() {
        let r = parse_append("a1 APPEND \"Sent\" (\\Seen) {310}").unwrap();
        assert_eq!(r.tag, "a1");
        assert_eq!(r.mailbox, "Sent");
        assert_eq!(r.literal_size, 310);

        // Bare (unquoted) mailbox, no flags.
        let r = parse_append("x APPEND Drafts {42}").unwrap();
        assert_eq!(r.mailbox, "Drafts");
        assert_eq!(r.literal_size, 42);

        // Non-synchronizing literal {N+}.
        let r = parse_append("y APPEND \"Sent\" {7+}").unwrap();
        assert_eq!(r.literal_size, 7);

        // Not an APPEND, or missing the literal.
        assert!(parse_append("z SELECT INBOX").is_none());
        assert!(parse_append("z APPEND Sent").is_none());
    }

    #[tokio::test]
    async fn append_targets_sent_only_for_the_sent_folder() {
        let backend = Arc::new(MockBackend::with_mails(vec![]));
        let store = MailStore::new();
        let sent = FolderInfo {
            id: "sent".into(),
            list_id: "folders".into(),
            entries_list_id: "sent_entries".into(),
            kind: MailSetKind::Sent,
            imap_path: "Sent".into(),
            special_use: Some("\\Sent".into()),
        };
        store.set_folder_list(vec![inbox_folder(), sent]).await;
        let session = ImapSession::new(store, backend, None, None);

        assert!(session.append_targets_sent("Sent").await);
        assert!(!session.append_targets_sent("INBOX").await);
        assert!(!session.append_targets_sent("Nonexistent").await);
    }

    fn test_label(id: &str, name: &str) -> crate::labels::LabelInfo {
        crate::labels::LabelInfo {
            id: id.to_string(),
            list_id: "labels".to_string(),
            name: name.to_string(),
            color: None,
        }
    }

    #[tokio::test]
    async fn select_advertises_label_keywords_as_permanent_without_star() {
        let backend = Arc::new(MockBackend::with_mails(vec![make_mail("e1", "s", true)]));
        let (store, mut session) = make_session(backend).await;
        store
            .set_labels(vec![
                test_label("l1", "Package Tracking"),
                test_label("l2", "Ważne"),
            ])
            .await;
        session.handle_command("a LOGIN u p").await;
        let resp = session.handle_command("b SELECT INBOX").await;

        let flags = resp
            .iter()
            .find(|r| r.starts_with("* FLAGS"))
            .expect("SELECT must advertise FLAGS");
        assert!(
            flags.contains("\\Draft Package_Tracking Wazne"),
            "keywords must follow the system flags: {flags}"
        );
        // Keywords are STOREable, and `\*` invites clients to invent new
        // ones — STORE creates the backing label.
        let perm = resp
            .iter()
            .find(|r| r.contains("PERMANENTFLAGS"))
            .expect("SELECT must advertise PERMANENTFLAGS");
        assert!(
            perm.contains("Package_Tracking") && perm.contains("Wazne"),
            "keywords must be permanent: {perm}"
        );
        assert!(perm.contains("\\*"), "\\* must be advertised: {perm}");
    }

    #[tokio::test]
    async fn store_plus_keyword_applies_label_and_reports_flags() {
        let mail = make_mail("e1", "s", false);
        let backend = Arc::new(MockBackend::with_mails(vec![mail]));
        let (store, mut session) = make_session(backend.clone()).await;
        store.set_labels(vec![test_label("l1", "Ephemeral")]).await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        // Lowercase keyword — Thunderbird sends its lowercased tag key.
        let resp = session
            .handle_command("c UID STORE 1 +FLAGS (ephemeral)")
            .await;

        let calls = backend.labels_applied.lock().unwrap();
        assert_eq!(calls.len(), 1, "one batched ApplyLabelService call");
        let (mails, added, removed) = &calls[0];
        assert_eq!(mails.len(), 1);
        assert_eq!(mails[0].element_id.to_string(), "e1");
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].element_id.to_string(), "l1");
        assert!(removed.is_empty());
        drop(calls);

        // Untagged FETCH with the new flags (and UID — UID mode).
        assert!(
            resp[0].contains("FETCH (UID 1 FLAGS (\\Seen Ephemeral))"),
            "untagged FETCH must report the new flags: {:?}",
            resp[0]
        );
        assert!(resp.last().unwrap().contains("OK UID STORE"));

        // Optimistic update reached the shared store too.
        let stored = store.get_folder("inbox").await;
        assert!(stored[0]
            .mail
            .sets
            .iter()
            .any(|s| s.element_id.to_string() == "l1"));
    }

    #[tokio::test]
    async fn malformed_sets_and_unsearchable_terms_are_errors_not_empty() {
        use crypto_primitives::aes::Aes256Key;
        use crypto_primitives::key::GenericAesKey;
        use crypto_primitives::randomizer_facade::RandomizerFacade;

        let tmp = std::env::temp_dir().join(format!("tutabridge_test_{}", rand::random::<u64>()));
        let key = GenericAesKey::Aes256(Aes256Key::generate(&RandomizerFacade::from_core(
            rand_core::OsRng,
        )));
        let local_store =
            Arc::new(LocalStore::open(&tmp.join("s.db"), &tmp.join("mails"), key).unwrap());
        let mails = vec![make_mail("e1", "a", true), make_mail("e2", "b", true)];
        let backend = Arc::new(MockBackend::with_mails(mails.clone()));
        let store = MailStore::new();
        populate_store(&store, &mails).await;
        let mut session = ImapSession::new(store, backend, None, Some(local_store));
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        for cmd in [
            "FETCH 1:2:3 (UID)",
            "FETCH 0 (UID)",
            "STORE x +FLAGS (\\Seen)",
        ] {
            let resp = session.handle_command(&format!("t {cmd}")).await;
            assert!(resp[0].starts_with("t BAD"), "{cmd}: {resp:?}");
        }
        // A huge range is one pass over the mailbox, not four billion.
        let started = std::time::Instant::now();
        let resp = session
            .handle_command("u UID FETCH 1:4294967295 (UID)")
            .await;
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(resp.len(), 3, "{resp:?}");

        let resp = session
            .handle_command("v SEARCH CHARSET KOI8-R SUBJECT a")
            .await;
        assert!(resp[0].starts_with("v NO [BADCHARSET"), "{resp:?}");
        let resp = session.handle_command("w SEARCH BODY \"!!!\"").await;
        assert!(resp[0].starts_with("w NO [CANNOT]"), "{resp:?}");
        // RFC 3501: the empty string is in every message.
        let resp = session.handle_command("x SEARCH BODY \"\"").await;
        assert_eq!(resp[0], "* SEARCH 1 2\r\n");
        // And an empty result has no trailing space.
        let resp = session.handle_command("y SEARCH SUBJECT zzz").await;
        assert_eq!(resp[0], "* SEARCH\r\n");
    }

    #[tokio::test]
    async fn search_keyword_matches_labelled_mail() {
        let mut tagged = make_mail("e1", "s", false);
        tagged.sets = vec![IdTupleGenerated::new(test_id("labels"), test_id("l1"))];
        let plain = make_mail("e2", "s", false);
        let backend = Arc::new(MockBackend::with_mails(vec![tagged, plain]));
        let (store, mut session) = make_session(backend).await;
        store.set_labels(vec![test_label("l1", "Ephemeral")]).await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        // Thunderbird sends keywords lowercased.
        let resp = session
            .handle_command("c UID SEARCH KEYWORD ephemeral")
            .await;
        assert_eq!(resp[0], "* SEARCH 1\r\n");
        let resp = session.handle_command("d SEARCH UNKEYWORD Ephemeral").await;
        assert_eq!(resp[0], "* SEARCH 2\r\n");
        // An unknown keyword is a real "nothing carries it", not a stub.
        let resp = session.handle_command("e SEARCH KEYWORD NoSuchTag").await;
        assert_eq!(resp[0], "* SEARCH\r\n");
        // A malformed one is an error, never an empty success.
        // `*` is the last message only (RFC 3501), not all of them.
        let resp = session.handle_command("g SEARCH *").await;
        assert_eq!(resp[0], "* SEARCH 2\r\n");
        let resp = session.handle_command("f UID SEARCH KEYWORD").await;
        assert!(resp[0].starts_with("f BAD "), "{resp:?}");
        assert_eq!(resp.len(), 1);
    }

    #[tokio::test]
    async fn store_minus_keyword_removes_label() {
        let mut mail = make_mail("e1", "s", false);
        mail.sets = vec![IdTupleGenerated::new(test_id("labels"), test_id("l1"))];
        let backend = Arc::new(MockBackend::with_mails(vec![mail]));
        let (store, mut session) = make_session(backend.clone()).await;
        store.set_labels(vec![test_label("l1", "Ephemeral")]).await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        let resp = session.handle_command("c STORE 1 -FLAGS (Ephemeral)").await;

        let calls = backend.labels_applied.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (_, added, removed) = &calls[0];
        assert!(added.is_empty());
        assert_eq!(removed[0].element_id.to_string(), "l1");
        drop(calls);

        assert!(
            resp[0].contains("FLAGS (\\Seen)") && !resp[0].contains("Ephemeral"),
            "keyword must be gone from the reported flags: {:?}",
            resp[0]
        );
    }

    #[tokio::test]
    async fn store_silent_suppresses_untagged_fetch() {
        let backend = Arc::new(MockBackend::with_mails(vec![make_mail("e1", "s", false)]));
        let (store, mut session) = make_session(backend.clone()).await;
        store.set_labels(vec![test_label("l1", "Ephemeral")]).await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        let resp = session
            .handle_command("c STORE 1 +FLAGS.SILENT (Ephemeral)")
            .await;
        assert_eq!(
            resp.len(),
            1,
            ".SILENT must suppress untagged FETCH: {resp:?}"
        );
        assert!(resp[0].contains("OK STORE"));
        // The label call still happened.
        assert_eq!(backend.labels_applied.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn store_mixed_system_flag_and_keyword() {
        let backend = Arc::new(MockBackend::with_mails(vec![make_mail("e1", "s", true)]));
        let (store, mut session) = make_session(backend.clone()).await;
        store.set_labels(vec![test_label("l1", "Ephemeral")]).await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        let resp = session
            .handle_command("c STORE 1 +FLAGS (\\Seen Ephemeral)")
            .await;

        // Both backends hit: read status and label service.
        let unread = backend.unread_calls.lock().unwrap();
        assert_eq!(unread.len(), 1);
        assert!(!unread[0].1, "+FLAGS \\Seen marks read");
        drop(unread);
        assert_eq!(backend.labels_applied.lock().unwrap().len(), 1);

        assert!(
            resp[0].contains("FLAGS (\\Seen Ephemeral)"),
            "both flags reported: {:?}",
            resp[0]
        );
    }

    #[tokio::test]
    async fn store_unknown_keyword_creates_label_and_applies_it() {
        let backend = Arc::new(MockBackend::with_mails(vec![make_mail("e1", "s", false)]));
        let (store, mut session) = make_session(backend.clone()).await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        let resp = session.handle_command("c STORE 1 +FLAGS (ProjectX)").await;

        // The label was created backend-side with the bridge default color…
        {
            let created = backend.labels.lock().unwrap();
            assert_eq!(created.len(), 1);
            assert_eq!(created[0].name, "ProjectX");
            assert_eq!(created[0].color.as_deref(), Some(""));
        }
        // …applied to the mail in the same STORE…
        {
            let calls = backend.labels_applied.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].1[0].element_id.to_string(), "created_1");
        }
        // …reported in the untagged FETCH, and registered for future STOREs.
        assert!(
            resp[0].contains("FLAGS (\\Seen ProjectX)"),
            "new keyword must be reported: {:?}",
            resp[0]
        );
        let reg = store.label_registry().await;
        assert_eq!(reg.label_for_keyword("projectx").unwrap().id, "created_1");
    }

    #[tokio::test]
    async fn store_minus_unknown_keyword_does_not_create() {
        let backend = Arc::new(MockBackend::with_mails(vec![make_mail("e1", "s", false)]));
        let (_store, mut session) = make_session(backend.clone()).await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        let resp = session.handle_command("c STORE 1 -FLAGS (Nope)").await;
        assert!(resp.last().unwrap().contains("OK STORE"));
        // Removing a keyword no label backs is a no-op, not a create.
        assert!(backend.labels.lock().unwrap().is_empty());
        assert!(backend.labels_applied.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn store_non_roundtripping_keyword_skipped_but_rest_applies() {
        let backend = Arc::new(MockBackend::with_mails(vec![make_mail("e1", "s", true)]));
        let (_store, mut session) = make_session(backend.clone()).await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        // '&' sanitizes to '_', so the created label's atom would not match
        // the stored keyword — the bridge must skip it, not create garbage.
        let resp = session
            .handle_command("c STORE 1 +FLAGS (\\Seen No&Such)")
            .await;

        assert!(resp.last().unwrap().contains("OK STORE"));
        assert_eq!(backend.unread_calls.lock().unwrap().len(), 1);
        assert!(backend.labels.lock().unwrap().is_empty());
        assert!(backend.labels_applied.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn label_rename_and_delete_refresh_keywords() {
        let mut mail = make_mail("e1", "s", false);
        mail.sets = vec![IdTupleGenerated::new(test_id("labels"), test_id("l1"))];
        let backend = Arc::new(MockBackend::with_mails(vec![mail]));
        let (store, mut session) = make_session(backend).await;
        store.set_labels(vec![test_label("l1", "OldName")]).await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        let resp = session.handle_command("c FETCH 1 (FLAGS)").await;
        assert!(resp[0].contains("OldName"));

        // Rename in the Tuta app arrives as a MailSet event → registry
        // rebuild. Same label id, new atom.
        store.set_labels(vec![test_label("l1", "NewName")]).await;
        let resp = session.handle_command("d FETCH 1 (FLAGS)").await;
        assert!(
            resp[0].contains("NewName") && !resp[0].contains("OldName"),
            "renamed label must swap atoms: {:?}",
            resp[0]
        );

        // Delete: the keyword vanishes even though the mail's `sets` still
        // carries the stale id until the Mail update event lands.
        store.set_labels(Vec::new()).await;
        let resp = session.handle_command("e FETCH 1 (FLAGS)").await;
        assert!(
            !resp[0].contains("NewName"),
            "deleted label must disappear from FLAGS: {:?}",
            resp[0]
        );
    }

    #[tokio::test]
    async fn store_replace_mode_diffs_labels_per_mail() {
        let mut mail = make_mail("e1", "s", false);
        mail.sets = vec![
            // Folder membership must survive a label replace untouched.
            IdTupleGenerated::new(test_id("folders"), test_id("inbox")),
            IdTupleGenerated::new(test_id("labels"), test_id("l1")),
        ];
        let backend = Arc::new(MockBackend::with_mails(vec![mail]));
        let (store, mut session) = make_session(backend.clone()).await;
        store
            .set_labels(vec![
                test_label("l1", "Ephemeral"),
                test_label("l2", "Keep"),
            ])
            .await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        let resp = session
            .handle_command("c STORE 1 FLAGS (\\Seen Keep)")
            .await;

        let calls = backend.labels_applied.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (_, added, removed) = &calls[0];
        assert_eq!(added[0].element_id.to_string(), "l2");
        assert_eq!(removed[0].element_id.to_string(), "l1");
        drop(calls);

        assert!(
            resp[0].contains("FLAGS (\\Seen Keep)"),
            "replaced flag set reported: {:?}",
            resp[0]
        );
        // Folder membership untouched by the optimistic sets update.
        let folder_still_there = session.mails[0]
            .mail
            .sets
            .iter()
            .any(|s| s.element_id.to_string() == "inbox");
        assert!(folder_still_there);
    }

    #[test]
    fn parse_store_args_variants() {
        let a = parse_store_args("1:5 +FLAGS.SILENT (\\Seen temp)").unwrap();
        assert_eq!(a.seq_set, "1:5");
        assert_eq!(a.op, StoreOp::Add);
        assert!(a.silent);
        assert_eq!(a.flags, vec!["\\Seen", "temp"]);

        let b = parse_store_args("7 -flags fup").unwrap();
        assert_eq!(b.op, StoreOp::Remove);
        assert!(!b.silent);
        assert_eq!(b.flags, vec!["fup"]);

        let c = parse_store_args("2 FLAGS ()").unwrap();
        assert_eq!(c.op, StoreOp::Replace);
        assert!(c.flags.is_empty());

        assert!(parse_store_args("2 NOTFLAGS (x)").is_none());
        assert!(parse_store_args("").is_none());
    }

    #[tokio::test]
    async fn fetch_flags_includes_keywords_for_labeled_mails_only() {
        let mut labeled = make_mail("e1", "labeled", false);
        labeled.sets = vec![
            // The mail's folder also appears in `sets` — it must not leak
            // into FLAGS as a keyword.
            IdTupleGenerated::new(test_id("folders"), test_id("inbox")),
            IdTupleGenerated::new(test_id("labels"), test_id("l1")),
        ];
        let plain = make_mail("e2", "plain", false);
        let backend = Arc::new(MockBackend::with_mails(vec![labeled, plain]));
        let (store, mut session) = make_session(backend).await;
        store.set_labels(vec![test_label("l1", "Ephemeral")]).await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        let resp = session.handle_command("c FETCH 1:2 (FLAGS)").await;
        assert!(
            resp[0].contains("FLAGS (\\Seen Ephemeral)"),
            "labeled mail must carry its keyword: {:?}",
            resp[0]
        );
        assert!(
            resp[1].contains("FLAGS (\\Seen)") && !resp[1].contains("Ephemeral"),
            "unlabeled mail must be unchanged: {:?}",
            resp[1]
        );
    }

    #[tokio::test]
    async fn label_change_in_store_is_visible_after_idle_wakeup() {
        // A label applied in the Tuta app arrives as a Mail UPDATE event:
        // the event handler refreshes the mail in the MailStore and bumps
        // the generation, the connection loop calls `check_new_mail`. The
        // session must fold the new `sets` in even though no mail was added
        // or removed.
        let mail = make_mail("e1", "s", false);
        let backend = Arc::new(MockBackend::with_mails(vec![mail.clone()]));
        let (store, mut session) = make_session(backend).await;
        store.set_labels(vec![test_label("l1", "Ephemeral")]).await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;

        let before = session.handle_command("c FETCH 1 (FLAGS)").await;
        assert!(!before[0].contains("Ephemeral"));

        let mut updated = mail;
        updated.sets = vec![IdTupleGenerated::new(test_id("labels"), test_id("l1"))];
        store.refresh_mail_in_place(&updated).await;
        let signals = session.check_new_mail().await;
        assert!(
            signals.is_empty(),
            "no EXISTS/EXPUNGE for a flags-only change"
        );

        let after = session.handle_command("d FETCH 1 (FLAGS)").await;
        assert!(
            after[0].contains("Ephemeral"),
            "label set in the store must reach the session view: {:?}",
            after[0]
        );
    }

    async fn populate_store(store: &MailStore, mails: &[Mail]) {
        store.set_folder_list(vec![inbox_folder()]).await;
        let stored: Vec<StoredMail> = mails
            .iter()
            .enumerate()
            .map(|(i, m)| StoredMail {
                mail: m.clone(),
                details: None,
                rfc2822: None,
                uid: (i + 1) as u32,
                attachments_pending: false,
            })
            .collect();
        store.set_folder("inbox", stored).await;
    }

    async fn make_session(backend: Arc<MockBackend>) -> (Arc<MailStore>, ImapSession) {
        let store = MailStore::new();
        let mails = backend.mails.lock().unwrap().clone();
        populate_store(&store, &mails).await;
        let session = ImapSession::new(store.clone(), backend, None, None);
        (store, session)
    }

    #[async_trait::async_trait]
    impl MailBackend for MockBackend {
        async fn load_mail_ids_for_folder(
            &self,
            _folder: &FolderInfo,
            _limit: usize,
        ) -> Result<Vec<Mail>, String> {
            Ok(self.mails.lock().unwrap().clone())
        }
        async fn load_mail(
            &self,
            _list_id: &str,
            element_id: &str,
        ) -> Result<Option<Mail>, String> {
            Ok(self
                .mails
                .lock()
                .unwrap()
                .iter()
                .find(|m| {
                    m._id
                        .as_ref()
                        .map(|id| id.element_id.to_string())
                        .as_deref()
                        == Some(element_id)
                })
                .cloned())
        }
        async fn decrypt_inline_mail(&self, _json: &str) -> Result<Option<Mail>, String> {
            // Tests stub: the inline path is exercised by handler tests with
            // an explicit recorded payload, not through the mock's body.
            Ok(None)
        }
        async fn decrypt_inline_mail_set_entry(
            &self,
            _json: &str,
        ) -> Result<Option<tutasdk::entities::generated::tutanota::MailSetEntry>, String> {
            Ok(None)
        }
        async fn decrypt_inline_mail_details_blob(
            &self,
            _json: &str,
        ) -> Result<Option<MailDetails>, String> {
            Ok(None)
        }
        async fn load_mail_details(&self, mail: &Mail) -> Result<Option<MailDetails>, String> {
            if *self.fail_details.lock().unwrap() {
                return Err("simulated Too Many Requests".to_string());
            }
            let key = mail
                ._id
                .as_ref()
                .map(|id| id.element_id.to_string())
                .unwrap_or_default();
            Ok(self.details.lock().unwrap().get(&key).cloned())
        }
        async fn load_attachments(
            &self,
            _mail: &Mail,
        ) -> Result<
            Vec<(
                tutasdk::entities::generated::tutanota::TutanotaFile,
                Vec<u8>,
            )>,
            String,
        > {
            if *self.fail_attachments.lock().unwrap() {
                return Err("simulated attachment failure".to_string());
            }
            // The mock has no attachment fixtures; the IMAP-session tests
            // only exercise body/header paths.
            Ok(Vec::new())
        }
        async fn list_folders(&self) -> Result<Vec<FolderInfo>, String> {
            Ok(vec![inbox_folder()])
        }
        async fn list_labels(&self) -> Result<Vec<crate::labels::LabelInfo>, String> {
            // Sessions read labels from the MailStore registry, never from
            // the backend — tests seed the store directly via `set_labels`.
            Ok(self.labels.lock().unwrap().clone())
        }
        async fn create_label(
            &self,
            name: &str,
            color: &str,
        ) -> Result<Vec<crate::labels::LabelInfo>, String> {
            let mut labels = self.labels.lock().unwrap();
            let id = format!("created_{}", labels.len() + 1);
            labels.push(crate::labels::LabelInfo {
                id,
                list_id: "labels".to_string(),
                name: name.to_string(),
                color: Some(color.to_string()),
            });
            Ok(labels.clone())
        }
        async fn set_unread_status(
            &self,
            mail_ids: Vec<IdTupleGenerated>,
            unread: bool,
        ) -> Result<(), String> {
            self.unread_calls.lock().unwrap().push((mail_ids, unread));
            Ok(())
        }
        async fn apply_labels(
            &self,
            mail_ids: Vec<IdTupleGenerated>,
            added: Vec<IdTupleGenerated>,
            removed: Vec<IdTupleGenerated>,
        ) -> Result<(), String> {
            self.labels_applied
                .lock()
                .unwrap()
                .push((mail_ids, added, removed));
            Ok(())
        }
        async fn trash_mails(&self, mail_ids: Vec<IdTupleGenerated>) -> Result<(), String> {
            self.trashed.lock().unwrap().extend(mail_ids);
            Ok(())
        }
        async fn move_mails(
            &self,
            mail_ids: Vec<IdTupleGenerated>,
            target: &FolderInfo,
        ) -> Result<(), String> {
            self.moved
                .lock()
                .unwrap()
                .push((mail_ids, target.id.clone()));
            Ok(())
        }
        async fn send_mail(&self, msg: &ParsedMessage) -> Result<(), String> {
            self.sent.lock().unwrap().push(msg.clone());
            Ok(())
        }
    }

    fn make_mail(element_id: &str, subject: &str, unread: bool) -> Mail {
        Mail {
            _id: Some(IdTupleGenerated::new(test_id("list1"), test_id(element_id))),
            _permissions: test_id("perm1"),
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
            conversationEntry: IdTupleGenerated::new(test_id("conv_list"), test_id("conv_elem")),
            firstRecipient: Some(MailAddress {
                _id: None,
                name: "Recip".to_string(),
                address: "recip@test.com".to_string(),
                contact: None,
                _errors: Default::default(),
            }),
            mailDetails: None,
            mailDetailsDraft: None,
            bucketKey: None,
            sets: vec![],
            clientSpamClassifierResult: None,
            _errors: Default::default(),
        }
    }

    fn make_details(body_html: &str) -> MailDetails {
        MailDetails {
            _id: None,
            sentDate: DateTime::from_millis(1735130245000),
            authStatus: 0,
            replyTos: vec![],
            recipients: Recipients {
                _id: None,
                toRecipients: vec![MailAddress {
                    _id: None,
                    name: "Recip".to_string(),
                    address: "recip@test.com".to_string(),
                    contact: None,
                    _errors: Default::default(),
                }],
                ccRecipients: vec![],
                bccRecipients: vec![],
            },
            headers: None,
            body: Body {
                _id: None,
                text: Some(body_html.to_string()),
                compressedText: None,
                _errors: Default::default(),
            },
        }
    }

    // --- Full IMAP session integration tests ---

    #[tokio::test]
    async fn test_full_login_select_fetch_sequence() {
        let m1 = make_mail("m1", "First mail", true);
        let m2 = make_mail("m2", "Second mail", false);
        let d1 = make_details("<p>Body 1</p>");
        let d2 = make_details("<p>Body 2</p>");

        let backend = Arc::new(MockBackend::with_mails(vec![m1.clone(), m2.clone()]));
        let store = MailStore::new();
        let rfc1 = crate::mail::mail_to_rfc2822(&m1, Some(&d1), &[]);
        let rfc2 = crate::mail::mail_to_rfc2822(&m2, Some(&d2), &[]);
        store.set_folder_list(vec![inbox_folder()]).await;
        store
            .set_folder(
                "inbox",
                vec![
                    StoredMail {
                        mail: m1,
                        details: Some(d1),
                        rfc2822: Some(rfc1),
                        uid: 1,
                        attachments_pending: false,
                    },
                    StoredMail {
                        mail: m2,
                        details: Some(d2),
                        rfc2822: Some(rfc2),
                        uid: 2,
                        attachments_pending: false,
                    },
                ],
            )
            .await;
        let mut session = ImapSession::new(store, backend, None, None);

        // LOGIN
        let resp = session.handle_command("A001 LOGIN user pass").await;
        assert!(resp[0].contains("OK LOGIN"));

        // LIST
        let resp = session.handle_command("A002 LIST \"\" \"*\"").await;
        assert!(resp.iter().any(|r| r.contains("INBOX")));
        assert!(resp.last().unwrap().contains("OK LIST"));

        // SELECT INBOX
        let resp = session.handle_command("A003 SELECT INBOX").await;
        assert!(resp.iter().any(|r| r.contains("* 2 EXISTS")));
        assert!(resp.iter().any(|r| r.contains("UIDNEXT")));
        assert!(resp.last().unwrap().contains("OK"));

        // FETCH FLAGS
        let resp = session.handle_command("A004 FETCH 1:* (FLAGS UID)").await;
        assert!(resp[0].contains("* 1 FETCH"));
        assert!(resp[0].contains("FLAGS ()")); // unread → no \Seen
        assert!(resp[1].contains("* 2 FETCH"));
        assert!(resp[1].contains("FLAGS (\\Seen)")); // read → \Seen
        assert!(resp.last().unwrap().contains("OK FETCH"));

        // UID FETCH with BODY
        let resp = session
            .handle_command("A005 UID FETCH 1 (BODY.PEEK[])")
            .await;
        assert!(resp[0].contains("BODY[]"));
        // Body is base64-encoded HTML, verify the literal is present
        let b64_body = base64::engine::general_purpose::STANDARD.encode(b"<p>Body 1</p>");
        assert!(resp[0].contains(&b64_body));
    }

    #[tokio::test]
    async fn test_store_seen_flag_calls_backend() {
        let backend = Arc::new(MockBackend::with_mails(vec![make_mail(
            "m1",
            "Unread mail",
            true,
        )]));
        let store = MailStore::new();
        populate_store(&store, &backend.mails.lock().unwrap()).await;
        let mut session = ImapSession::new(store, backend.clone(), None, None);

        session.handle_command("A001 LOGIN user pass").await;
        session.handle_command("A002 SELECT INBOX").await;

        // Mark as read — the new state comes back as an untagged FETCH
        // (RFC 3501 §6.4.6) followed by the tagged OK.
        let resp = session.handle_command("A003 STORE 1 +FLAGS (\\Seen)").await;
        assert!(resp[0].contains("* 1 FETCH (FLAGS (\\Seen))"), "{resp:?}");
        assert!(resp.last().unwrap().contains("OK"));

        // Verify backend was called
        let calls = backend.unread_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, false); // unread=false → marking as read

        // Verify local state updated
        let resp = session.handle_command("A004 FETCH 1 (FLAGS)").await;
        assert!(resp[0].contains("\\Seen"));
    }

    #[tokio::test]
    async fn test_delete_and_expunge() {
        let backend = Arc::new(MockBackend::with_mails(vec![
            make_mail("m1", "Mail 1", false),
            make_mail("m2", "Mail 2", false),
            make_mail("m3", "Mail 3", false),
        ]));
        let store = MailStore::new();
        populate_store(&store, &backend.mails.lock().unwrap()).await;
        let mut session = ImapSession::new(store, backend.clone(), None, None);

        session.handle_command("A001 LOGIN user pass").await;
        session.handle_command("A002 SELECT INBOX").await;

        // Mark mail 2 as deleted
        session
            .handle_command("A003 STORE 2 +FLAGS (\\Deleted)")
            .await;

        // Verify deleted flag in FETCH
        let resp = session.handle_command("A004 FETCH 2 (FLAGS)").await;
        assert!(resp[0].contains("\\Deleted"));

        // EXPUNGE
        let resp = session.handle_command("A005 EXPUNGE").await;
        assert!(resp.iter().any(|r| r.contains("* 2 EXPUNGE")));
        assert!(resp.last().unwrap().contains("OK EXPUNGE"));

        // Verify backend was called
        let trashed = backend.trashed.lock().unwrap();
        assert_eq!(trashed.len(), 1);

        // Verify only 2 mails remain
        let resp = session.handle_command("A006 FETCH 1:* (FLAGS UID)").await;
        let fetch_lines: Vec<_> = resp
            .iter()
            .filter(|r| r.contains("* ") && r.contains("FETCH"))
            .collect();
        assert_eq!(fetch_lines.len(), 2);
    }

    #[tokio::test]
    async fn test_uid_stability_across_refresh() {
        let backend = Arc::new(MockBackend::with_mails(vec![
            make_mail("m1", "First", false),
            make_mail("m2", "Second", false),
        ]));
        let store = MailStore::new();
        populate_store(&store, &backend.mails.lock().unwrap()).await;
        let mut session = ImapSession::new(store.clone(), backend.clone(), None, None);

        session.handle_command("A001 LOGIN user pass").await;
        session.handle_command("A002 SELECT INBOX").await;

        // Get initial UIDs
        let resp = session.handle_command("A003 FETCH 1:* (UID)").await;
        let uid1_first = extract_uid(&resp[0]);
        let uid2_first = extract_uid(&resp[1]);

        // Add a new mail, update both backend and store, re-SELECT
        {
            let mut mails = backend.mails.lock().unwrap();
            mails.push(make_mail("m3", "Third", true));
        }
        populate_store(&store, &backend.mails.lock().unwrap()).await;
        session.handle_command("A004 SELECT INBOX").await;

        // Get UIDs again
        let resp = session.handle_command("A005 FETCH 1:* (UID)").await;
        let uid1_second = extract_uid(&resp[0]);
        let uid2_second = extract_uid(&resp[1]);
        let uid3 = extract_uid(&resp[2]);

        // UIDs for existing mails must be stable
        assert_eq!(uid1_first, uid1_second, "UID for m1 changed after refresh");
        assert_eq!(uid2_first, uid2_second, "UID for m2 changed after refresh");
        // New mail gets a new UID
        assert!(uid3 > uid2_second, "New mail UID should be higher");
    }

    fn extract_uid(line: &str) -> u32 {
        let uid_pos = line.find("UID ").unwrap();
        let rest = &line[uid_pos + 4..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse().unwrap()
    }

    #[tokio::test]
    async fn test_idle_end_with_done() {
        let backend = Arc::new(MockBackend::with_mails(vec![make_mail(
            "m1", "Test", false,
        )]));
        let (_store, mut session) = make_session(backend).await;

        session.handle_command("A001 LOGIN user pass").await;
        session.handle_command("A002 SELECT INBOX").await;

        // Enter IDLE
        let resp = session.handle_command("A003 IDLE").await;
        assert!(resp[0].contains("+ idling"));
        assert!(session.is_idle());

        // End IDLE
        let resp = session.end_idle();
        assert!(resp[0].contains("A003 OK IDLE terminated"));
        assert!(!session.is_idle());
    }

    #[tokio::test]
    async fn test_search_unseen() {
        let backend = Arc::new(MockBackend::with_mails(vec![
            make_mail("m1", "Read", false),
            make_mail("m2", "Unread", true),
            make_mail("m3", "Also read", false),
        ]));
        let (_store, mut session) = make_session(backend).await;

        session.handle_command("A001 LOGIN user pass").await;
        session.handle_command("A002 SELECT INBOX").await;

        let resp = session.handle_command("A003 SEARCH UNSEEN").await;
        assert!(resp[0].contains("* SEARCH 2"));
        assert!(!resp[0].contains("1"));
        assert!(!resp[0].contains("3"));
    }

    #[tokio::test]
    async fn test_uid_search_unseen() {
        let backend = Arc::new(MockBackend::with_mails(vec![
            make_mail("m1", "Read", false),
            make_mail("m2", "Unread", true),
        ]));
        let (_store, mut session) = make_session(backend).await;

        session.handle_command("A001 LOGIN user pass").await;
        session.handle_command("A002 SELECT INBOX").await;

        let resp = session.handle_command("A003 UID SEARCH UNSEEN").await;
        // Should return UID of the unread mail, not sequence number
        let search_line = &resp[0];
        assert!(search_line.contains("* SEARCH"));
        // UID 2 (second mail)
        assert!(search_line.contains("2"));
    }

    #[tokio::test]
    async fn test_search_subject_and_from() {
        let backend = Arc::new(MockBackend::with_mails(vec![
            make_mail("m1", "Invoice March", false),
            make_mail("m2", "Holiday photos", true),
            make_mail("m3", "Invoice April", false),
        ]));
        let (_store, mut session) = make_session(backend).await;
        session.handle_command("A001 LOGIN user pass").await;
        session.handle_command("A002 SELECT INBOX").await;

        // SUBJECT matches only the two invoices (1 and 3), case-insensitively.
        let resp = session
            .handle_command(r#"A003 SEARCH SUBJECT "invoice""#)
            .await;
        assert_eq!(resp[0], "* SEARCH 1 3\r\n");

        // Combined with UNSEEN, nothing matches (both invoices are read).
        let resp = session
            .handle_command(r#"A004 SEARCH SUBJECT "invoice" UNSEEN"#)
            .await;
        assert_eq!(resp[0], "* SEARCH\r\n");

        // FROM matches the shared sender on every message.
        let resp = session
            .handle_command(r#"A005 SEARCH FROM "sender@tuta.com""#)
            .await;
        assert_eq!(resp[0], "* SEARCH 1 2 3\r\n");

        // A non-matching subject returns an empty set (the regression that
        // motivated real SEARCH: it used to return everything).
        let resp = session
            .handle_command(r#"A006 SEARCH SUBJECT "nonexistent""#)
            .await;
        assert_eq!(resp[0], "* SEARCH\r\n");
    }

    #[tokio::test]
    async fn test_not_authenticated_rejects_commands() {
        let backend = Arc::new(MockBackend::new());
        let (_store, mut session) = make_session(backend).await;

        let resp = session.handle_command("A001 SELECT INBOX").await;
        assert!(resp[0].contains("NO Not authenticated"));

        let resp = session.handle_command("A001 LIST \"\" \"*\"").await;
        assert!(resp[0].contains("NO Not authenticated"));
    }

    #[tokio::test]
    async fn test_no_mailbox_selected_rejects_fetch() {
        let backend = Arc::new(MockBackend::new());
        let (_store, mut session) = make_session(backend).await;

        session.handle_command("A001 LOGIN user pass").await;

        let resp = session.handle_command("A002 FETCH 1 (FLAGS)").await;
        assert!(resp[0].contains("NO No mailbox selected"));
    }

    #[tokio::test]
    async fn test_close_resets_state() {
        let backend = Arc::new(MockBackend::with_mails(vec![make_mail(
            "m1", "Test", false,
        )]));
        let (_store, mut session) = make_session(backend).await;

        session.handle_command("A001 LOGIN user pass").await;
        session.handle_command("A002 SELECT INBOX").await;
        session.handle_command("A003 CLOSE").await;

        // Should reject FETCH after CLOSE
        let resp = session.handle_command("A004 FETCH 1 (FLAGS)").await;
        assert!(resp[0].contains("NO No mailbox selected"));
    }

    #[tokio::test]
    async fn test_expunge_sequence_numbers_shift() {
        let backend = Arc::new(MockBackend::with_mails(vec![
            make_mail("m1", "Mail 1", false),
            make_mail("m2", "Mail 2", false),
            make_mail("m3", "Mail 3", false),
            make_mail("m4", "Mail 4", false),
        ]));
        let (_store, mut session) = make_session(backend).await;

        session.handle_command("A001 LOGIN user pass").await;
        session.handle_command("A002 SELECT INBOX").await;

        // Delete mails 1 and 3
        session
            .handle_command("A003 STORE 1 +FLAGS (\\Deleted)")
            .await;
        session
            .handle_command("A004 STORE 3 +FLAGS (\\Deleted)")
            .await;

        let resp = session.handle_command("A005 EXPUNGE").await;

        // Mail 1 is expunged at seq 1, then mail 3 becomes seq 2
        let expunge_lines: Vec<_> = resp
            .iter()
            .filter(|r| r.starts_with("* ") && r.contains("EXPUNGE"))
            .collect();
        assert_eq!(expunge_lines.len(), 2);
        assert!(expunge_lines[0].contains("* 1 EXPUNGE"));
        assert!(expunge_lines[1].contains("* 2 EXPUNGE"));
    }

    #[tokio::test]
    async fn test_logout() {
        let backend = Arc::new(MockBackend::new());
        let (_store, mut session) = make_session(backend).await;

        let resp = session.handle_command("A001 LOGOUT").await;
        assert!(resp.iter().any(|r| r.contains("BYE")));
        assert!(session.is_logout());
    }

    #[tokio::test]
    async fn test_namespace() {
        let backend = Arc::new(MockBackend::new());
        let (_store, mut session) = make_session(backend).await;

        let resp = session.handle_command("A001 NAMESPACE").await;
        assert!(resp[0].contains("NAMESPACE"));
        assert!(resp[0].contains("((\"\" \"/\"))"));
    }

    #[tokio::test]
    async fn test_capability() {
        let backend = Arc::new(MockBackend::new());
        let (_store, mut session) = make_session(backend).await;

        let resp = session.handle_command("A001 CAPABILITY").await;
        assert!(resp[0].contains("IMAP4rev1"));
        assert!(resp[0].contains("IDLE"));
    }

    // --- check_new_mail: push diff to the IDLE'd client ---

    async fn session_on_inbox(mails: Vec<Mail>) -> (Arc<MailStore>, ImapSession) {
        let backend = Arc::new(MockBackend::with_mails(mails.clone()));
        let (store, mut session) = make_session(backend).await;
        populate_store(&store, &mails).await;
        session.handle_command("a LOGIN u p").await;
        session.handle_command("b SELECT INBOX").await;
        (store, session)
    }

    #[tokio::test]
    async fn check_new_mail_quiet_when_set_unchanged() {
        // Same mails, same order, same count → nothing to tell the client.
        let m1 = make_mail("e1", "one", false);
        let (_store, mut session) = session_on_inbox(vec![m1]).await;
        let resp = session.check_new_mail().await;
        assert!(resp.is_empty(), "expected no notifications, got {resp:?}");
    }

    #[tokio::test]
    async fn check_new_mail_pushes_exists_on_growth() {
        let m1 = make_mail("e1", "one", false);
        let (store, mut session) = session_on_inbox(vec![m1.clone()]).await;
        let m2 = make_mail("e2", "two", false);
        store
            .set_folder(
                "inbox",
                vec![
                    StoredMail {
                        mail: m1,
                        details: None,
                        rfc2822: None,
                        uid: 1,
                        attachments_pending: false,
                    },
                    StoredMail {
                        mail: m2,
                        details: None,
                        rfc2822: None,
                        uid: 2,
                        attachments_pending: false,
                    },
                ],
            )
            .await;
        let resp = session.check_new_mail().await;
        // No EXPUNGE — only an added mail. EXISTS reports the new total.
        assert!(!resp.iter().any(|r| r.contains("EXPUNGE")), "got {resp:?}");
        assert!(
            resp.iter().any(|r| r.contains("* 2 EXISTS")),
            "got {resp:?}"
        );
    }

    #[tokio::test]
    async fn check_new_mail_pushes_expunge_on_removal() {
        let m1 = make_mail("e1", "one", false);
        let m2 = make_mail("e2", "two", false);
        let (store, mut session) = session_on_inbox(vec![m1.clone(), m2.clone()]).await;
        // Drop m2 from the store — simulates a server-side delete arriving via
        // the event bus.
        store
            .set_folder(
                "inbox",
                vec![StoredMail {
                    mail: m1,
                    details: None,
                    rfc2822: None,
                    uid: 1,
                    attachments_pending: false,
                }],
            )
            .await;
        let resp = session.check_new_mail().await;
        // m2 was seqno 2 in the session view.
        assert!(
            resp.iter().any(|r| r.contains("* 2 EXPUNGE")),
            "got {resp:?}"
        );
        assert!(
            resp.iter().any(|r| r.contains("* 1 EXISTS")),
            "got {resp:?}"
        );
    }

    #[tokio::test]
    async fn check_new_mail_pushes_swap_when_count_unchanged() {
        // Regression test for the MOVE-between-folders bug: a fresh mail
        // arrived (event bus) and an old one fell out of the sync_limit
        // window. Total count stays the same, but the set changed — we must
        // still notify so the client refetches.
        let old1 = make_mail("e1", "one", false);
        let old2 = make_mail("e2", "two", false);
        let (store, mut session) = session_on_inbox(vec![old1.clone(), old2.clone()]).await;
        let new3 = make_mail("e3", "three", false);
        store
            .set_folder(
                "inbox",
                vec![
                    StoredMail {
                        mail: old1,
                        details: None,
                        rfc2822: None,
                        uid: 1,
                        attachments_pending: false,
                    },
                    StoredMail {
                        mail: new3,
                        details: None,
                        rfc2822: None,
                        uid: 3,
                        attachments_pending: false,
                    },
                ],
            )
            .await;
        let resp = session.check_new_mail().await;
        // e2 was at seqno 2 — must EXPUNGE it. Then EXISTS reports the
        // (unchanged) count so the client refetches and discovers e3.
        assert!(
            resp.iter().any(|r| r.contains("* 2 EXPUNGE")),
            "got {resp:?}"
        );
        assert!(
            resp.iter().any(|r| r.contains("* 2 EXISTS")),
            "got {resp:?}"
        );
    }

    #[tokio::test]
    async fn check_new_mail_expunges_in_descending_seqno() {
        // RFC 3501: when several mails are expunged, seqnos must arrive in
        // descending order so subsequent ones don't shift incorrectly.
        let m1 = make_mail("e1", "1", false);
        let m2 = make_mail("e2", "2", false);
        let m3 = make_mail("e3", "3", false);
        let (store, mut session) = session_on_inbox(vec![m1.clone(), m2, m3]).await;
        // Only m1 survives; m2 and m3 are gone.
        store
            .set_folder(
                "inbox",
                vec![StoredMail {
                    mail: m1,
                    details: None,
                    rfc2822: None,
                    uid: 1,
                    attachments_pending: false,
                }],
            )
            .await;
        let resp = session.check_new_mail().await;
        let expunge_idx_3 = resp
            .iter()
            .position(|r| r.contains("* 3 EXPUNGE"))
            .expect("missing 3");
        let expunge_idx_2 = resp
            .iter()
            .position(|r| r.contains("* 2 EXPUNGE"))
            .expect("missing 2");
        assert!(
            expunge_idx_3 < expunge_idx_2,
            "EXPUNGE 3 must come before EXPUNGE 2, got {resp:?}",
        );
    }
}
