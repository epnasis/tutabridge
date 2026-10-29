mod search;
mod session;
mod utf7;

use log::{debug, error, info};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use crate::store::LocalStore;
use crate::sync::MailStore;
use crate::tuta::MailBackend;
use session::ImapSession;

pub async fn serve(
    port: u16,
    store: Arc<MailStore>,
    backend: Arc<dyn MailBackend>,
    local_store: Arc<LocalStore>,
    tls: TlsAcceptor,
    password_hash: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    info!("IMAP server listening on 127.0.0.1:{} (TLS)", port);

    crate::net::accept_loop(
        listener,
        "IMAP",
        crate::net::MAX_CONNECTIONS,
        move |stream, _addr| {
            let store = store.clone();
            let backend = backend.clone();
            let local_store = local_store.clone();
            let tls = tls.clone();
            let pw_hash = password_hash.clone();
            async move {
                match tokio::time::timeout(crate::net::HANDSHAKE_TIMEOUT, tls.accept(stream)).await
                {
                    Ok(Ok(tls_stream)) => {
                        if let Err(e) =
                            handle_connection(tls_stream, store, backend, local_store, pw_hash)
                                .await
                        {
                            error!("IMAP connection error: {}", e);
                        }
                    }
                    Ok(Err(e)) => error!("IMAP TLS handshake failed: {}", e),
                    Err(_) => debug!("IMAP TLS handshake timed out"),
                }
            }
        },
    )
    .await;

    Ok(())
}

async fn handle_connection(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    store: Arc<MailStore>,
    backend: Arc<dyn MailBackend>,
    local_store: Arc<LocalStore>,
    password_hash: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut store_watch: watch::Receiver<u64> = store.subscribe();
    let mut session = ImapSession::new(store, backend, password_hash, Some(local_store));

    writer
        .write_all(b"* OK TutaBridge IMAP4rev1 ready\r\n")
        .await?;
    writer.flush().await?;

    let mut line = String::new();
    loop {
        if session.is_idle() {
            line.clear();
            tokio::select! {
                result = reader.read_line(&mut line) => {
                    let n = result?;
                    if n == 0 {
                        break;
                    }
                    let trimmed = line.trim_end();
                    debug!("IMAP C (idle): {}", trimmed);
                    if trimmed.eq_ignore_ascii_case("DONE") {
                        let responses = session.end_idle();
                        for resp in &responses {
                            debug!("IMAP S: {}", resp.trim_end());
                            writer.write_all(resp.as_bytes()).await?;
                        }
                        writer.flush().await?;
                    }
                }
                _ = store_watch.changed() => {
                    let updates = session.check_new_mail().await;
                    for resp in &updates {
                        debug!("IMAP S (store update): {}", resp.trim_end());
                        writer.write_all(resp.as_bytes()).await?;
                    }
                    writer.flush().await?;
                }
            }
            continue;
        }

        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let trimmed = line.trim_end();
        debug!("IMAP C: {}", trimmed);

        // APPEND carries a message literal the line-based session layer cannot
        // read, so it is handled here at the socket level.
        if !session.is_awaiting_auth() {
            if let Some(req) = session::parse_append(trimmed) {
                handle_append(&mut reader, &mut writer, &session, req).await?;
                continue;
            }
        }

        let responses = if session.is_awaiting_auth() {
            session.handle_auth_response(trimmed)
        } else {
            session.handle_command(trimmed).await
        };
        for resp in &responses {
            debug!("IMAP S: {}", resp.trim_end());
            writer.write_all(resp.as_bytes()).await?;
        }
        writer.flush().await?;

        if session.is_logout() {
            break;
        }
    }

    Ok(())
}

/// Largest APPEND message literal we will read into memory.
const MAX_APPEND_BYTES: usize = 26_214_400;

/// Handle an `APPEND`:
/// - to Sent it is accepted as a no-op: Tuta saves sent mail server-side,
///   so a client's "save a copy to Sent" must not create a duplicate (the
///   real copy arrives via the syncer);
/// - to Drafts the message is saved as a Tuta draft;
/// - anywhere else it is refused before the literal is sent, so the client
///   aborts a synchronizing literal; a non-synchronizing one (`{N+}`) is
///   already on its way and is read and dropped to keep the stream in sync.
async fn handle_append<R, W>(
    reader: &mut R,
    writer: &mut W,
    session: &ImapSession,
    req: session::AppendRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // Logged in first: a draft is real mail in the user's account.
    let target = session.append_target(&req.mailbox).await;
    let refusal = if !session.is_authenticated() {
        Some(format!("{} NO Not authenticated\r\n", req.tag))
    } else if req.literal_size > MAX_APPEND_BYTES {
        Some(format!("{} NO [TOOBIG] message too large\r\n", req.tag))
    } else if matches!(target, session::AppendTarget::Other) {
        Some(format!(
            "{} NO [CANNOT] APPEND is supported for Sent (kept by Tuta) and Drafts only\r\n",
            req.tag
        ))
    } else {
        None
    };
    if let Some(refusal) = refusal {
        if req.non_sync {
            discard_literal(reader, req.literal_size).await?;
        }
        writer.write_all(refusal.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    if !req.non_sync {
        writer.write_all(b"+ OK\r\n").await?;
        writer.flush().await?;
    }
    let mut message = vec![0u8; req.literal_size];
    reader.read_exact(&mut message).await?;
    let mut tail = String::new();
    reader.read_line(&mut tail).await?;

    // The target as decided above, not looked up again: the folder list may
    // have changed while the literal arrived.
    let resp = match target {
        session::AppendTarget::Drafts(drafts) => {
            session.append_draft(&req.tag, &drafts, &message).await
        }
        _ => format!("{} OK APPEND completed\r\n", req.tag),
    };
    writer.write_all(resp.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Read and drop a literal plus the end of its command line, without
/// holding a huge one in memory at once.
async fn discard_literal<R>(
    reader: &mut R,
    size: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncBufRead + Unpin,
{
    let mut left = size;
    let mut chunk = vec![0u8; 64 * 1024];
    while left > 0 {
        let n = left.min(chunk.len());
        reader.read_exact(&mut chunk[..n]).await?;
        left -= n;
    }
    let mut tail = String::new();
    reader.read_line(&mut tail).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail::parser::ParsedMessage;
    use crate::tuta::FolderInfo;
    use tokio::io::AsyncReadExt;
    use tutasdk::entities::generated::tutanota::{Mail, MailDetails, MailSetEntry, TutanotaFile};
    use tutasdk::folder_system::MailSetKind;
    use tutasdk::IdTupleGenerated;

    #[derive(Default)]
    struct NoopBackend {
        /// Subjects of the drafts `save_draft` was given.
        drafts: std::sync::Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl MailBackend for NoopBackend {
        async fn save_draft(&self, m: &ParsedMessage) -> Result<IdTupleGenerated, String> {
            self.drafts.lock().unwrap().push(m.subject.clone());
            Ok(IdTupleGenerated::new(
                tutasdk::GeneratedId("draftlist".into()),
                tutasdk::GeneratedId("draft1".into()),
            ))
        }
        async fn load_mail_ids_for_folder(
            &self,
            _f: &FolderInfo,
            _l: usize,
        ) -> Result<Vec<Mail>, String> {
            unimplemented!()
        }
        async fn load_mail(&self, _l: &str, _e: &str) -> Result<Option<Mail>, String> {
            unimplemented!()
        }
        async fn decrypt_inline_mail(&self, _j: &str) -> Result<Option<Mail>, String> {
            unimplemented!()
        }
        async fn decrypt_inline_mail_set_entry(
            &self,
            _j: &str,
        ) -> Result<Option<MailSetEntry>, String> {
            unimplemented!()
        }
        async fn decrypt_inline_mail_details_blob(
            &self,
            _j: &str,
        ) -> Result<Option<MailDetails>, String> {
            unimplemented!()
        }
        async fn load_mail_details(&self, _m: &Mail) -> Result<Option<MailDetails>, String> {
            unimplemented!()
        }
        async fn load_attachments(
            &self,
            _m: &Mail,
        ) -> Result<Vec<(TutanotaFile, Vec<u8>)>, String> {
            unimplemented!()
        }
        async fn list_folders(&self) -> Result<Vec<FolderInfo>, String> {
            unimplemented!()
        }
        async fn list_labels(&self) -> Result<Vec<crate::labels::LabelInfo>, String> {
            unimplemented!()
        }
        async fn create_label(
            &self,
            _name: &str,
            _color: &str,
        ) -> Result<Vec<crate::labels::LabelInfo>, String> {
            unimplemented!()
        }
        async fn apply_labels(
            &self,
            _mail_ids: Vec<IdTupleGenerated>,
            _added: Vec<IdTupleGenerated>,
            _removed: Vec<IdTupleGenerated>,
        ) -> Result<(), String> {
            unimplemented!()
        }
        async fn set_unread_status(
            &self,
            _ids: Vec<IdTupleGenerated>,
            _u: bool,
        ) -> Result<(), String> {
            unimplemented!()
        }
        async fn trash_mails(&self, _ids: Vec<IdTupleGenerated>) -> Result<(), String> {
            unimplemented!()
        }
        async fn move_mails(
            &self,
            _ids: Vec<IdTupleGenerated>,
            _t: &FolderInfo,
        ) -> Result<(), String> {
            unimplemented!()
        }
        async fn send_mail(&self, _m: &ParsedMessage) -> Result<(), String> {
            unimplemented!()
        }
    }

    async fn session_with_sent() -> ImapSession {
        let store = MailStore::new();
        let sent = FolderInfo {
            id: "sent".into(),
            list_id: "folders".into(),
            entries_list_id: "se".into(),
            kind: MailSetKind::Sent,
            imap_path: "Sent".into(),
            special_use: Some("\\Sent".into()),
        };
        store.set_folder_list(vec![sent]).await;
        let mut session = ImapSession::new(store, Arc::new(NoopBackend::default()), None, None);
        session.handle_command("a LOGIN u p").await;
        session
    }

    #[tokio::test]
    async fn append_to_drafts_saves_a_draft_and_names_its_uid() {
        use crypto_primitives::aes::Aes256Key;
        use crypto_primitives::key::GenericAesKey;
        use crypto_primitives::randomizer_facade::RandomizerFacade;

        let tmp = std::env::temp_dir().join(format!("tutabridge_test_{}", rand::random::<u64>()));
        let key = GenericAesKey::Aes256(Aes256Key::generate(&RandomizerFacade::from_core(
            rand_core::OsRng,
        )));
        let local_store = Arc::new(
            crate::store::LocalStore::open(&tmp.join("s.db"), &tmp.join("mails"), key).unwrap(),
        );
        let (validity, _) = local_store.folder_uid_state("drafts").unwrap();
        let store = MailStore::new();
        store
            .set_folder_list(vec![FolderInfo {
                id: "drafts".into(),
                list_id: "folders".into(),
                entries_list_id: "de".into(),
                kind: MailSetKind::Draft,
                imap_path: "Drafts".into(),
                special_use: Some("\\Drafts".into()),
            }])
            .await;
        let backend = Arc::new(NoopBackend::default());
        let mut session = ImapSession::new(store, backend.clone(), None, Some(local_store.clone()));
        session.handle_command("a LOGIN u p").await;

        let message = b"Subject: plan\r\nTo: a@x.test\r\n\r\nbody\r\n";
        let (mut client, server) = tokio::io::duplex(4096);
        let (sr, mut sw) = tokio::io::split(server);
        let mut reader = BufReader::new(sr);
        let req =
            session::parse_append(&format!("d1 APPEND Drafts (\\Draft) {{{}}}", message.len()))
                .unwrap();
        let server_fut = handle_append(&mut reader, &mut sw, &session, req);
        let client_fut = async {
            let mut buf = [0u8; 32];
            let n = client.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with('+'));
            client.write_all(message).await.unwrap();
            client.write_all(b"\r\n").await.unwrap();
            let mut resp = vec![0u8; 128];
            let n = client.read(&mut resp).await.unwrap();
            String::from_utf8_lossy(&resp[..n]).into_owned()
        };
        let (res, resp) = tokio::join!(server_fut, client_fut);
        res.unwrap();
        assert_eq!(
            resp,
            format!("d1 OK [APPENDUID {validity} 1] APPEND completed\r\n")
        );
        assert_eq!(*backend.drafts.lock().unwrap(), ["plan"]);
        // The event handler will find the same UID for this placement.
        assert_eq!(
            local_store
                .assign_folder_uids("drafts", &["draft1"])
                .unwrap()["draft1"],
            1
        );
    }

    #[tokio::test]
    async fn a_refused_non_synchronizing_append_keeps_the_stream_in_step() {
        let session = session_with_sent().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let (sr, mut sw) = tokio::io::split(server);
        let mut reader = BufReader::new(sr);
        let req = session::parse_append("n1 APPEND Work {5+}").unwrap();
        assert!(req.non_sync);
        // `{N+}`: the bytes follow at once, with the next command after them.
        client.write_all(b"hello\r\nn2 NOOP\r\n").await.unwrap();
        handle_append(&mut reader, &mut sw, &session, req)
            .await
            .unwrap();
        let mut resp = vec![0u8; 128];
        let n = client.read(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).starts_with("n1 NO"));
        let mut next = String::new();
        reader.read_line(&mut next).await.unwrap();
        assert_eq!(next, "n2 NOOP\r\n");
    }

    #[tokio::test]
    async fn append_before_login_creates_nothing() {
        let store = MailStore::new();
        store
            .set_folder_list(vec![FolderInfo {
                id: "drafts".into(),
                list_id: "folders".into(),
                entries_list_id: "de".into(),
                kind: MailSetKind::Draft,
                imap_path: "Drafts".into(),
                special_use: Some("\\Drafts".into()),
            }])
            .await;
        let backend = Arc::new(NoopBackend::default());
        let session = ImapSession::new(store, backend.clone(), Some("secret".into()), None);
        let (mut client, server) = tokio::io::duplex(4096);
        let (sr, mut sw) = tokio::io::split(server);
        let mut reader = BufReader::new(sr);
        let req = session::parse_append("p1 APPEND Drafts {7+}").unwrap();
        client.write_all(b"preauth\r\n").await.unwrap();
        handle_append(&mut reader, &mut sw, &session, req)
            .await
            .unwrap();
        let mut resp = vec![0u8; 128];
        let n = client.read(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).starts_with("p1 NO"));
        assert!(backend.drafts.lock().unwrap().is_empty());
    }

    #[test]
    fn append_mailbox_names_are_unescaped() {
        let req = session::parse_append("a APPEND \"Say \\\"hi\\\"\" {5}").unwrap();
        assert_eq!(req.mailbox, "Say \"hi\"");
        assert!(!req.non_sync);
    }

    #[tokio::test]
    async fn append_to_sent_reads_literal_and_returns_ok() {
        let session = session_with_sent().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let (sr, mut sw) = tokio::io::split(server);
        let mut reader = BufReader::new(sr);
        let req = session::AppendRequest {
            tag: "a1".into(),
            mailbox: "Sent".into(),
            non_sync: false,
            literal_size: 5,
        };

        let server_fut = handle_append(&mut reader, &mut sw, &session, req);
        let client_fut = async {
            let mut buf = [0u8; 32];
            let n = client.read(&mut buf).await.unwrap();
            assert!(
                String::from_utf8_lossy(&buf[..n]).starts_with('+'),
                "expected a continuation request"
            );
            client.write_all(b"hello\r\n").await.unwrap();
            let mut resp = vec![0u8; 128];
            let n = client.read(&mut resp).await.unwrap();
            String::from_utf8_lossy(&resp[..n]).into_owned()
        };
        let (res, resp) = tokio::join!(server_fut, client_fut);
        res.unwrap();
        assert!(resp.contains("a1 OK APPEND completed"), "got {resp:?}");
    }

    #[tokio::test]
    async fn append_to_non_sent_is_rejected_without_continuation() {
        let session = session_with_sent().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let (sr, mut sw) = tokio::io::split(server);
        let mut reader = BufReader::new(sr);
        let req = session::AppendRequest {
            tag: "b2".into(),
            mailbox: "Drafts".into(),
            non_sync: false,
            literal_size: 5,
        };

        let server_fut = handle_append(&mut reader, &mut sw, &session, req);
        let client_fut = async {
            let mut resp = vec![0u8; 128];
            let n = client.read(&mut resp).await.unwrap();
            String::from_utf8_lossy(&resp[..n]).into_owned()
        };
        let (res, resp) = tokio::join!(server_fut, client_fut);
        res.unwrap();
        assert!(resp.contains("b2 NO"), "got {resp:?}");
        assert!(
            !resp.contains('+'),
            "a rejected folder must not get a continuation"
        );
    }
}
