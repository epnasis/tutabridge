//! The bridge's connection to Tuta, published as a file for local clients.
//!
//! IMAP has no way to say "this mailbox is stale": while the event bus is
//! down, the store keeps serving whatever it synced last and every client
//! sees a normal-looking inbox. On 2026-09-16 Tuta began refusing the
//! bridge's client version and it served a frozen inbox for eight days
//! with nothing but its own log saying so. Clients that can read a file
//! (aish's tuta tools) check this one and report the state they find.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tutasdk::event_bus::WsState;

/// Record the connection state and when it was entered. Written through a
/// temp file so a reader never sees a torn write.
pub fn record(path: &Path, state: WsState, since: SystemTime) -> std::io::Result<()> {
    let since_unix = since
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = serde_json::json!({
        "tuta_connection": format!("{state:?}"),
        "since_unix": since_unix,
        "pid": std::process::id(),
    });
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    std::fs::write(&tmp, body.to_string())?;
    std::fs::rename(&tmp, path)
}

/// Like [`record`], but a failure is logged rather than returned: the file is
/// a courtesy to clients and must never take the bridge down.
pub fn record_or_log(path: &Path, state: WsState) {
    if let Err(e) = record(path, state, SystemTime::now()) {
        log::warn!(
            "could not write connection status to {}: {e}",
            path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn scratch_dir() -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tutabridge_status_test_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn records_state_and_entry_time() {
        let dir = scratch_dir();
        let path = dir.join("status.json");
        let since = UNIX_EPOCH + Duration::from_secs(1_789_000_000);
        record(&path, WsState::Reconnecting, since).unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["tuta_connection"], "Reconnecting");
        assert_eq!(doc["since_unix"], 1_789_000_000u64);
        assert_eq!(doc["pid"], std::process::id());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_new_state_replaces_the_old_one() {
        let dir = scratch_dir();
        let path = dir.join("status.json");
        record(&path, WsState::Reconnecting, SystemTime::now()).unwrap();
        record(&path, WsState::Connected, SystemTime::now()).unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["tuta_connection"], "Connected");
        let leftovers: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(leftovers.len(), 1, "temp file left behind");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
