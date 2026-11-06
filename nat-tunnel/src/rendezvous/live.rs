//! Global status board decoupling the transport from the UI: the transport publishes the
//! runner's per-method [`Status`] here, the GUI reads a snapshot every frame.

use std::sync::RwLock;

use super::Status;

type Board = Vec<(&'static str, Status)>;

static HOST: RwLock<Board> = RwLock::new(Vec::new());
static GUEST: RwLock<Board> = RwLock::new(Vec::new());

/// `"host"` -> host board, anything else -> guest board.
fn board(session: &str) -> &'static RwLock<Board> {
    if session == "host" { &HOST } else { &GUEST }
}

/// Replace the whole board of `session` (`"host"` | `"guest"`).
pub fn publish(session: &'static str, statuses: Vec<(&'static str, Status)>) {
    if let Ok(mut b) = board(session).write() {
        *b = statuses;
    }
}

pub fn snapshot(session: &str) -> Vec<(&'static str, Status)> {
    board(session).read().map(|b| b.clone()).unwrap_or_default()
}

pub fn clear(session: &str) {
    if let Ok(mut b) = board(session).write() {
        b.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_snapshot_clear_per_session() {
        // Sessions are independent; one test owns both boards to avoid cross-test races.
        clear("host");
        clear("guest");
        publish("host", vec![("nostr", Status::Waiting), ("trk", Status::Starting)]);
        publish("guest", vec![("dht", Status::Failed("x".into()))]);
        assert_eq!(snapshot("host").len(), 2);
        assert_eq!(snapshot("guest"), vec![("dht", Status::Failed("x".into()))]);
        publish("host", vec![("nostr", Status::Publishing)]);
        assert_eq!(snapshot("host"), vec![("nostr", Status::Publishing)]);
        clear("host");
        assert!(snapshot("host").is_empty());
        assert_eq!(snapshot("guest").len(), 1);
        clear("guest");
    }
}
