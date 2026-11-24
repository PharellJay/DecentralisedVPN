//! Recent log lines kept in memory, so the service's clients (the app) can
//! show them. `tracing` writes into a [`LogBuffer`] through [`MakeWriter`].

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;
use tracing_subscriber::fmt::MakeWriter;

pub const LOG_LINES: usize = 500;

#[derive(Clone)]
pub struct LogBuffer(Arc<Inner>);

struct Inner {
    lines: Mutex<Lines>,
    /// The number of lines ever written, for those waiting for new ones.
    written: watch::Sender<u64>,
}

#[derive(Default)]
struct Lines {
    recent: VecDeque<String>,
    /// The number of lines ever written; the last of `recent` is line `written - 1`.
    written: u64,
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self(Arc::new(Inner {
            lines: Mutex::default(),
            written: watch::Sender::new(0),
        }))
    }
}

impl LogBuffer {
    pub fn lines(&self) -> Vec<String> {
        self.0.lines.lock().expect("log lock").recent.iter().cloned().collect()
    }

    /// The number of lines written so far: a cursor for [`Self::since`].
    pub fn written(&self) -> u64 {
        self.0.lines.lock().expect("log lock").written
    }

    /// The lines written since `cursor` that are still kept, moving `cursor` past them.
    pub fn since(&self, cursor: &mut u64) -> Vec<String> {
        let lines = self.0.lines.lock().expect("log lock");
        let first_kept = lines.written - lines.recent.len() as u64;
        let skip = cursor.saturating_sub(first_kept).min(lines.recent.len() as u64) as usize;
        *cursor = lines.written;
        lines.recent.iter().skip(skip).cloned().collect()
    }

    /// Changes whenever lines are written.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.written.subscribe()
    }
}

pub struct LogWriter {
    buffer: LogBuffer,
    pending: Vec<u8>,
}

impl io::Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for LogWriter {
    fn drop(&mut self) {
        let text = String::from_utf8_lossy(&self.pending);
        let mut lines = self.buffer.0.lines.lock().expect("log lock");
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            lines.recent.push_back(line.trim_end().to_string());
            lines.written += 1;
        }
        while lines.recent.len() > LOG_LINES {
            lines.recent.pop_front();
        }
        let written = lines.written;
        drop(lines);
        self.buffer.0.written.send_if_modified(|w| std::mem::replace(w, written) != written);
    }
}

impl<'a> MakeWriter<'a> for LogBuffer {
    type Writer = LogWriter;
    fn make_writer(&'a self) -> LogWriter {
        LogWriter {
            buffer: self.clone(),
            pending: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_most_recent_lines() {
        use std::io::Write;
        let logs = LogBuffer::default();
        for i in 0..LOG_LINES + 10 {
            let mut writer = logs.make_writer();
            writeln!(writer, "line {i}").unwrap();
        }
        let lines = logs.lines();
        assert_eq!(lines.len(), LOG_LINES);
        assert_eq!(lines.last().unwrap(), &format!("line {}", LOG_LINES + 9));
    }

    #[test]
    fn hands_out_only_new_lines() {
        use std::io::Write;
        let logs = LogBuffer::default();
        let write = |text: &str| writeln!(logs.make_writer(), "{text}").unwrap();
        let mut cursor = logs.written();
        assert!(logs.since(&mut cursor).is_empty());
        write("a");
        write("b");
        assert_eq!(logs.since(&mut cursor), ["a", "b"]);
        assert!(logs.since(&mut cursor).is_empty());
        write("c");
        assert_eq!(logs.since(&mut cursor), ["c"]);
        // A reader that fell behind gets what is still kept.
        let mut behind = 0;
        for i in 0..LOG_LINES + 5 {
            write(&format!("line {i}"));
        }
        assert_eq!(logs.since(&mut behind).len(), LOG_LINES);
        assert_eq!(behind, logs.written());
    }
}
