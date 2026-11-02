//! Recent log lines kept in memory, so the dashboard and the service's clients can
//! show them. `tracing` writes into a [`LogBuffer`] through [`MakeWriter`].

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

pub const LOG_LINES: usize = 500;

#[derive(Clone, Default)]
pub struct LogBuffer(Arc<Mutex<VecDeque<String>>>);

impl LogBuffer {
    pub fn lines(&self) -> Vec<String> {
        self.0.lock().expect("log lock").iter().cloned().collect()
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
        let mut lines = self.buffer.0.lock().expect("log lock");
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            lines.push_back(line.trim_end().to_string());
        }
        while lines.len() > LOG_LINES {
            lines.pop_front();
        }
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
}
