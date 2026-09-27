//! A small stderr progress line (`42% · 1.2 GB / 3.0 GB · 850 MB/s`), shown only
//! when stderr is a terminal.

use std::io::{IsTerminal, Read, Write};
use std::time::{Duration, Instant};

/// Human-readable byte count (`1.5 MB`).
#[allow(clippy::cast_precision_loss)] // display only
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Progress state for one operation.
pub struct Progress {
    label: String,
    total: Option<u64>,
    done: u64,
    start: Instant,
    last: Option<Instant>,
    enabled: bool,
}

impl Progress {
    pub fn new(label: &str, total: Option<u64>, quiet: bool) -> Self {
        Progress {
            label: label.to_owned(),
            total,
            done: 0,
            start: Instant::now(),
            last: None,
            enabled: !quiet && std::io::stderr().is_terminal(),
        }
    }

    pub fn set(&mut self, done: u64) {
        self.done = done;
        if !self.enabled || self.start.elapsed() < Duration::from_millis(300) {
            return;
        }
        if self
            .last
            .is_some_and(|t| t.elapsed() < Duration::from_millis(100))
        {
            return;
        }
        self.last = Some(Instant::now());
        self.draw();
    }

    pub fn add(&mut self, n: u64) {
        self.set(self.done + n);
    }

    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn draw(&self) {
        let secs = self.start.elapsed().as_secs_f64().max(1e-3);
        let rate = human_bytes((self.done as f64 / secs) as u64);
        let line = match self.total {
            Some(t) if t > 0 => format!(
                "{} {:>3}% · {} / {} · {rate}/s",
                self.label,
                (self.done.min(t) * 100 / t),
                human_bytes(self.done),
                human_bytes(t)
            ),
            _ => format!("{} {} · {rate}/s", self.label, human_bytes(self.done)),
        };
        let mut err = std::io::stderr().lock();
        let _ = write!(err, "\r\x1b[2K{line}");
        let _ = err.flush();
    }

    /// Clear the progress line (if one was drawn).
    pub fn finish(&mut self) {
        if self.enabled && self.last.is_some() {
            let _ = write!(std::io::stderr().lock(), "\r\x1b[2K");
        }
    }
}

/// A reader that reports how many bytes passed through it.
pub struct Counting<'a, R: Read> {
    pub inner: R,
    pub progress: &'a mut Progress,
}

impl<R: Read> Read for Counting<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.progress.add(n as u64);
        Ok(n)
    }
}
