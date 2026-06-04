// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! A dependency-free, persistent file-backed [`Store`] (spec §III.A/C).
//!
//! The default build is `std`-only, so the durable backend here uses the
//! filesystem directly rather than an embedded KV (that is [`crate::RocksStore`],
//! behind the optional `rocksdb` feature). Each column family is a directory
//! under the store root and each key is a file (its name the hex of the key, its
//! contents the raw value); an in-memory [`MemoryStore`] mirror — loaded once at
//! [`FileStore::open`] and kept in sync — serves reads, so `get`/`scan`/`count`
//! never touch the disk.
//!
//! The handle is cloneable and thread-safe (`Arc<Mutex<…>>`), so it shares one
//! dataset across the transport's connection threads, like [`crate::SharedStore`]
//! but durable. Writes hold the lock across the mirror update and the file write,
//! so they are serialised and crash-consistent per key (a temp file is renamed
//! into place). The [`Store`] contract is infallible, so a transient I/O error on
//! a write is swallowed (mirroring [`crate::RocksStore`]); the mirror still
//! reflects it for this process.

use crate::{MemoryStore, Store};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// A persistent, cloneable, thread-safe file-backed store.
#[derive(Clone, Debug)]
pub struct FileStore {
    root: PathBuf,
    mem: Arc<Mutex<MemoryStore>>,
}

impl FileStore {
    /// Open (creating if absent) a store rooted at `root`, loading any data
    /// already persisted there into the in-memory mirror.
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;

        let mut mem = MemoryStore::default();
        for cf_entry in std::fs::read_dir(&root)? {
            let cf_entry = cf_entry?;
            if !cf_entry.file_type()?.is_dir() {
                continue;
            }
            let cf = cf_entry.file_name().to_string_lossy().into_owned();
            for key_entry in std::fs::read_dir(cf_entry.path())? {
                let key_entry = key_entry?;
                if !key_entry.file_type()?.is_file() {
                    continue;
                }
                let file_name = key_entry.file_name().to_string_lossy().into_owned();
                // Skip in-progress temp files and unparseable names.
                let Some(key) = hex_decode(&file_name) else {
                    continue;
                };
                let value = std::fs::read(key_entry.path())?;
                mem.put(&cf, &key, &value);
            }
        }

        Ok(Self {
            root,
            mem: Arc::new(Mutex::new(mem)),
        })
    }

    fn lock(&self) -> MutexGuard<'_, MemoryStore> {
        self.mem.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Write `value` for `(cf, key)` to disk, atomically (temp file + rename).
    fn persist_put(&self, cf: &str, key: &str, value: &[u8]) -> std::io::Result<()> {
        let dir = self.root.join(cf);
        std::fs::create_dir_all(&dir)?;
        let name = hex_encode(key.as_bytes());
        let path = dir.join(&name);
        let tmp = dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, value)?;
        std::fs::rename(&tmp, &path)
    }

    /// Remove the on-disk file for `(cf, key)`, if any.
    fn persist_delete(&self, cf: &str, key: &str) {
        let path = self.root.join(cf).join(hex_encode(key.as_bytes()));
        let _ = std::fs::remove_file(path);
    }
}

impl Store for FileStore {
    fn put(&mut self, cf: &str, key: &str, value: &[u8]) {
        let mut mem = self.lock();
        mem.put(cf, key, value);
        // Best-effort, like RocksStore: the Store contract is infallible.
        let _ = self.persist_put(cf, key, value);
    }

    fn delete(&mut self, cf: &str, key: &str) {
        let mut mem = self.lock();
        mem.delete(cf, key);
        self.persist_delete(cf, key);
    }

    fn get(&self, cf: &str, key: &str) -> Option<Vec<u8>> {
        self.lock().get(cf, key)
    }

    fn scan(&self, cf: &str) -> Vec<(String, Vec<u8>)> {
        self.lock().scan(cf)
    }

    fn count(&self, cf: &str) -> usize {
        self.lock().count(cf)
    }
}

/// Lowercase hex of `bytes` (a filesystem-safe, reversible key encoding).
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    out
}

/// Decode a hex filename back to the original key string, or `None` if it is not
/// valid hex of UTF-8 (e.g. a temp file).
fn hex_decode(s: &str) -> Option<String> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let chars: Vec<char> = s.chars().collect();
    for pair in chars.chunks(2) {
        let hi = pair[0].to_digit(16)?;
        let lo = pair[1].to_digit(16)?;
        bytes.push((hi * 16 + lo) as u8);
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let mut path = std::env::temp_dir();
            path.push(format!("gm-store-file-{}-{nanos}", std::process::id()));
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn hex_round_trips_keys_with_separators() {
        let key = "!room:gaussian.tech\u{1f}m.room.member\u{1f}@a:b";
        assert_eq!(
            hex_decode(&hex_encode(key.as_bytes())).as_deref(),
            Some(key)
        );
    }

    #[test]
    fn data_survives_reopen() {
        let tmp = TempDir::new();
        {
            let mut store = FileStore::open(&tmp.0).unwrap();
            store.put(cf::EVENTS, "!r:x\u{1f}k", b"v1");
            store.put(cf::ROOM_STATE, "s", b"v2");
            store.delete(cf::EVENTS, "gone"); // no-op
        }
        // Re-open the same directory: writes are durable and isolated by cf.
        let store = FileStore::open(&tmp.0).unwrap();
        assert_eq!(store.get(cf::EVENTS, "!r:x\u{1f}k"), Some(b"v1".to_vec()));
        assert_eq!(store.get(cf::ROOM_STATE, "s"), Some(b"v2".to_vec()));
        assert_eq!(store.count(cf::EVENTS), 1);
        assert!(store.get(cf::EVENTS, "missing").is_none());
    }

    #[test]
    fn delete_removes_from_disk_too() {
        let tmp = TempDir::new();
        {
            let mut store = FileStore::open(&tmp.0).unwrap();
            store.put(cf::EVENTS, "k", b"v");
            store.delete(cf::EVENTS, "k");
        }
        let store = FileStore::open(&tmp.0).unwrap();
        assert!(store.get(cf::EVENTS, "k").is_none());
    }

    #[test]
    fn clones_share_one_dataset_and_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FileStore>();

        let tmp = TempDir::new();
        let store = FileStore::open(&tmp.0).unwrap();
        let mut a = store.clone();
        a.put(cf::EVENTS, "k", b"v");
        // Visible through the original handle (same underlying dataset).
        assert_eq!(store.get(cf::EVENTS, "k"), Some(b"v".to_vec()));
    }

    #[test]
    fn concurrent_writers_persist_every_entry() {
        let tmp = TempDir::new();
        let store = FileStore::open(&tmp.0).unwrap();
        let mut handles = Vec::new();
        for t in 0..4 {
            let mut store = store.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..50 {
                    store.put(cf::EVENTS, &format!("{t}-{i}"), b"v");
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Re-open from disk: all 200 entries were persisted.
        let reopened = FileStore::open(&tmp.0).unwrap();
        assert_eq!(reopened.count(cf::EVENTS), 200);
    }
}
