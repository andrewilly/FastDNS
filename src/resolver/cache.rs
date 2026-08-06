//! DNS response cache with TTL management and serve-stale (RFC 8767) support.
#![allow(dead_code)]

use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use lru::LruCache;
use tracing::{debug, trace};

use crate::dns::types::{self, ResourceRecord};

/// Maximum number of entries in the cache
const MAX_CACHE_ENTRIES: usize = 100_000;

/// How long stale entries are kept before being purged (RFC 8767 recommends
/// at least 24 hours for stale answers, but we use 6 hours to balance memory).
const STALE_MAX_AGE: Duration = Duration::from_secs(6 * 3600);

/// Maximum number of stale entries to keep (same as main cache, avoids unbounded growth).
const STALE_MAX_ENTRIES: usize = 50_000;

/// Maximum number of records stored per cache key.
/// Prevents a single (name, type, class) key from accumulating an unbounded
/// Vec of duplicate/large records (RRSIG, DNSKEY, HTTPS, TXT...), which is a
/// primary driver of memory growth over hours of operation.
const MAX_RECORDS_PER_KEY: usize = 16;

/// A cached entry with expiry tracking
#[derive(Debug, Clone)]
struct CacheEntry {
    record: ResourceRecord,
    expires_at: Instant,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    fn ttl_remaining(&self) -> u32 {
        let remaining = self.expires_at.saturating_duration_since(Instant::now());
        remaining.as_secs() as u32
    }
}

/// DNS cache that stores resource records by (name, type, class).
///
/// Supports serve-stale (RFC 8767): when a record expires and the resolver
/// cannot refresh it, the stale record can still be served to avoid failures.
#[derive(Debug)]
pub struct DnsCache {
    /// Key: (encoded_name, rtype, rclass) -> Vec of cached records
    /// LRU eviction is handled by the LruCache internals.
    entries: LruCache<(Vec<u8>, u16, u16), Vec<CacheEntry>>,
    /// Stale (expired) entries kept for serve-stale.
    /// Capacity-limited to prevent unbounded memory growth.
    stale_entries: LruCache<(Vec<u8>, u16, u16), Vec<CacheEntry>>,
    max_entries: usize,
    hits: u64,
    misses: u64,
}

impl DnsCache {
    pub fn new() -> Self {
        let cap = NonZeroUsize::new(MAX_CACHE_ENTRIES).expect("MAX_CACHE_ENTRIES > 0");
        let stale_cap = NonZeroUsize::new(STALE_MAX_ENTRIES).expect("STALE_MAX_ENTRIES > 0");
        DnsCache {
            entries: LruCache::new(cap),
            stale_entries: LruCache::new(stale_cap),
            max_entries: MAX_CACHE_ENTRIES,
            hits: 0,
            misses: 0,
        }
    }

    pub fn with_max_entries(max: usize) -> Self {
        let cap = NonZeroUsize::new(max.max(1)).expect("cache size > 0");
        let stale_cap = NonZeroUsize::new((max / 5).clamp(1000, STALE_MAX_ENTRIES))
            .expect("stale cache size > 0");
        DnsCache {
            entries: LruCache::new(cap),
            stale_entries: LruCache::new(stale_cap),
            max_entries: max,
            hits: 0,
            misses: 0,
        }
    }

    /// Insert a resource record into the cache.
    pub fn insert(
        &mut self,
        name: Vec<u8>,
        rtype: u16,
        rclass: u16,
        ttl: u32,
        rdata: Vec<u8>,
        rdlength: u16,
    ) {
        if ttl == 0 {
            return; // Don't cache zero-TTL records
        }

        // Clamp TTL to reasonable maximum (24 hours)
        let ttl = ttl.min(86400);
        let expires_at = Instant::now() + Duration::from_secs(ttl as u64);

        let record = ResourceRecord {
            name: name.clone(),
            rtype,
            rclass,
            ttl,
            rdlength,
            rdata,
            parsed: None,
        };

        let key = (name, rtype, rclass);
        let entry = CacheEntry { record, expires_at };

        // lru::LruCache doesn't have entry() API, use get_mut + put.
        // Bounded per key: dedupe identical rdata and cap the Vec length so a
        // single key cannot accumulate unbounded records over time.
        match self.entries.get_mut(&key) {
            Some(vec) => {
                // Skip duplicates (same rdata) to avoid unbounded growth.
                if vec.iter().any(|e| e.record.rdata == entry.record.rdata) {
                    return;
                }
                if vec.len() >= MAX_RECORDS_PER_KEY {
                    // Replace the oldest record with the new one.
                    vec.remove(0);
                }
                vec.push(entry);
            }
            None => {
                self.entries.put(key, vec![entry]);
            }
        }

        trace!(?ttl, "cached DNS record");
    }

    /// Lookup records for a given (name, type, class).
    /// Returns (records, ttl) where ttl is the minimum remaining TTL.
    /// Expired records are automatically moved to the stale store.
    pub fn lookup(
        &mut self,
        name: &[u8],
        rtype: u16,
        rclass: u16,
    ) -> Option<(Vec<ResourceRecord>, u32)> {
        let key = (name.to_vec(), rtype, rclass);
        if let Some(entries) = self.entries.get_mut(&key) {
            // Separate expired entries into the stale store
            let mut fresh: Vec<CacheEntry> = Vec::new();
            let mut stale: Vec<CacheEntry> = Vec::new();
            for e in entries.drain(..) {
                if e.is_expired() {
                    stale.push(e);
                } else {
                    fresh.push(e);
                }
            }
            // Keep stale entries for serve-stale (bounded by LruCache capacity)
            if !stale.is_empty() {
                self.stale_entries.put(key.clone(), stale);
            }

            if fresh.is_empty() {
                self.entries.pop_entry(&key);
                self.misses += 1;
                debug!(
                    "cache MISS (expired) for {} type={}",
                    types::labels_to_string(name),
                    rtype
                );
                return None;
            }

            *entries = fresh;

            let mut min_ttl = u32::MAX;
            let records: Vec<ResourceRecord> = entries
                .iter()
                .map(|e| {
                    let ttl_rem = e.ttl_remaining();
                    min_ttl = min_ttl.min(ttl_rem);
                    let mut rec = e.record.clone();
                    rec.ttl = ttl_rem;
                    rec
                })
                .collect();

            self.hits += 1;
            debug!(
                "cache HIT for {} type={} ({} records, TTL={})",
                types::labels_to_string(name),
                rtype,
                records.len(),
                min_ttl
            );
            Some((records, min_ttl))
        } else {
            self.misses += 1;
            debug!(
                "cache MISS for {} type={}",
                types::labels_to_string(name),
                rtype
            );
            None
        }
    }

    /// Lookup stale (expired) records for serve-stale (RFC 8767).
    /// Returns records with TTL=0 to indicate they are stale.
    /// The caller should only use these if a fresh resolution fails.
    pub fn lookup_stale(
        &mut self,
        name: &[u8],
        rtype: u16,
        rclass: u16,
    ) -> Option<Vec<ResourceRecord>> {
        let key = (name.to_vec(), rtype, rclass);
        if let Some(entries) = self.stale_entries.get(&key) {
            // Remove entries that are too old even for stale serving
            let now = Instant::now();
            let usable: Vec<&CacheEntry> = entries
                .iter()
                .filter(|e| now.duration_since(e.expires_at) < STALE_MAX_AGE)
                .collect();

            if usable.is_empty() {
                self.stale_entries.pop_entry(&key);
                return None;
            }

            let records: Vec<ResourceRecord> = usable
                .iter()
                .map(|e| {
                    let mut rec = e.record.clone();
                    rec.ttl = 0; // Mark as stale
                    rec
                })
                .collect();

            debug!(
                "serve-stale for {} type={} ({} records)",
                types::labels_to_string(name),
                rtype,
                records.len()
            );
            Some(records)
        } else {
            None
        }
    }

    /// Insert a batch of records, preserving each record's own name/type/class.
    pub fn insert_records(&mut self, records: &[ResourceRecord]) {
        for rec in records {
            self.insert(
                rec.name.clone(),
                rec.rtype,
                rec.rclass,
                rec.ttl,
                rec.rdata.clone(),
                rec.rdlength,
            );
        }
    }

    /// Purge expired entries from the stale store.
    /// Now called on every insert to keep memory bounded.
    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        let too_old: Vec<(Vec<u8>, u16, u16)> = self
            .stale_entries
            .iter()
            .filter(|(_, entries)| {
                entries
                    .iter()
                    .all(|e| now.duration_since(e.expires_at) >= STALE_MAX_AGE)
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in too_old {
            self.stale_entries.pop_entry(&key);
        }
    }

    /// Clear all entries from the cache (including stale entries).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.stale_entries.clear();
        self.hits = 0;
        self.misses = 0;
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.stale_entries.is_empty()
    }

    pub fn stale_len(&self) -> usize {
        self.stale_entries.len()
    }

    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    pub fn hits(&self) -> u64 {
        self.hits
    }

    pub fn misses(&self) -> u64 {
        self.misses
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}
