use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::UdpSocket;
use simple_dns::{
    rdata::{RData, A, TYPE},
    Packet, PacketFlag, ResourceRecord, CLASS, QTYPE, RCODE,
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use bandwidth::BandwidthStats;
use tor::TorManager;

/// Manages .onion hostname ↔ synthetic IP mappings with an embedded allocator.
///
/// Each VPN session creates a fresh `OnionState`, so the IP counter automatically
/// resets between sessions without global state.
pub struct OnionState {
    map: DashMap<String, Ipv4Addr>,
    counter: AtomicU32,
}

impl Default for OnionState {
    fn default() -> Self {
        Self::new()
    }
}

impl OnionState {
    pub fn new() -> Self {
        Self {
            map: DashMap::new(),
            counter: AtomicU32::new(1),
        }
    }

    /// Allocate the next synthetic IP in the 10.254.0.0/16 range.
    /// Returns `None` if the address space is exhausted (65535 addresses).
    ///
    /// Uses `fetch_update` (CAS loop) to stop incrementing at the limit,
    /// preventing the counter from growing unboundedly after exhaustion.
    fn allocate_ip(&self) -> Option<Ipv4Addr> {
        let n = self
            .counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (1..=65535).contains(&current).then_some(current + 1)
            })
            .ok()?;
        Some(Ipv4Addr::new(10, 254, (n >> 8) as u8, n as u8))
    }

    /// Get the existing synthetic IP for a .onion hostname, or allocate a new one.
    ///
    /// Uses DashMap's entry API to make the check-and-insert atomic,
    /// preventing wasted IP allocations from concurrent requests.
    pub fn get_or_allocate(&self, hostname: &str) -> anyhow::Result<Ipv4Addr> {
        use dashmap::mapref::entry::Entry;
        match self.map.entry(hostname.to_string()) {
            Entry::Occupied(e) => Ok(*e.get()),
            Entry::Vacant(e) => {
                let ip = self.allocate_ip().ok_or_else(|| {
                    anyhow::anyhow!(".onion IP address space exhausted (10.254.0.0/16)")
                })?;
                tracing::debug!(hostname = %hostname, ip = %ip, "Allocated synthetic IP for .onion");
                Ok(*e.insert(ip))
            }
        }
    }

    /// Reverse-lookup: find the .onion hostname for a synthetic IP.
    /// O(n) scan — acceptable since the map is small (typically <100 entries).
    pub fn lookup_by_ip(&self, ip: Ipv4Addr) -> Option<String> {
        self.map
            .iter()
            .find(|entry| *entry.value() == ip)
            .map(|entry| entry.key().clone())
    }
}

/// Maps .onion hostnames to synthetic IPs (10.254.x.x).
/// Single source of truth for .onion ↔ IP mapping.
pub type OnionMap = Arc<OnionState>;

/// Create a new OnionMap with a fresh IP counter.
pub fn new_onion_map() -> OnionMap {
    Arc::new(OnionState::new())
}

/// Shared context for DNS and TCP handlers.
#[derive(Clone)]
pub struct HandlerCtx {
    pub tor: Arc<TorManager>,
    pub onion_map: OnionMap,
    pub dns_cache: DnsCache,
    pub dns_cache_ttl: u32,
    pub stats: Arc<BandwidthStats>,
    pub cancel: CancellationToken,
}

/// Concurrent DNS cache with built-in TTL expiry and LRU eviction (via moka).
/// Each entry stores the resolved IPs and the insertion time, so cached responses
/// can report an accurate remaining TTL instead of always returning the max TTL.
pub type DnsCache = Arc<moka::sync::Cache<String, (Vec<Ipv4Addr>, Instant)>>;

const DNS_CACHE_MAX_ENTRIES: u64 = 4096;

/// Create a new DNS cache with the given TTL and capacity limits.
pub fn new_dns_cache(ttl_secs: u32) -> DnsCache {
    Arc::new(
        moka::sync::Cache::builder()
            .max_capacity(DNS_CACHE_MAX_ENTRIES)
            .time_to_live(Duration::from_secs(ttl_secs as u64))
            .build(),
    )
}

/// Check if an IP is in the synthetic .onion range (10.254.0.0/16).
pub fn is_onion_ip(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 10 && ip.octets()[1] == 254
}

/// Run the DNS/UDP handler.
///
/// - Port 53 packets: parse DNS queries, resolve through Tor or handle .onion mapping
/// - Non-port-53 UDP: log and drop (Tor doesn't support arbitrary UDP)
pub async fn run_dns_handler(udp_socket: UdpSocket, ctx: HandlerCtx, max_dns_queries: usize) {
    let semaphore = Arc::new(Semaphore::new(max_dns_queries));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let (mut read_half, mut write_half) = udp_socket.split();

    // Writer task: sends DNS responses back through the stack
    let cancel_writer = ctx.cancel.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = cancel_writer.cancelled() => break,
                msg = rx.recv() => {
                    match msg {
                        Some(msg) => {
                            if let Err(e) = write_half.send(msg).await {
                                tracing::warn!(error = %e, "DNS response send error");
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    // Reader loop: receives UDP packets from the stack
    loop {
        tokio::select! {
            biased;
            _ = ctx.cancel.cancelled() => break,
            pkt = read_half.next() => {
                let Some((data, src_addr, dst_addr)) = pkt else {
                    break;
                };

                // Only handle DNS (port 53)
                if dst_addr.port() != 53 {
                    tracing::trace!(src = %src_addr, dst = %dst_addr, "Dropping non-DNS UDP packet (Tor doesn't support UDP)");
                    continue;
                }

                let ctx = ctx.clone();
                let tx = tx.clone();

                // Acquire permit before spawn to apply backpressure to the reader
                let permit = tokio::select! {
                    biased;
                    _ = ctx.cancel.cancelled() => break,
                    permit = semaphore.clone().acquire_owned() => {
                        match permit {
                            Ok(p) => p,
                            Err(_) => break, // semaphore closed
                        }
                    }
                };

                tokio::spawn(async move {
                    let _permit = permit;
                    // Bandwidth: counts local DNS query/response sizes, not Tor resolve traffic.
                    // TCP connections use CountingIo on the Tor stream for accurate byte tracking.
                    ctx.stats.add_tx(data.len() as u64);
                    match handle_dns_query(&data, &ctx.tor, &ctx.onion_map, &ctx.dns_cache, ctx.dns_cache_ttl).await {
                        Ok(response) => {
                            ctx.stats.add_rx(response.len() as u64);
                            // Send response back: swap src/dst
                            let _ = tx.send((response, dst_addr, src_addr));
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "DNS query handling failed");
                            // Send SERVFAIL response
                            if let Some(response) = build_servfail(&data) {
                                ctx.stats.add_rx(response.len() as u64);
                                let _ = tx.send((response, dst_addr, src_addr));
                            }
                        }
                    }
                });
            }
        }
    }

    tracing::debug!("DNS handler stopped");
}

/// Handle a single DNS query: parse, resolve (with cache), build response.
pub async fn handle_dns_query(
    data: &[u8],
    tor: &TorManager,
    onion_map: &OnionState,
    dns_cache: &DnsCache,
    dns_cache_ttl: u32,
) -> anyhow::Result<Vec<u8>> {
    let packet = match Packet::parse(data) {
        Ok(p) => p,
        Err(_) => {
            // Genuinely malformed — return SERVFAIL or raw empty
            return Ok(build_servfail(data).unwrap_or_else(|| build_raw_empty(data)));
        }
    };

    let question = packet
        .questions
        .first()
        .ok_or_else(|| anyhow::anyhow!("DNS query has no questions"))?;

    let qname = question.qname.to_string();

    tracing::debug!(name = %qname, qtype = ?question.qtype, "DNS query");

    // Handle .onion domains: allocate synthetic IP
    if qname.ends_with(".onion") || qname.ends_with(".onion.") {
        let hostname = qname.trim_end_matches('.').to_string();

        if matches!(question.qtype, QTYPE::TYPE(TYPE::A)) {
            let ip = onion_map.get_or_allocate(&hostname)?;
            return Ok(build_a_response(data, &[ip], 300));
        }

        // For AAAA or other types on .onion, return empty answer
        return Ok(build_empty_response(data));
    }

    // AAAA queries: return empty immediately (IPv6/AAAA not supported via Tor)
    // Must be checked before the cache to avoid returning cached A records for AAAA queries.
    if matches!(question.qtype, QTYPE::TYPE(TYPE::AAAA)) {
        return Ok(build_empty_response(data));
    }

    // Regular domain: check cache, then resolve through Tor
    if matches!(question.qtype, QTYPE::TYPE(TYPE::A) | QTYPE::ANY) {
        // Check cache first (moka handles TTL expiry automatically)
        if let Some((ips, inserted_at)) = dns_cache.get(&qname) {
            // Compute remaining TTL so clients don't cache longer than we do
            let elapsed = inserted_at.elapsed().as_secs() as u32;
            let remaining_ttl = dns_cache_ttl.saturating_sub(elapsed).max(1);
            return Ok(build_a_response(data, &ips, remaining_ttl));
        }

        match tor.resolve_dns(&qname).await {
            Ok(addrs) => {
                let v4_addrs: Vec<Ipv4Addr> = addrs
                    .iter()
                    .filter_map(|a| match a {
                        std::net::IpAddr::V4(v4) => Some(*v4),
                        _ => None,
                    })
                    .collect();

                if v4_addrs.is_empty() {
                    return Ok(build_empty_response(data));
                }

                // Cache the result with insertion time (moka handles eviction automatically)
                dns_cache.insert(qname, (v4_addrs.clone(), Instant::now()));

                Ok(build_a_response(data, &v4_addrs, dns_cache_ttl))
            }
            Err(e) => {
                // Log at debug — per-query failures are expected during Tor issues.
                // The bootstrap watcher handles sustained failures by restarting the session.
                // SERVFAIL tells clients to retry later (1-5s backoff).
                // NXDOMAIN would cause negative caching ("domain doesn't exist" for minutes).
                tracing::debug!(name = %qname, error = %e, "Tor DNS resolution failed");
                Ok(build_servfail(data).unwrap_or_else(|| build_raw_empty(data)))
            }
        }
    } else {
        // Unsupported query type: return empty response
        Ok(build_empty_response(data))
    }
}

/// Build a DNS A record response via simple-dns Packet API.
fn build_a_response(query: &[u8], ips: &[Ipv4Addr], ttl: u32) -> Vec<u8> {
    if query.len() < 12 {
        return query.to_vec();
    }
    let Ok(parsed) = Packet::parse(query) else {
        return build_raw_empty(query);
    };
    if parsed.questions.is_empty() {
        return build_raw_empty(query);
    }
    let mut reply = parsed.into_reply();
    reply.set_flags(PacketFlag::RECURSION_AVAILABLE);
    reply.additional_records.clear();

    let qname = reply.questions[0].qname.clone();
    for ip in ips {
        reply.answers.push(ResourceRecord::new(
            qname.clone(),
            CLASS::IN,
            ttl,
            RData::A(A::from(*ip)),
        ));
    }

    reply
        .build_bytes_vec()
        .unwrap_or_else(|_| build_raw_empty(query))
}

/// Build a DNS reply with the given RCODE, stripping EDNS OPT records.
/// Returns `None` if the query is too short or unparseable.
fn build_reply(query: &[u8], rcode: RCODE) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut reply = Packet::parse(query).ok()?.into_reply();
    reply.set_flags(PacketFlag::RECURSION_AVAILABLE);
    *reply.rcode_mut() = rcode;
    reply.additional_records.clear();
    reply.build_bytes_vec().ok()
}

/// Build a DNS SERVFAIL response.
pub fn build_servfail(query: &[u8]) -> Option<Vec<u8>> {
    build_reply(query, RCODE::ServerFailure)
}

/// Build an empty (no answers) DNS response.
fn build_empty_response(query: &[u8]) -> Vec<u8> {
    build_reply(query, RCODE::NoError).unwrap_or_else(|| build_raw_empty(query))
}

/// Raw-byte fallback for building an empty DNS response when simple-dns cannot parse the query.
/// Copies the full query (including question section) and sets response flags with zero answer counts.
fn build_raw_empty(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return query.to_vec();
    }
    let mut r = query.to_vec();
    r[2] = 0x81; // QR=1, RD=1
    r[3] = 0x80; // RA=1, RCODE=0
                 // Zero out ANCOUNT, NSCOUNT, ARCOUNT (bytes 6-11), preserve QDCOUNT (bytes 4-5)
    r[6..12].fill(0);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- helpers ----

    /// Build a full DNS query for `example.com` type A.
    fn example_com_query() -> Vec<u8> {
        #[rustfmt::skip]
        let query = vec![
            0xAB, 0xCD, // ID
            0x01, 0x00, // Flags: RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
            // QNAME: example.com
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm',
            0,          // null terminator
            0x00, 0x01, // QTYPE=A
            0x00, 0x01, // QCLASS=IN
        ];
        query
    }

    /// Build an example.com A query with an EDNS OPT record in the additional section.
    fn example_com_query_with_edns() -> Vec<u8> {
        #[rustfmt::skip]
        let query = vec![
            0xAB, 0xCD, // ID
            0x01, 0x20, // Flags: RD=1, AD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x01, // ARCOUNT=1 (OPT record)
            // QNAME: example.com
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm',
            0,          // null terminator
            0x00, 0x01, // QTYPE=A
            0x00, 0x01, // QCLASS=IN
            // OPT record (EDNS)
            0x00,       // NAME: root
            0x00, 0x29, // TYPE: OPT (41)
            0x10, 0x00, // CLASS: UDP payload size 4096
            0x00, 0x00, 0x00, 0x00, // TTL: extended RCODE + flags
            0x00, 0x00, // RDLENGTH: 0
        ];
        query
    }

    /// Build a DNS query for `example.com` type AAAA.
    fn example_com_aaaa_query() -> Vec<u8> {
        #[rustfmt::skip]
        let query = vec![
            0xAB, 0xCD, // ID
            0x01, 0x00, // Flags: RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
            // QNAME: example.com
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm',
            0,          // null terminator
            0x00, 0x1C, // QTYPE=AAAA (28)
            0x00, 0x01, // QCLASS=IN
        ];
        query
    }

    #[test]
    fn test_allocate_onion_ip() {
        let state = OnionState::new();
        let ip1 = state.allocate_ip().expect("should allocate");
        let ip2 = state.allocate_ip().expect("should allocate");
        assert!(is_onion_ip(ip1));
        assert!(is_onion_ip(ip2));
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_is_onion_ip() {
        assert!(is_onion_ip(Ipv4Addr::new(10, 254, 0, 1)));
        assert!(is_onion_ip(Ipv4Addr::new(10, 254, 255, 255)));
        assert!(!is_onion_ip(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_onion_ip(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_build_a_response() {
        let query = example_com_query();
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let response = build_a_response(&query, &[ip], 60);

        assert_eq!(response[0], 0xAB);
        assert_eq!(response[1], 0xCD);

        let parsed = Packet::parse(&response).expect("response should be valid DNS");
        assert!(parsed.has_flags(PacketFlag::RESPONSE));
        assert!(parsed.has_flags(PacketFlag::RECURSION_AVAILABLE));
        assert_eq!(parsed.rcode(), RCODE::NoError);
        assert_eq!(parsed.answers.len(), 1);
        match &parsed.answers[0].rdata {
            RData::A(a) => assert_eq!(Ipv4Addr::from(a.address), ip),
            other => panic!("expected A record, got {other:?}"),
        }
    }

    #[test]
    fn test_build_reply_with_name_error() {
        let query = example_com_query();
        let response = build_reply(&query, RCODE::NameError).expect("should parse valid query");
        let parsed = Packet::parse(&response).expect("response should be valid DNS");
        assert!(parsed.has_flags(PacketFlag::RESPONSE));
        assert_eq!(parsed.rcode(), RCODE::NameError);
        assert!(parsed.answers.is_empty());
        assert!(parsed.additional_records.is_empty());
    }

    #[test]
    fn test_build_reply_short_query_returns_none() {
        assert!(build_reply(&[], RCODE::NoError).is_none());
        assert!(build_reply(&[0x00; 11], RCODE::NoError).is_none());
    }

    #[test]
    fn test_build_reply_strips_edns_opt() {
        let query = example_com_query_with_edns();
        let response = build_reply(&query, RCODE::NoError).expect("should parse valid query");
        let parsed = Packet::parse(&response).expect("response should be valid DNS");
        assert!(
            parsed.additional_records.is_empty(),
            "EDNS OPT should be stripped"
        );
        assert_eq!(parsed.rcode(), RCODE::NoError);
    }

    #[test]
    fn test_build_servfail_valid_query() {
        let mut query = example_com_query();
        query[0] = 0xDE;
        query[1] = 0xAD;
        let result = build_servfail(&query);
        assert!(result.is_some(), "should return Some for a valid query");
        let response = result.unwrap();
        let parsed = Packet::parse(&response).expect("response should be valid DNS");
        assert_eq!(parsed.id(), 0xDEAD);
        assert!(parsed.has_flags(PacketFlag::RESPONSE));
        assert!(parsed.has_flags(PacketFlag::RECURSION_AVAILABLE));
        assert_eq!(parsed.rcode(), RCODE::ServerFailure);
        assert!(parsed.answers.is_empty());
        assert!(parsed.additional_records.is_empty());
    }

    #[test]
    fn test_build_servfail_short_query_returns_none() {
        assert!(build_servfail(&[]).is_none());
        assert!(build_servfail(&[0x00; 11]).is_none());
    }

    #[test]
    fn test_build_servfail_exactly_12_bytes() {
        let query = [0u8; 12];
        assert!(build_servfail(&query).is_some());
    }

    #[test]
    fn test_build_empty_response_valid_query() {
        let mut query = example_com_query();
        query[0] = 0xBE;
        query[1] = 0xEF;
        let response = build_empty_response(&query);
        let parsed = Packet::parse(&response).expect("response should be valid DNS");
        assert_eq!(parsed.id(), 0xBEEF);
        assert!(parsed.has_flags(PacketFlag::RESPONSE));
        assert!(parsed.has_flags(PacketFlag::RECURSION_AVAILABLE));
        assert_eq!(parsed.rcode(), RCODE::NoError);
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn test_build_empty_response_short_query_returns_original() {
        let short = vec![0x01, 0x02, 0x03];
        let response = build_empty_response(&short);
        assert_eq!(response, short);
    }

    #[test]
    fn test_build_empty_response_no_answers() {
        let query = example_com_query();
        let response = build_empty_response(&query);
        let parsed = Packet::parse(&response).expect("response should be valid DNS");
        assert!(parsed.answers.is_empty(), "no records should be appended");
    }

    #[test]
    fn test_build_a_response_multiple_ips() {
        let query = example_com_query();
        let ips = [
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 0, 0, 1),
            Ipv4Addr::new(8, 8, 8, 8),
        ];
        let response = build_a_response(&query, &ips, 300);
        let parsed = Packet::parse(&response).expect("response should be valid DNS");
        assert_eq!(parsed.answers.len(), ips.len());

        for (i, ip) in ips.iter().enumerate() {
            match &parsed.answers[i].rdata {
                RData::A(a) => assert_eq!(Ipv4Addr::from(a.address), *ip),
                other => panic!("expected A record, got {other:?}"),
            }
            assert_eq!(parsed.answers[i].ttl, 300);
        }
    }

    #[test]
    fn test_build_a_response_preserves_id_and_question() {
        let query = example_com_query();
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let response = build_a_response(&query, &[ip], 60);
        let parsed = Packet::parse(&response).expect("response should be valid DNS");
        assert_eq!(parsed.id(), 0xABCD);
        assert_eq!(parsed.questions.len(), 1);
        assert!(matches!(parsed.questions[0].qtype, QTYPE::TYPE(TYPE::A)));
    }

    #[test]
    fn test_build_a_response_ttl_encoded_correctly() {
        let query = example_com_query();
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let ttl: u32 = 86400;
        let response = build_a_response(&query, &[ip], ttl);
        let parsed = Packet::parse(&response).expect("response should be valid DNS");
        assert_eq!(parsed.answers[0].ttl, ttl);
    }

    #[test]
    fn test_build_a_response_short_query_returns_original() {
        let short = vec![0x00, 0x01, 0x02];
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let response = build_a_response(&short, &[ip], 60);
        assert_eq!(response, short);
    }

    #[test]
    fn test_is_onion_ip_boundary_values() {
        assert!(is_onion_ip(Ipv4Addr::new(10, 254, 0, 0)));
        assert!(is_onion_ip(Ipv4Addr::new(10, 254, 0, 255)));
        assert!(is_onion_ip(Ipv4Addr::new(10, 254, 128, 1)));
        assert!(!is_onion_ip(Ipv4Addr::new(10, 253, 0, 1)));
        assert!(!is_onion_ip(Ipv4Addr::new(10, 255, 0, 1)));
        assert!(!is_onion_ip(Ipv4Addr::new(11, 254, 0, 1)));
    }

    #[test]
    fn test_allocated_onion_ips_are_in_range() {
        let state = OnionState::new();
        for _ in 0..64 {
            let ip = state
                .allocate_ip()
                .expect("should allocate within test range");
            assert!(
                is_onion_ip(ip),
                "allocated IP {ip} is outside the 10.254.0.0/16 onion range"
            );
        }
    }

    #[test]
    fn test_build_servfail_malformed_zero_bytes() {
        assert!(build_servfail(&[]).is_none());
    }

    #[test]
    fn test_build_servfail_malformed_one_byte() {
        assert!(build_servfail(&[0xFF]).is_none());
    }

    #[test]
    fn test_build_empty_response_malformed_five_bytes() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let result = build_empty_response(&data);
        assert_eq!(result, data);
    }

    #[test]
    fn test_build_a_response_malformed_eleven_bytes() {
        let data = vec![0x00u8; 11];
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let result = build_a_response(&data, &[ip], 60);
        assert_eq!(result, data);
    }

    #[test]
    fn test_build_a_response_strips_edns_opt() {
        let query = example_com_query_with_edns();
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let response = build_a_response(&query, &[ip], 60);
        let parsed = Packet::parse(&response).expect("response should be valid DNS");
        assert_eq!(parsed.answers.len(), 1);
        assert!(
            parsed.additional_records.is_empty(),
            "EDNS OPT should be stripped"
        );
        match &parsed.answers[0].rdata {
            RData::A(a) => assert_eq!(Ipv4Addr::from(a.address), Ipv4Addr::new(1, 2, 3, 4)),
            other => panic!("expected A record, got {other:?}"),
        }
    }

    #[test]
    fn test_build_empty_response_strips_edns_opt() {
        let query = example_com_query_with_edns();
        let response = build_empty_response(&query);
        let parsed = Packet::parse(&response).expect("response should be valid DNS");
        assert!(
            parsed.additional_records.is_empty(),
            "EDNS OPT should be stripped"
        );
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn test_build_servfail_strips_edns_opt() {
        let query = example_com_query_with_edns();
        let response = build_servfail(&query).unwrap();
        let parsed = Packet::parse(&response).expect("response should be valid DNS");
        assert!(
            parsed.additional_records.is_empty(),
            "EDNS OPT should be stripped"
        );
        assert_eq!(parsed.rcode(), RCODE::ServerFailure);
    }

    #[test]
    fn test_build_servfail_zeroes_count_fields() {
        let query = example_com_query();
        let response = build_servfail(&query).unwrap();
        let parsed = Packet::parse(&response).expect("response should be valid DNS");
        assert!(parsed.answers.is_empty());
        assert!(parsed.additional_records.is_empty());
    }

    #[test]
    fn test_build_raw_empty_preserves_question() {
        let query = example_com_query();
        let response = build_raw_empty(&query);
        assert!(
            response.len() >= query.len(),
            "raw empty response should include question section"
        );
        assert_eq!(response[4], 0x00);
        assert_eq!(response[5], 0x01);
        assert_eq!(&response[6..12], &[0, 0, 0, 0, 0, 0]);
        assert_eq!(&response[12..], &query[12..]);
    }

    #[test]
    fn test_fresh_onion_state_starts_clean() {
        let state = OnionState::new();
        let ip1 = state.allocate_ip().expect("should allocate");
        let ip2 = state.allocate_ip().expect("should allocate");
        assert_eq!(ip1, Ipv4Addr::new(10, 254, 0, 1));
        assert_eq!(ip2, Ipv4Addr::new(10, 254, 0, 2));
    }

    #[test]
    fn test_get_or_allocate_idempotent() {
        let state = OnionState::new();
        let ip1 = state.get_or_allocate("test.onion").unwrap();
        let ip2 = state.get_or_allocate("test.onion").unwrap();
        assert_eq!(ip1, ip2, "same hostname must return same IP");
    }

    #[test]
    fn test_get_or_allocate_different_hostnames() {
        let state = OnionState::new();
        let ip1 = state.get_or_allocate("a.onion").unwrap();
        let ip2 = state.get_or_allocate("b.onion").unwrap();
        assert_ne!(ip1, ip2, "different hostnames must get different IPs");
    }

    #[test]
    fn test_lookup_by_ip() {
        let state = OnionState::new();
        let ip = state.get_or_allocate("test.onion").unwrap();
        assert_eq!(state.lookup_by_ip(ip), Some("test.onion".to_string()));
        assert_eq!(state.lookup_by_ip(Ipv4Addr::new(10, 254, 255, 255)), None);
    }

    #[tokio::test]
    async fn test_handle_dns_query_aaaa_returns_empty() {
        let query = example_com_aaaa_query();

        let packet = Packet::parse(&query).unwrap();
        assert!(matches!(packet.questions[0].qtype, QTYPE::TYPE(TYPE::AAAA)));

        let response = build_empty_response(&query);
        let parsed = Packet::parse(&response).unwrap();
        assert!(parsed.has_flags(PacketFlag::RESPONSE));
        assert!(
            parsed.answers.is_empty(),
            "AAAA query must not return A records"
        );
        assert_eq!(parsed.rcode(), RCODE::NoError);
    }
}
