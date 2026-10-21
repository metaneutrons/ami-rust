//! Bounded in-process loopback fixture for one synthetic authenticated sparse registry.
//!
//! This module is intentionally narrow: it serves only the config, one sparse
//! index record, and one matching .crate archive. It records request routes and
//! whether Authorization matched the synthetic value, never header contents.

use ami_rust_core::digest;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;

use serde_json::{Value, json};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub const REGISTRY_NAME: &str = "rc2-fixture";
pub const CRATE_NAME: &str = "rc2-fixture-leaf";
pub const CRATE_VERSION: &str = "0.1.0";
pub const SYNTHETIC_AUTHORIZATION: &str = "Bearer rc2-synthetic-only";

const CONFIG_ROUTE: &str = "/index/config.json";
const INDEX_ROUTE: &str = "/index/rc/2-/rc2-fixture-leaf";
const DOWNLOAD_ROUTE: &str = "/api/rc2-fixture-leaf/0.1.0/download";
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_REQUESTS: usize = 64;
const READ_TIMEOUT: Duration = Duration::from_millis(400);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const WRITE_TIMEOUT: Duration = Duration::from_millis(400);
const ACCEPT_POLL: Duration = Duration::from_millis(5);

const CRATE_ARCHIVE: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xed, 0xd3, 0xbf, 0x6e, 0xc2, 0x30,
    0x10, 0x06, 0x70, 0xe6, 0x3c, 0xc5, 0x29, 0x53, 0x19, 0x12, 0x2e, 0x8e, 0x61, 0xa3, 0x4b, 0x1f,
    0x03, 0x55, 0x95, 0x09, 0x0e, 0x8a, 0xc8, 0x1f, 0x74, 0x8e, 0x69, 0xa5, 0xaa, 0xef, 0x5e, 0x37,
    0x8a, 0x3a, 0x64, 0x41, 0x08, 0x04, 0x0c, 0xdf, 0x6f, 0xb1, 0x75, 0x96, 0x7c, 0xb2, 0x7c, 0x9f,
    0x14, 0x2a, 0x29, 0xab, 0xaf, 0xde, 0x8b, 0x4d, 0x6a, 0x6b, 0xca, 0x84, 0xd3, 0x2c, 0xe5, 0xc5,
    0x9b, 0x91, 0x7d, 0x97, 0xf6, 0x5d, 0x53, 0xcf, 0xae, 0xc7, 0xc1, 0x4a, 0xeb, 0x61, 0x0d, 0xa6,
    0x2b, 0x67, 0x2a, 0xff, 0xdf, 0x0f, 0xf5, 0x2c, 0xd7, 0xac, 0x66, 0xc4, 0x37, 0xe8, 0x7d, 0x96,
    0x77, 0xbd, 0x91, 0xd0, 0xfe, 0x1e, 0xbd, 0x9e, 0xd0, 0xe6, 0x68, 0x8a, 0x83, 0xd9, 0xdb, 0xf7,
    0xa8, 0x35, 0x8d, 0xa5, 0x35, 0xc5, 0x32, 0x99, 0x88, 0x38, 0x3a, 0x59, 0x71, 0x55, 0xd7, 0xfe,
    0x1d, 0x0e, 0xd3, 0x11, 0x47, 0x76, 0x57, 0xf5, 0x63, 0x45, 0xb1, 0xca, 0xe2, 0x68, 0xf3, 0xd9,
    0xc9, 0xc1, 0x85, 0xbb, 0xc2, 0x45, 0x8f, 0x7e, 0x12, 0x5c, 0x60, 0xfa, 0xdb, 0x63, 0xfe, 0x9d,
    0x14, 0x8b, 0xba, 0xda, 0xa6, 0xe2, 0x6e, 0xd0, 0xe3, 0x5c, 0xfe, 0x59, 0x2f, 0xa7, 0xf9, 0xcf,
    0x57, 0x8c, 0xfc, 0xdf, 0xc3, 0xd1, 0x6f, 0xa9, 0x6c, 0x69, 0x1c, 0x81, 0x8f, 0x93, 0xa9, 0xbd,
    0x7d, 0x99, 0x53, 0xf2, 0x4a, 0x3e, 0x57, 0xf4, 0x4d, 0x5a, 0xd1, 0x0f, 0x12, 0x0d, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xbc, 0x7e,
    0x01, 0xc9, 0x19, 0x45, 0xc7, 0x00, 0x28, 0x00, 0x00,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthPolicy {
    /// Return registry data only when Authorization matches the fixture token.
    AcceptExpected,
    /// Return 401 for protected routes, including when the fixture token matches.
    RejectAll,
}

#[derive(Clone, Debug)]
struct Observation {
    route: String,
    authorization_matches: bool,
}

/// Owns a bounded loopback server. Dropping it signals the worker and joins it.
pub struct RegistryFixture {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    observations: Arc<Mutex<Vec<Observation>>>,
    worker: Option<JoinHandle<()>>,
    #[cfg(test)]
    accepted_connections: Arc<AtomicUsize>,
}

impl RegistryFixture {
    pub fn start(policy: AuthPolicy) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        if !address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "synthetic registry did not bind to loopback",
            ));
        }

        let stop = Arc::new(AtomicBool::new(false));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let (config_body, index_body) = response_bodies(address)?;

        #[cfg(test)]
        let accepted_connections = Arc::new(AtomicUsize::new(0));
        #[cfg(test)]
        let worker_accepted = Arc::clone(&accepted_connections);
        let worker_stop = Arc::clone(&stop);
        let worker_observations = Arc::clone(&observations);
        let worker = thread::Builder::new()
            .name("rc2-sparse-registry-fixture".to_owned())
            .spawn(move || {
                serve(
                    listener,
                    worker_stop,
                    worker_observations,
                    policy,
                    config_body,
                    index_body,
                    #[cfg(test)]
                    worker_accepted,
                );
            })?;

        Ok(Self {
            address,
            stop,
            observations,
            worker: Some(worker),
            #[cfg(test)]
            accepted_connections,
        })
    }

    /// Returns Cargo's sparse registry URL, including its required trailing slash.
    pub fn sparse_index_url(&self) -> String {
        format!("sparse+http://{}/index/", self.address)
    }

    /// Returns the synthetic Authorization value expected by the loopback server.
    pub fn expected_token(&self) -> &'static str {
        SYNTHETIC_AUTHORIZATION
    }

    /// Returns only route and token-match booleans; no request headers or values.
    pub fn sanitized_observations(&self) -> Vec<Value> {
        self.observations
            .lock()
            .map(|observations| {
                observations
                    .iter()
                    .map(|observation| {
                        json!({
                            "route": observation.route.as_str(),
                            "authorization_matches": observation.authorization_matches
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns (matching Authorization count, nonmatching Authorization count).
    pub fn authorization_counts(&self) -> (usize, usize) {
        self.observations
            .lock()
            .map(|observations| {
                let matched = observations
                    .iter()
                    .filter(|observation| observation.authorization_matches)
                    .count();
                (matched, observations.len() - matched)
            })
            .unwrap_or_default()
    }

    pub fn crate_checksum(&self) -> String {
        digest::sha256_bytes(CRATE_ARCHIVE)
    }
}

impl Drop for RegistryFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn response_bodies(address: SocketAddr) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let config = json!({
        "dl": format!("http://{}/api/{{crate}}/{{version}}/download", address),
        "auth-required": true
    });
    let config_body = serde_json::to_vec(&config).map_err(json_io_error)?;

    let index_record = json!({
        "name": CRATE_NAME,
        "vers": CRATE_VERSION,
        "deps": [],
        "cksum": digest::sha256_bytes(CRATE_ARCHIVE),
        "features": {},
        "yanked": false
    });
    let mut index_body = serde_json::to_vec(&index_record).map_err(json_io_error)?;
    index_body.push(b'\n');
    Ok((config_body, index_body))
}

fn json_io_error(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn serve(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    observations: Arc<Mutex<Vec<Observation>>>,
    policy: AuthPolicy,
    config_body: Vec<u8>,
    index_body: Vec<u8>,
    #[cfg(test)] accepted_connections: Arc<AtomicUsize>,
) {
    let mut accepted = 0;
    while accepted < MAX_REQUESTS && !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _peer)) => {
                accepted += 1;
                // macOS accepts may inherit O_NONBLOCK from the listener.
                // Header reads below require the configured bounded blocking timeout.
                if stream.set_nonblocking(false).is_err()
                    || stream.set_read_timeout(Some(READ_TIMEOUT)).is_err()
                    || stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err()
                {
                    continue;
                }
                #[cfg(test)]
                accepted_connections.fetch_add(1, Ordering::Release);
                let _ = handle_connection(
                    &mut stream,
                    &observations,
                    policy,
                    &config_body,
                    &index_body,
                );
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(_) => break,
        }
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    observations: &Mutex<Vec<Observation>>,
    policy: AuthPolicy,
    config_body: &[u8],
    index_body: &[u8],
) -> io::Result<()> {
    let request = match read_request(stream) {
        Ok(request) => request,
        Err(_) => {
            return write_response(
                stream,
                "400 Bad Request",
                "text/plain",
                b"bad request\n",
                false,
            );
        }
    };
    let Some(route) = KnownRoute::from_path(&request.target) else {
        return write_response(stream, "404 Not Found", "text/plain", b"not found\n", false);
    };
    if request.method != "GET" {
        return write_response(
            stream,
            "405 Method Not Allowed",
            "text/plain",
            b"method not allowed\n",
            false,
        );
    }

    let authorization_matches = request.authorization.as_deref() == Some(SYNTHETIC_AUTHORIZATION);
    if let Ok(mut observations) = observations.lock()
        && observations.len() < MAX_REQUESTS
    {
        observations.push(Observation {
            route: request.target,
            authorization_matches,
        });
    }

    match route {
        KnownRoute::Config => {
            write_response(stream, "200 OK", "application/json", config_body, false)
        }
        KnownRoute::Index if policy == AuthPolicy::AcceptExpected && authorization_matches => {
            write_response(stream, "200 OK", "application/json", index_body, false)
        }
        KnownRoute::Download if policy == AuthPolicy::AcceptExpected && authorization_matches => {
            write_response(
                stream,
                "200 OK",
                "application/octet-stream",
                CRATE_ARCHIVE,
                false,
            )
        }
        KnownRoute::Index | KnownRoute::Download => write_response(
            stream,
            "401 Unauthorized",
            "text/plain",
            b"unauthorized\n",
            true,
        ),
    }
}

#[derive(Clone, Copy)]
enum KnownRoute {
    Config,
    Index,
    Download,
}

impl KnownRoute {
    fn from_path(path: &str) -> Option<Self> {
        match path {
            CONFIG_ROUTE => Some(Self::Config),
            INDEX_ROUTE => Some(Self::Index),
            DOWNLOAD_ROUTE => Some(Self::Download),
            _ => None,
        }
    }
}

struct Request {
    method: String,
    target: String,
    authorization: Option<String>,
}

fn read_request(stream: &mut TcpStream) -> io::Result<Request> {
    read_request_before(stream, Instant::now() + REQUEST_TIMEOUT)
}

fn read_request_before(stream: &mut TcpStream, deadline: Instant) -> io::Result<Request> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(end) = find_header_end(&bytes) {
            break end;
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers exceed fixture bound",
            ));
        }
        let time_left = deadline.saturating_duration_since(Instant::now());
        if time_left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture request deadline exceeded",
            ));
        }
        stream.set_read_timeout(Some(time_left.min(READ_TIMEOUT)))?;
        let remaining = MAX_HEADER_BYTES - bytes.len();
        let read_limit = remaining.min(chunk.len());
        let count = stream.read(&mut chunk[..read_limit])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request ended before header terminator",
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
    };

    let body_start = header_end + 4;
    if !bytes[body_start..].is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture accepts only bodyless GET requests",
        ));
    }
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if !header.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request headers must be ASCII",
        ));
    }

    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty()
        || target.is_empty()
        || !target.starts_with('/')
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || parts.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    }

    let mut authorization = None;
    let mut content_length_seen = false;
    for line in lines {
        if line.is_empty() || line.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed header line",
            ));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed header field"))?;
        if name.is_empty() || !name.bytes().all(is_http_token_byte) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed header name",
            ));
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim_matches(|character| character == ' ' || character == '\t');
        if value
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "control byte in header value",
            ));
        }
        match name.as_str() {
            "authorization" if authorization.is_none() => {
                authorization = Some(value.to_owned());
            }
            "authorization" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate Authorization header",
                ));
            }
            "content-length" if !content_length_seen => {
                content_length_seen = true;
                if value.is_empty()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                    || value != "0"
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "fixture accepts only Content-Length: 0",
                    ));
                }
            }
            "content-length" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate Content-Length header",
                ));
            }
            "transfer-encoding" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "transfer-encoded requests are unsupported",
                ));
            }
            _ => {}
        }
    }

    Ok(Request {
        method: method.to_owned(),
        target: target.to_owned(),
        authorization,
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_|~".contains(&byte)
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    challenge: bool,
) -> io::Result<()> {
    let mut headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if challenge {
        headers.push_str("WWW-Authenticate: Cargo realm=\"rc2-fixture\"\r\n");
    }
    headers.push_str("\r\n");
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(fixture: &RegistryFixture, route: &str, authorization: Option<&str>) -> (u16, Vec<u8>) {
        get_after_delay(fixture, route, authorization, Duration::ZERO)
    }

    fn get_after_delay(
        fixture: &RegistryFixture,
        route: &str,
        authorization: Option<&str>,
        delay: Duration,
    ) -> (u16, Vec<u8>) {
        let expected_accept = fixture.accepted_connections.load(Ordering::Acquire) + 1;
        let mut stream = TcpStream::connect(fixture.address).unwrap();
        if !delay.is_zero() {
            let deadline = Instant::now() + Duration::from_secs(2);
            while fixture.accepted_connections.load(Ordering::Acquire) < expected_accept {
                assert!(
                    Instant::now() < deadline,
                    "server did not accept before the header delay"
                );
                thread::sleep(ACCEPT_POLL);
            }
        }
        thread::sleep(delay);
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(WRITE_TIMEOUT)).unwrap();
        let authorization_header = authorization
            .map(|value| format!("Authorization: {value}\r\n"))
            .unwrap_or_default();
        write!(
            stream,
            "GET {route} HTTP/1.1\r\nHost: {}\r\n{authorization_header}Connection: close\r\n\r\n",
            fixture.address
        )
        .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let response_text = String::from_utf8_lossy(&response);
        let status = response_text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap();
        let body_start = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|end| end + 4)
            .unwrap();
        (status, response[body_start..].to_vec())
    }

    #[test]
    fn trickled_headers_cannot_extend_the_total_request_deadline() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (ready, begin) = std::sync::mpsc::channel();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            if begin.recv_timeout(Duration::from_secs(2)).is_err() {
                return;
            }
            for _ in 0..50 {
                if stream.write_all(b"x").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        });
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(false).unwrap();
        ready.send(()).unwrap();
        let result = read_request_before(&mut stream, Instant::now() + Duration::from_millis(180));
        drop(stream);
        writer.join().unwrap();
        assert!(matches!(result, Err(ref error)
            if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)));
    }

    #[test]
    fn delayed_request_waits_for_headers_after_accept() {
        let fixture = RegistryFixture::start(AuthPolicy::RejectAll).unwrap();
        let (status, _) = get_after_delay(
            &fixture,
            INDEX_ROUTE,
            Some(SYNTHETIC_AUTHORIZATION),
            Duration::from_millis(50),
        );
        assert_eq!(status, 401);
        assert_eq!(fixture.authorization_counts(), (1, 0));
    }

    #[test]
    fn serves_valid_synthetic_registry_and_counts_only_token_matches() {
        let fixture = RegistryFixture::start(AuthPolicy::AcceptExpected).unwrap();

        let (config_status, config) = get(&fixture, CONFIG_ROUTE, None);
        assert_eq!(config_status, 200);
        assert!(String::from_utf8_lossy(&config).contains("\"auth-required\":true"));

        let (index_status, index) = get(&fixture, INDEX_ROUTE, Some(SYNTHETIC_AUTHORIZATION));
        assert_eq!(index_status, 200);
        let checksum = fixture.crate_checksum();
        assert!(String::from_utf8_lossy(&index).contains(checksum.as_str()));

        let (download_status, archive) =
            get(&fixture, DOWNLOAD_ROUTE, Some(SYNTHETIC_AUTHORIZATION));
        assert_eq!(download_status, 200);
        assert_eq!(archive.as_slice(), CRATE_ARCHIVE);

        let (wrong_token_status, _) = get(&fixture, INDEX_ROUTE, Some("Bearer deliberately-wrong"));
        assert_eq!(wrong_token_status, 401);

        assert_eq!(fixture.authorization_counts(), (2, 2));
        let observations = fixture.sanitized_observations();
        assert_eq!(
            observations
                .iter()
                .map(|observation| observation["route"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![CONFIG_ROUTE, INDEX_ROUTE, DOWNLOAD_ROUTE, INDEX_ROUTE]
        );
        assert_eq!(observations[0]["authorization_matches"], false);
        assert_eq!(observations[1]["authorization_matches"], true);
        assert_eq!(observations[2]["authorization_matches"], true);
        assert_eq!(observations[3]["authorization_matches"], false);
        let serialized = serde_json::to_string(&observations).unwrap();
        assert!(!serialized.contains("rc2-synthetic-only"));
        assert!(!serialized.contains("deliberately-wrong"));
    }

    #[test]
    fn reject_all_policy_denies_even_the_expected_synthetic_token() {
        let fixture = RegistryFixture::start(AuthPolicy::RejectAll).unwrap();
        let (status, _) = get(&fixture, INDEX_ROUTE, Some(SYNTHETIC_AUTHORIZATION));
        assert_eq!(status, 401);
        assert_eq!(fixture.authorization_counts(), (1, 0));
    }
}
