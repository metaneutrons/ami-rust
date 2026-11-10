//! Sockets in `std` on AROS: `TcpStream`, `TcpListener`, `UdpSocket` and name lookup over
//! `bsdsocket.library`. One behaviour per run, chosen by the first argument; the expected results are in
//! README.md. All traffic is on the loopback interface. The run must create `RAM:ami-rust-m1` and start in it.

#![feature(restricted_std)]
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

struct T {
    failed: u32,
    total: u32,
}

impl T {
    fn check(&mut self, name: &str, ok: bool, detail: String) {
        self.total += 1;
        if !ok {
            self.failed += 1;
        }
        println!("RESULT net {name} {}{}", if ok { "ok" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!(" ({detail})") });
    }

    fn is<V: PartialEq + std::fmt::Debug>(&mut self, name: &str, got: V, want: V) {
        let ok = got == want;
        self.check(name, ok, if ok { String::new() } else { format!("got {got:?}, wanted {want:?}") });
    }
}

fn kind<V>(result: &std::io::Result<V>) -> String {
    match result {
        Ok(_) => "Ok".to_string(),
        Err(e) => format!("{:?}", e.kind()),
    }
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// No network stack is running: every entry point returns `Unsupported` at once.
fn nostack(t: &mut T) {
    let start = Instant::now();
    let tcp = TcpStream::connect(loopback(9));
    t.is("connect-unsupported", kind(&tcp), "Unsupported".to_string());
    if let Err(e) = &tcp {
        println!("INFO message: {e}");
    }
    t.is("bind-unsupported", kind(&TcpListener::bind(loopback(0))), "Unsupported".to_string());
    t.is("udp-unsupported", kind(&UdpSocket::bind(loopback(0))), "Unsupported".to_string());
    t.is("lookup-unsupported", kind(&("localhost", 80).to_socket_addrs()), "Unsupported".to_string());
    t.is("numeric-lookup-needs-no-stack", ("127.0.0.1", 80).to_socket_addrs().map(|mut a| a.next()).ok().flatten(), Some(loopback(80)));
    t.check("no-wait", start.elapsed() < Duration::from_secs(5), format!("{:?}", start.elapsed()));
}

fn tcp(t: &mut T) {
    // The server is a thread: it makes the listener, so the thread that accepts is the thread that made it.
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let listener = TcpListener::bind(loopback(0)).expect("bind");
        tx.send(listener.local_addr().unwrap()).unwrap();
        let (mut stream, peer) = listener.accept().expect("accept");
        let mut got = [0u8; 5];
        stream.read_exact(&mut got).expect("server read");
        stream.write_all(&got).expect("server write");
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).expect("server read to end");
        (peer.ip(), got, rest.len())
    });
    let addr = rx.recv().unwrap();
    t.check("listener-port", addr.port() != 0 && addr.ip().is_loopback(), format!("{addr}"));
    let mut client = TcpStream::connect(addr).expect("connect");
    t.is("peer-addr", client.peer_addr().unwrap(), addr);
    t.check("local-addr", client.local_addr().map(|a| a.ip().is_loopback() && a.port() != 0).unwrap_or(false), String::new());
    client.write_all(b"hello").unwrap();
    let mut echo = [0u8; 5];
    client.read_exact(&mut echo).unwrap();
    t.is("echo", &echo, b"hello");
    // a read with a timeout ends with an error of its own kind, and the stream stays usable
    client.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    t.is("read-timeout-set", client.read_timeout().unwrap(), Some(Duration::from_millis(300)));
    let start = Instant::now();
    let mut one = [0u8; 1];
    let timed = client.read(&mut one);
    let waited = start.elapsed();
    t.check("read-timeout-kind", matches!(&timed, Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut), kind(&timed));
    t.check("read-timeout-time", waited >= Duration::from_millis(250) && waited < Duration::from_secs(3), format!("{waited:?}"));
    client.set_read_timeout(None).unwrap();
    // non-blocking mode
    client.set_nonblocking(true).unwrap();
    let nb = client.read(&mut one);
    t.check("nonblocking-would-block", matches!(&nb, Err(e) if e.kind() == ErrorKind::WouldBlock), kind(&nb));
    client.set_nonblocking(false).unwrap();
    // options
    t.check("nodelay", client.set_nodelay(true).is_ok() && client.nodelay().unwrap_or(false), String::new());
    t.check("ttl", client.set_ttl(33).is_ok() && client.ttl().ok() == Some(33), format!("{:?}", client.ttl()));
    t.is("take-error", client.take_error().ok().map(|e| e.is_none()), Some(true));
    t.is("duplicate-unsupported", kind(&client.try_clone()), "Unsupported".to_string());
    client.write_all(b"tail").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let (peer_ip, got, rest) = server.join().unwrap();
    t.is("server-saw", (peer_ip, &got, rest), (Ipv4Addr::LOCALHOST.into(), b"hello", 4));
    // the server thread has ended: its sockets are closed, the client reads the end of the stream
    let mut tail = Vec::new();
    t.is("eof-after-server", client.read_to_end(&mut tail).map(|n| n).ok(), Some(0));
    // a port nobody listens on
    let closed = {
        let l = TcpListener::bind(loopback(0)).unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        port
    };
    let refused = TcpStream::connect(loopback(closed));
    t.is("connect-refused", kind(&refused), "ConnectionRefused".to_string());
    let timeout = TcpStream::connect_timeout(&loopback(closed), Duration::from_secs(2));
    t.is("connect-timeout-refused", kind(&timeout), "ConnectionRefused".to_string());
}

fn udp(t: &mut T) {
    let a = UdpSocket::bind(loopback(0)).expect("bind a");
    let b = UdpSocket::bind(loopback(0)).expect("bind b");
    let (a_addr, b_addr) = (a.local_addr().unwrap(), b.local_addr().unwrap());
    t.check("two-ports", a_addr.port() != b_addr.port() && a_addr.port() != 0, format!("{a_addr} {b_addr}"));
    t.is("send-to", a.send_to(b"ping", b_addr).ok(), Some(4));
    let mut buf = [0u8; 16];
    b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let peeked = b.peek_from(&mut buf).map(|(n, from)| (n, from.port()));
    t.is("peek-from", peeked.ok(), Some((4, a_addr.port())));
    let got = b.recv_from(&mut buf).map(|(n, from)| (n, from.port()));
    t.is("recv-from", got.ok(), Some((4, a_addr.port())));
    t.is("payload", &buf[..4], b"ping");
    // a connected pair
    a.connect(b_addr).unwrap();
    b.connect(a_addr).unwrap();
    t.is("connected-peer", a.peer_addr().unwrap(), b_addr);
    t.is("send", b.send(b"pong").ok(), Some(4));
    t.is("recv", a.recv(&mut buf).ok(), Some(4));
    // nothing to read: the timeout ends the call
    a.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let start = Instant::now();
    let none = a.recv(&mut buf);
    t.check("recv-timeout", matches!(&none, Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut) && start.elapsed() >= Duration::from_millis(250), format!("{} {:?}", kind(&none), start.elapsed()));
    t.check("broadcast", a.set_broadcast(true).is_ok() && a.broadcast().unwrap_or(false), String::new());
    t.is("multicast-unsupported", kind(&a.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 9), &Ipv4Addr::UNSPECIFIED)), "Unsupported".to_string());
    t.is("duplicate-unsupported", kind(&a.try_clone()), "Unsupported".to_string());
    // a datagram larger than a few hundred bytes
    let big = [7u8; 1200];
    let c = UdpSocket::bind(loopback(0)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.send_to(&big, c.local_addr().unwrap()).unwrap();
    let mut large = [0u8; 2048];
    t.is("large-datagram", c.recv(&mut large).ok(), Some(1200));
}

fn lookup(t: &mut T) {
    let numeric: Vec<SocketAddr> = ("127.0.0.1", 4000).to_socket_addrs().map(|a| a.collect()).unwrap_or_default();
    t.is("numeric", numeric, vec![loopback(4000)]);
    let named = ("localhost", 4000).to_socket_addrs().map(|a| a.collect::<Vec<_>>());
    t.check("localhost", matches!(&named, Ok(v) if v.contains(&loopback(4000))), format!("{named:?}"));
    let unknown = ("no-such-host.invalid", 80).to_socket_addrs();
    t.check("unknown-host", unknown.is_err(), kind(&unknown));
    t.is("nul-byte", kind(&("a\0b", 80).to_socket_addrs()), "InvalidInput".to_string());
}

fn threads(t: &mut T, workers_wanted: u8) {
    // a socket made in this thread, used in another: refused, and still usable here
    let listener = TcpListener::bind(loopback(0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let foreign = thread::spawn(move || {
        let r = listener.local_addr();
        let k = kind(&r);
        // the listener is dropped here, in a thread that did not make it
        (k, 0)
    })
    .join()
    .unwrap();
    t.is("foreign-use-refused", foreign.0, "Unsupported".to_string());
    // several threads, each with its own pair: they run at once
    let start = Instant::now();
    let workers: Vec<_> = (0..workers_wanted)
        .map(|n| {
            thread::spawn(move || {
                // the server thread makes its own listener: a socket is used by the thread that made it
                let (tx, rx) = mpsc::channel();
                let server = thread::spawn(move || {
                    let listener = TcpListener::bind(loopback(0)).unwrap();
                    tx.send(listener.local_addr().unwrap()).unwrap();
                    let (mut s, _) = listener.accept().unwrap();
                    let mut b = [0u8; 1];
                    s.read_exact(&mut b).unwrap();
                    s.write_all(&[b[0] + 1]).unwrap();
                });
                let started = Instant::now();
                let addr = rx.recv().unwrap();
                let got_addr = started.elapsed();
                let mut c = TcpStream::connect(addr).unwrap();
                let connected = started.elapsed();
                c.write_all(&[n]).unwrap();
                let mut b = [0u8; 1];
                c.read_exact(&mut b).unwrap();
                server.join().unwrap();
                (b[0], got_addr, connected, started.elapsed())
            })
        })
        .collect();
    let mut results = Vec::new();
    for (n, w) in workers.into_iter().enumerate() {
        let (value, got_addr, connected, done) = w.join().unwrap();
        println!("INFO worker {n}: address {got_addr:?}, connected {connected:?}, done {done:?}, joined at {:?}", start.elapsed());
        results.push(value);
    }
    t.is("pairs", results, (1..=workers_wanted).collect::<Vec<u8>>());
    t.check("pairs-time", start.elapsed() < Duration::from_secs(20), format!("{:?}", start.elapsed()));
    // the listener was dropped in another thread; this thread closes it at its next call, so the address is free
    let again = TcpListener::bind(addr);
    t.check("rebind-after-foreign-drop", again.is_ok(), kind(&again));
}

fn many(t: &mut T) {
    // opening and closing many sockets leaves nothing behind
    let mut ok = 0;
    for _ in 0..200 {
        match UdpSocket::bind(loopback(0)) {
            Ok(s) => {
                drop(s);
                ok += 1;
            }
            Err(e) => {
                println!("INFO bind failed after {ok}: {e}");
                break;
            }
        }
    }
    t.is("udp-open-close", ok, 200);
    let mut held = Vec::new();
    for _ in 0..20 {
        if let Ok(s) = UdpSocket::bind(loopback(0)) {
            held.push(s);
        }
    }
    t.is("hold-twenty", held.len(), 20);
    drop(held);
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let listener = TcpListener::bind(loopback(0)).unwrap();
        tx.send(listener.local_addr().unwrap()).unwrap();
        let mut served = 0;
        for _ in 0..30 {
            let (mut s, _) = listener.accept().unwrap();
            let mut b = [0u8; 1];
            if s.read(&mut b).unwrap_or(0) == 1 {
                served += 1;
            }
        }
        served
    });
    let addr = rx.recv().unwrap();
    for i in 0..30u8 {
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(&[i]).unwrap();
    }
    t.is("thirty-connections", server.join().unwrap(), 30);
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    let mut t = T { failed: 0, total: 0 };
    match mode {
        "nostack" => nostack(&mut t),
        "tcp" => tcp(&mut t),
        "udp" => udp(&mut t),
        "lookup" => lookup(&mut t),
        "threads" => threads(&mut t, args.get(2).and_then(|n| n.parse().ok()).unwrap_or(4)),
        "many" => many(&mut t),
        _ => {
            eprintln!("usage: std-net nostack|tcp|udp|lookup|threads|many");
            return ExitCode::from(5);
        }
    }
    println!("RESULT net summary {} of {} checks passed", t.total - t.failed, t.total);
    if t.failed == 0 { ExitCode::SUCCESS } else { ExitCode::from(10) }
}
