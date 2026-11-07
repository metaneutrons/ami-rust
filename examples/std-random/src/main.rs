//! Randomness of `std` on AROS, through `std::random` (the path that `HashMap` seeds from): which source
//! is used, statistics of 64 KiB, a self-test that shows the statistics reject bad streams, edge
//! sizes, `HashMap` and the high-level API. One behaviour per run; the results are in README.md.

#![feature(restricted_std)]
#![feature(random)]

use std::arch::x86_64::__cpuid;
use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::process::ExitCode;
use std::random::{Rng, SystemRng, random};

unsafe extern "C" {
    static __ami_rust_random_source: u8;
}

fn source() -> &'static str {
    match unsafe { std::ptr::addr_of!(__ami_rust_random_source).read_volatile() } {
        0 => "none",
        1 => "weak generator only",
        2 => "weak generator mixed with RDRAND",
        3 => "getentropy",
        _ => "unknown",
    }
}

struct Report { ones: f64, chi2: f64, duplicate_words: usize, longest_run: usize }

fn analyse(bytes: &[u8]) -> Report {
    let ones: u64 = bytes.iter().map(|b| b.count_ones() as u64).sum();
    let mut bins = [0u64; 256];
    for &b in bytes { bins[b as usize] += 1; }
    let expected = bytes.len() as f64 / 256.0;
    let chi2 = bins.iter().map(|&o| { let d = o as f64 - expected; d * d / expected }).sum();
    let mut words: Vec<u64> = bytes.chunks_exact(8).map(|c| u64::from_ne_bytes(c.try_into().unwrap())).collect();
    words.sort_unstable();
    let duplicate_words = words.windows(2).filter(|w| w[0] == w[1]).count();
    let (mut longest, mut run) = (1, 1);
    for w in bytes.windows(2) { if w[0] == w[1] { run += 1; longest = longest.max(run); } else { run = 1; } }
    Report { ones: ones as f64 / (bytes.len() as f64 * 8.0), chi2, duplicate_words, longest_run: longest }
}

/// The bounds are set so that a good generator fails one run in a million or less.
fn verdict(r: &Report) -> bool {
    (r.ones - 0.5).abs() < 0.005 && r.chi2 > 130.0 && r.chi2 < 400.0 && r.duplicate_words == 0 && r.longest_run <= 4
}

fn show(name: &str, r: &Report) {
    println!("RESULT {name} ones={:.4} chi2={:.1} duplicate_words={} longest_run={} {}", r.ones, r.chi2, r.duplicate_words, r.longest_run, if verdict(r) { "pass" } else { "FAIL" });
}

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let mut ok = true;
    match mode.as_str() {
        "source" => {
            let mut b = [0u8; 16];
            SystemRng.fill_bytes(&mut b);
            let cpu_rdrand = __cpuid(1).ecx & (1 << 30) != 0;
            println!("RESULT source={} cpu_has_rdrand={cpu_rdrand}", source());
        }
        "stats" => {
            let mut b = vec![0u8; 65536];
            SystemRng.fill_bytes(&mut b);
            let r = analyse(&b);
            ok = verdict(&r);
            print!("source={} ", source());
            show("stats", &r);
        }
        "selftest" => {
            // The same analysis must reject streams that are not random.
            let zeros = vec![0u8; 65536];
            let counter: Vec<u8> = (0..65536u32).map(|i| i as u8).collect();
            let biased: Vec<u8> = (0..65536u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8 & 0x7f).collect();
            let repeated: Vec<u8> = (0..65536usize).map(|i| [3u8, 141, 59, 26, 53, 58, 97, 93][i % 8]).collect();
            for (name, data) in [("zeros", &zeros), ("counter", &counter), ("biased", &biased), ("repeated", &repeated)] {
                let r = analyse(data);
                let rejected = !verdict(&r);
                println!("RESULT selftest {name} rejected={rejected} (ones={:.3} chi2={:.0} dup={} run={})", r.ones, r.chi2, r.duplicate_words, r.longest_run);
                ok &= rejected;
            }
        }
        "sizes" => {
            for n in [0usize, 1, 7, 8, 9, 255, 256, 257, 511, 512, 513, 1000, 65536] {
                let mut b = vec![0u8; n];
                SystemRng.fill_bytes(&mut b);
                // Not all zero (for n >= 8), and the last byte is covered: over 64 fills it is not constant.
                let nonzero = n < 8 || b.iter().any(|&x| x != 0);
                let mut seen = std::collections::BTreeSet::new();
                if n > 0 { for _ in 0..64 { let mut t = vec![0u8; n]; SystemRng.fill_bytes(&mut t); seen.insert(t[n - 1]); } }
                let tail_ok = n == 0 || seen.len() > 8;
                println!("RESULT sizes {n} nonzero={nonzero} distinct_last_bytes={} {}", seen.len(), if nonzero && tail_ok { "ok" } else { "FAIL" });
                ok &= nonzero && tail_ok;
            }
        }
        "api" => {
            // The high-level function that users call.
            let a: u64 = random(..);
            let b: u64 = random(..);
            let bytes: Vec<u8> = (0..4000).map(|_| random::<u8>(..)).collect();
            let seen = bytes.iter().collect::<std::collections::BTreeSet<_>>().len();
            let trues = (0..4000).filter(|_| random::<bool>(..)).count();
            println!("RESULT api two_u64_differ={} u8_values_seen={seen} of 256 bools_true={trues} of 4000", a != b);
            ok = a != b && seen > 240 && (1800..2200).contains(&trues);
        }
        "hashmap" => {
            let a = RandomState::new().hash_one(1u64);
            let b = RandomState::new().hash_one(1u64);
            let mut m = HashMap::new();
            for i in 0..2000u32 { m.insert(i, i * 3); }
            let sum_ok = (0..2000u32).all(|i| m.get(&i) == Some(&(i * 3)));
            println!("RESULT hashmap seed_a={a:016x} seed_b={b:016x} two_states_differ={} map_ok={sum_ok}", a != b);
            ok = a != b && sum_ok;
        }
        "seed" => {
            let mut b = [0u8; 16];
            SystemRng.fill_bytes(&mut b);
            let h = RandomState::new().hash_one(0u64);
            let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
            println!("RESULT seed bytes={hex} hash={h:016x} source={}", source());
        }
        _ => println!("modes: source stats selftest sizes hashmap seed"),
    }
    if ok { ExitCode::SUCCESS } else { ExitCode::from(3) }
}
