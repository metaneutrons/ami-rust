//! Bounded parser and pure scope calculation for the existing `ps` observer.
//!
//! The caller chooses the input-byte and row limits. This module does not run
//! `ps`, signal processes, or treat a missing root as successful completion. A
//! parsed table is one observation of a changing process list, not an atomic
//! snapshot. Process IDs are linkage observations, not durable identities or
//! authority to signal. Callers must validate the requested root and decide
//! whether a missing root requires refusal.
#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    error::Error,
    fmt,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessRow {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub rss_kib: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessSnapshot {
    pub rows: Vec<ProcessRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotError {
    pub line: Option<usize>,
    pub message: &'static str,
}

impl SnapshotError {
    fn new(line: Option<usize>, message: &'static str) -> Self {
        Self { line, message }
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "ps row {line}: {}", self.message),
            None => f.write_str(self.message),
        }
    }
}

impl Error for SnapshotError {}

/// Parse the four integer columns emitted by
/// `/bin/ps -axo pid=,ppid=,pgid=,rss=`. Blank lines are ignored; every other
/// line must contain exactly four ASCII decimal integers. A PID of zero is
/// retained if the host reports one, but it cannot be requested as a target.
pub fn parse_ps_snapshot(
    raw: &[u8],
    maximum_bytes: usize,
    maximum_rows: usize,
) -> Result<ProcessSnapshot, SnapshotError> {
    if raw.len() > maximum_bytes {
        return Err(SnapshotError::new(
            None,
            "ps output exceeds caller byte limit",
        ));
    }
    if !raw.is_ascii() {
        return Err(SnapshotError::new(None, "ps output is not ASCII"));
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| SnapshotError::new(None, "ps output is not valid UTF-8"))?;
    let mut rows = Vec::new();
    let mut seen_pids = HashSet::new();

    for (line_index, line) in text.lines().enumerate() {
        let mut fields = line.split_ascii_whitespace();
        let Some(pid_text) = fields.next() else {
            continue;
        };
        if rows.len() >= maximum_rows {
            return Err(SnapshotError::new(
                Some(line_index + 1),
                "ps row count exceeds caller limit",
            ));
        }
        let ppid_text = fields.next().ok_or_else(|| {
            SnapshotError::new(Some(line_index + 1), "expected exactly four columns")
        })?;
        let pgid_text = fields.next().ok_or_else(|| {
            SnapshotError::new(Some(line_index + 1), "expected exactly four columns")
        })?;
        let rss_text = fields.next().ok_or_else(|| {
            SnapshotError::new(Some(line_index + 1), "expected exactly four columns")
        })?;
        if fields.next().is_some() {
            return Err(SnapshotError::new(
                Some(line_index + 1),
                "expected exactly four columns",
            ));
        }

        let pid = parse_u32(pid_text, line_index + 1)?;
        let ppid = parse_u32(ppid_text, line_index + 1)?;
        let pgid = parse_u32(pgid_text, line_index + 1)?;
        if !is_ascii_decimal(rss_text) {
            return Err(SnapshotError::new(
                Some(line_index + 1),
                "RSS KiB is not a u64 decimal integer",
            ));
        }
        let rss_kib = rss_text.parse::<u64>().map_err(|_| {
            SnapshotError::new(Some(line_index + 1), "RSS KiB is not a u64 decimal integer")
        })?;
        if !seen_pids.insert(pid) {
            return Err(SnapshotError::new(
                Some(line_index + 1),
                "duplicate PID in ps output",
            ));
        }
        rows.push(ProcessRow {
            pid,
            ppid,
            pgid,
            rss_kib,
        });
    }
    Ok(ProcessSnapshot { rows })
}

fn parse_u32(value: &str, line: usize) -> Result<u32, SnapshotError> {
    if !is_ascii_decimal(value) {
        return Err(SnapshotError::new(
            Some(line),
            "PID/PPID/PGID is not a u32 decimal integer",
        ));
    }
    value
        .parse::<u32>()
        .map_err(|_| SnapshotError::new(Some(line), "PID/PPID/PGID is not a u32 decimal integer"))
}

fn is_ascii_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// A single observation of a target's currently visible process scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeSnapshot {
    /// False is an explicit observation. Callers must decide what it means;
    /// this module does not equate root absence with successful completion.
    pub root_present: bool,
    /// Current rows in the scope, in the source snapshot's order.
    pub rows: Vec<ProcessRow>,
    /// Current in-scope PIDs, sorted and unique.
    pub process_ids: Vec<u32>,
    /// Remembered process groups plus groups observed in this scope, sorted.
    pub process_groups: Vec<u32>,
    /// Previously observed PIDs that are no longer in the current table.
    pub missing_previous_pids: Vec<u32>,
    pub rss_kib: u64,
    pub rss_bytes: u64,
}

/// Compute the visible process closure using the existing observer's linkage:
/// the target root, prior PIDs as linkage seeds, descendants through PPIDs, and
/// members of the target or previously observed process groups. Newly found
/// rows add their process groups for the next pass. The caller supplies prior
/// IDs/groups from earlier observations; this function does not persist state.
/// The caller bounds cumulative history with `maximum_history_entries`, which
/// counts both input slices, including duplicates, before allocating indexes.
pub fn observe_scope(
    snapshot: &ProcessSnapshot,
    target_pid: u32,
    previously_observed_pids: &[u32],
    previously_observed_groups: &[u32],
    maximum_history_entries: usize,
) -> Result<ScopeSnapshot, SnapshotError> {
    if target_pid == 0 {
        return Err(SnapshotError::new(
            None,
            "target PID must be a positive process identifier",
        ));
    }
    if previously_observed_pids
        .len()
        .checked_add(previously_observed_groups.len())
        .is_none_or(|entries| entries > maximum_history_entries)
    {
        return Err(SnapshotError::new(
            None,
            "process history exceeds caller entry limit",
        ));
    }

    let present_pids: BTreeSet<u32> = snapshot.rows.iter().map(|row| row.pid).collect();
    let root_present = present_pids.contains(&target_pid);
    let mut missing_previous_pids = BTreeSet::new();
    let mut connected = BTreeSet::from([target_pid]);
    for pid in previously_observed_pids {
        // ps reads a changing process table. A child row can still name a
        // parent whose own row disappeared during that walk. Preserve the
        // historical linkage seed without counting an absent PID's RSS.
        connected.insert(*pid);
        if !present_pids.contains(pid) {
            missing_previous_pids.insert(*pid);
        }
    }

    let mut groups: BTreeSet<u32> = previously_observed_groups.iter().copied().collect();
    // The original observer seeds the target PID as its initial PGID. This
    // also lets a still-live child be found after the leader disappears.
    groups.insert(target_pid);

    // Index each edge once. The prior fixed-point loop rescanned the complete
    // process table for every newly reached generation, which is quadratic for
    // a deep process tree. These adjacency lists preserve row indices so the
    // final public rows still follow the source snapshot's order.
    let mut rows_by_pid: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    let mut children_by_parent: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    let mut rows_by_group: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (index, row) in snapshot.rows.iter().enumerate() {
        rows_by_pid.entry(row.pid).or_default().push(index);
        children_by_parent.entry(row.ppid).or_default().push(index);
        rows_by_group.entry(row.pgid).or_default().push(index);
    }

    #[derive(Clone, Copy)]
    enum Pending {
        Pid(u32),
        Group(u32),
    }

    let mut pending = VecDeque::new();
    for pid in connected.iter().copied() {
        pending.push_back(Pending::Pid(pid));
    }
    for group in groups.iter().copied() {
        pending.push_back(Pending::Group(group));
    }

    while let Some(next) = pending.pop_front() {
        match next {
            Pending::Pid(pid) => {
                if let Some(indices) = rows_by_pid.get(&pid) {
                    for &index in indices {
                        let group = snapshot.rows[index].pgid;
                        if groups.insert(group) {
                            pending.push_back(Pending::Group(group));
                        }
                    }
                }
                if let Some(indices) = children_by_parent.get(&pid) {
                    for &index in indices {
                        let child_pid = snapshot.rows[index].pid;
                        if connected.insert(child_pid) {
                            pending.push_back(Pending::Pid(child_pid));
                        }
                    }
                }
            }
            Pending::Group(group) => {
                if let Some(indices) = rows_by_group.get(&group) {
                    for &index in indices {
                        let pid = snapshot.rows[index].pid;
                        if connected.insert(pid) {
                            pending.push_back(Pending::Pid(pid));
                        }
                    }
                }
            }
        }
    }

    let rows: Vec<ProcessRow> = snapshot
        .rows
        .iter()
        .copied()
        .filter(|row| connected.contains(&row.pid))
        .collect();
    let mut rss_kib = 0u64;
    for row in &rows {
        rss_kib = rss_kib
            .checked_add(row.rss_kib)
            .ok_or_else(|| SnapshotError::new(None, "aggregate RSS KiB sum overflows u64"))?;
    }
    let rss_bytes = rss_kib
        .checked_mul(1024)
        .ok_or_else(|| SnapshotError::new(None, "aggregate RSS byte conversion overflows u64"))?;

    let process_ids = rows
        .iter()
        .map(|row| row.pid)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(ScopeSnapshot {
        root_present,
        rows,
        process_ids,
        process_groups: groups.into_iter().collect(),
        missing_previous_pids: missing_previous_pids.into_iter().collect(),
        rss_kib,
        rss_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const INPUT_LIMIT: usize = 4096;
    const ROW_LIMIT: usize = 32;

    fn parse(raw: &str) -> ProcessSnapshot {
        parse_ps_snapshot(raw.as_bytes(), INPUT_LIMIT, ROW_LIMIT).unwrap()
    }

    #[test]
    fn parses_exact_four_integer_columns_and_blank_lines() {
        let snapshot = parse("  10  1  10  24\n\n20 10 20 7\n");
        assert_eq!(snapshot.rows.len(), 2);
        assert_eq!(
            snapshot.rows[0],
            ProcessRow {
                pid: 10,
                ppid: 1,
                pgid: 10,
                rss_kib: 24,
            }
        );
    }

    #[test]
    fn refuses_byte_and_row_limit_excess() {
        let bytes = parse_ps_snapshot(b"1 0 1 0\n", 7, ROW_LIMIT).unwrap_err();
        assert_eq!(bytes.message, "ps output exceeds caller byte limit");

        let rows = parse_ps_snapshot(b"1 0 1 0\n2 1 1 0\n", INPUT_LIMIT, 1).unwrap_err();
        assert_eq!(rows.message, "ps row count exceeds caller limit");
    }

    #[test]
    fn refuses_malformed_non_ascii_and_overflowing_columns() {
        assert_eq!(
            parse_ps_snapshot(b"1 0 1\n", INPUT_LIMIT, ROW_LIMIT)
                .unwrap_err()
                .message,
            "expected exactly four columns"
        );
        assert_eq!(
            parse_ps_snapshot(b"1 0 1 0 extra\n", INPUT_LIMIT, ROW_LIMIT)
                .unwrap_err()
                .message,
            "expected exactly four columns"
        );
        assert_eq!(
            parse_ps_snapshot(b"1 0 1 0\xff\n", INPUT_LIMIT, ROW_LIMIT)
                .unwrap_err()
                .message,
            "ps output is not ASCII"
        );
        assert!(parse_ps_snapshot(b"4294967296 0 1 0\n", INPUT_LIMIT, ROW_LIMIT).is_err());
        assert!(
            parse_ps_snapshot(b"1 0 1 18446744073709551616\n", INPUT_LIMIT, ROW_LIMIT).is_err()
        );
    }

    #[test]
    fn refuses_plus_signs_in_ascii_decimal_columns() {
        for raw in [
            b"+1 0 1 0\n".as_slice(),
            b"1 +0 1 0\n".as_slice(),
            b"1 0 +1 0\n".as_slice(),
            b"1 0 1 +0\n".as_slice(),
        ] {
            assert!(
                parse_ps_snapshot(raw, INPUT_LIMIT, ROW_LIMIT).is_err(),
                "accepted plus-prefixed decimal column: {}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn refuses_duplicate_pids() {
        let error = parse_ps_snapshot(b"7 1 7 2\n7 1 7 3\n", INPUT_LIMIT, ROW_LIMIT).unwrap_err();
        assert_eq!(error.message, "duplicate PID in ps output");
        assert_eq!(error.line, Some(2));
    }

    #[test]
    fn closes_over_transitive_children_and_reparented_prior_members() {
        let snapshot = parse("100 1 100 4\n110 1 110 5\n120 110 120 6\n130 1 130 7\n140 1 140 8\n");
        let scope = observe_scope(&snapshot, 100, &[110, 130], &[110, 130], 32).unwrap();
        assert!(scope.root_present);
        assert_eq!(scope.process_ids, vec![100, 110, 120, 130]);
        assert_eq!(scope.rss_kib, 22);
        assert_eq!(scope.rss_bytes, 22 * 1024);
        assert_eq!(scope.missing_previous_pids, Vec::<u32>::new());
        assert!(!scope.process_ids.contains(&140));
    }

    #[test]
    fn process_ids_are_sorted_while_rows_keep_snapshot_order() {
        let snapshot = parse("120 110 120 3\n100 1 100 1\n110 100 110 2\n");
        let scope = observe_scope(&snapshot, 100, &[], &[], 32).unwrap();
        assert_eq!(
            scope.rows.iter().map(|row| row.pid).collect::<Vec<_>>(),
            vec![120, 100, 110]
        );
        assert_eq!(scope.process_ids, vec![100, 110, 120]);
    }

    #[test]
    fn closes_over_newly_observed_process_groups() {
        let snapshot = parse(
            "100 1 100 1\n110 100 200 2\n120 1 200 3\n130 120 300 4\n140 1 300 5\n900 1 900 6\n",
        );
        let scope = observe_scope(&snapshot, 100, &[], &[], 32).unwrap();
        assert_eq!(scope.process_ids, vec![100, 110, 120, 130, 140]);
        assert_eq!(scope.rss_kib, 15);
        assert!(scope.process_groups.contains(&100));
        assert!(scope.process_groups.contains(&200));
        assert!(scope.process_groups.contains(&300));
        assert!(!scope.process_ids.contains(&900));
    }

    #[test]
    fn reports_missing_root_and_missing_prior_pid_without_hiding_live_member() {
        let snapshot = parse("201 1 201 9\n900 1 900 3\n");
        let scope = observe_scope(&snapshot, 200, &[201, 202], &[201], 32).unwrap();
        assert!(!scope.root_present);
        assert_eq!(scope.process_ids, vec![201]);
        assert_eq!(scope.missing_previous_pids, vec![202]);
        assert_eq!(scope.rss_bytes, 9 * 1024);
    }

    #[test]
    fn refuses_aggregate_rss_arithmetic_overflow() {
        let snapshot = parse("100 1 100 18446744073709551615\n101 100 101 1\n");
        let error = observe_scope(&snapshot, 100, &[], &[], 32).unwrap_err();
        assert_eq!(error.message, "aggregate RSS KiB sum overflows u64");
    }

    #[test]
    fn bounds_cumulative_history_before_allocating_indexes() {
        let snapshot = parse("100 1 100 1\n110 100 110 2\n");
        let scope = observe_scope(&snapshot, 100, &[110], &[110], 2).unwrap();
        assert_eq!(scope.process_ids, vec![100, 110]);
        for (pids, groups) in [
            (&[110, 110][..], &[110][..]),
            (&[][..], &[110, 110, 110][..]),
        ] {
            let error = observe_scope(&snapshot, 100, pids, groups, 2).unwrap_err();
            assert_eq!(error.message, "process history exceeds caller entry limit");
        }
        assert!(observe_scope(&snapshot, 100, &[], &[], 0).is_ok());
    }

    #[test]
    fn refuses_zero_as_requested_target_pid() {
        let snapshot = parse("0 0 0 0\n");
        let error = observe_scope(&snapshot, 0, &[], &[], 32).unwrap_err();
        assert_eq!(
            error.message,
            "target PID must be a positive process identifier"
        );
    }

    #[test]
    fn traverses_deep_reversed_process_chain_and_preserves_row_order() {
        const DEPTH: u32 = 32_768;
        let snapshot = ProcessSnapshot {
            rows: (1..=DEPTH)
                .rev()
                .map(|pid| ProcessRow {
                    pid,
                    ppid: pid.saturating_sub(1),
                    pgid: pid,
                    rss_kib: 1,
                })
                .collect(),
        };

        let scope = observe_scope(&snapshot, 1, &[], &[], 32).unwrap();
        assert_eq!(scope.rows.len(), DEPTH as usize);
        assert_eq!(scope.rows.first().unwrap().pid, DEPTH);
        assert_eq!(scope.rows.last().unwrap().pid, 1);
        assert_eq!(scope.process_ids.first(), Some(&1));
        assert_eq!(scope.process_ids.last(), Some(&DEPTH));
        assert_eq!(scope.process_groups.first(), Some(&1));
        assert_eq!(scope.process_groups.last(), Some(&DEPTH));
        assert_eq!(scope.rss_kib, u64::from(DEPTH));
    }

    #[test]
    fn closes_cycles_and_nested_groups_without_duplicate_members() {
        let snapshot = ProcessSnapshot {
            rows: vec![
                ProcessRow {
                    pid: 700,
                    ppid: 600,
                    pgid: 700,
                    rss_kib: 7,
                },
                ProcessRow {
                    pid: 300,
                    ppid: 999,
                    pgid: 300,
                    rss_kib: 3,
                },
                ProcessRow {
                    pid: 100,
                    ppid: 200,
                    pgid: 100,
                    rss_kib: 1,
                },
                ProcessRow {
                    pid: 600,
                    ppid: 999,
                    pgid: 500,
                    rss_kib: 6,
                },
                ProcessRow {
                    pid: 200,
                    ppid: 100,
                    pgid: 300,
                    rss_kib: 2,
                },
                ProcessRow {
                    pid: 500,
                    ppid: 300,
                    pgid: 500,
                    rss_kib: 5,
                },
                ProcessRow {
                    pid: 900,
                    ppid: 900,
                    pgid: 900,
                    rss_kib: 9,
                },
            ],
        };

        let scope = observe_scope(&snapshot, 100, &[], &[], 32).unwrap();
        assert_eq!(
            scope.rows.iter().map(|row| row.pid).collect::<Vec<_>>(),
            vec![700, 300, 100, 600, 200, 500]
        );
        assert_eq!(scope.process_ids, vec![100, 200, 300, 500, 600, 700]);
        assert_eq!(scope.process_groups, vec![100, 300, 500, 700]);
        assert_eq!(scope.rss_kib, 24);
        assert!(!scope.process_ids.contains(&900));
    }
}

#[cfg(test)]
mod historical_linkage_regression {
    use super::*;
    #[test]
    fn absent_prior_parent_still_links_a_visible_child_during_table_churn() {
        let snapshot = parse_ps_snapshot(b"100 1 100 2\n102 101 102 3\n", 1024, 8).unwrap();
        let scope = observe_scope(&snapshot, 100, &[101], &[101], 32).unwrap();
        assert_eq!(scope.process_ids, vec![100, 102]);
        assert_eq!(scope.missing_previous_pids, vec![101]);
        assert_eq!(scope.rss_bytes, 5 * 1024);
        // PID 101 is a linkage observation; it is absent from measured rows
        // and grants no permission to signal a process with that number.
        assert!(!scope.rows.iter().any(|row| row.pid == 101));
    }
}
