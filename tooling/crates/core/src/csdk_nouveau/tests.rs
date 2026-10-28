use super::{
    COMPILER_ENV_DIRECTORY, COMPILER_HOME_DIRECTORY, COMPILER_TEMP_DIRECTORY, CompileCommand,
    EXPECTED_OBJECTS, LOG_DIRECTORY, MAX_LOG_BYTES_PER_STREAM, PathIdentity, RunConfig,
    compiler_environment, create_output_parents, run_commands, saved_stream,
    validate_fresh_outputs, verify_compiler,
};
use crate::{
    digest::sha256_file,
    directory::Directory,
    resource_capture::{ResourceLimits, SampleLimits},
    workspace_accounting::ScanLimits,
};
use serde_json::Value;
use std::{
    fs,
    os::unix::{fs::PermissionsExt, fs::symlink},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).expect("canonicalize temporary root");
        for _ in 0..100 {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                ".csdk-nouveau-executor-test-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create unique test directory: {error}"),
            }
        }
        panic!("could not allocate a unique test directory");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove executor fixture");
    }
}

struct Fixture {
    _temporary: TempDir,
    source_root: PathBuf,
    build_root: PathBuf,
    toolchain_root: PathBuf,
    work_dir: PathBuf,
    compiler: PathBuf,
    source: PathBuf,
    include: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = TempDir::new();
        let root = &temporary.0;
        let source_root = root.join("source");
        let build_root = root.join("build");
        let toolchain_root = root.join("toolchain");
        let work_dir = root.join("work");
        let source_dir = source_root.join("src");
        let include = source_root.join("include");
        let bin = toolchain_root.join("bin");
        for path in [&source_dir, &include, &build_root, &bin, &work_dir] {
            fs::create_dir_all(path).expect("create fixture directory");
        }
        let source = source_dir.join("unit.c");
        fs::write(&source, b"int fixture;\n").expect("write source fixture");
        fs::write(include.join("fixture.h"), b"/* fixture */\n").expect("write header fixture");
        let compiler = bin.join("clang-11");
        fs::write(
            &compiler,
            b"#!/bin/sh\n\
for argument in \"$@\"; do\n\
  case \"$argument\" in\n\
    -DOMIT) exit 0 ;;\n\
    -DFAIL) /bin/sleep 0.2; printf 'fixture compiler failure\\n' >&2; exit 17 ;;\n\
    -DSLEEP) /bin/sleep 30 ;;\n\
    -DBURST) /usr/bin/head -c 600000 /dev/zero; exit 0 ;;\n\
  esac\n\
done\n\
output=\n\
while [ \"$#\" -gt 0 ]; do\n\
  if [ \"$1\" = \"-o\" ]; then shift; output=$1; break; fi\n\
  shift\n\
done\n\
[ -n \"$output\" ] || exit 19\n\
printf 'object bytes\\n' > \"$output\"\n\
printf 'fixture compiler output\\n'\n",
        )
        .expect("write fake compiler");
        fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755))
            .expect("make fake compiler executable");
        Self {
            _temporary: temporary,
            source_root,
            build_root,
            toolchain_root,
            work_dir,
            compiler,
            source,
            include,
        }
    }

    fn command(&self, index: usize, mode: Option<&str>) -> CompileCommand {
        let object = self.build_root.join(format!("objects/unit{index}.o"));
        let mut argv = vec![self.compiler.display().to_string()];
        if let Some(mode) = mode {
            argv.push(mode.to_owned());
        }
        argv.extend([
            "-o".to_owned(),
            object.display().to_string(),
            "-c".to_owned(),
            self.source.display().to_string(),
        ]);
        CompileCommand {
            source: self.source.clone(),
            object,
            argv,
            include_paths: vec![self.include.clone()],
        }
    }

    fn execute(
        &self,
        commands: &[CompileCommand],
        jobs: usize,
        timeout: Duration,
        cancellation: impl FnMut() -> bool,
    ) -> Value {
        create_output_parents(commands, &self.build_root).expect("create output parents");
        let work = Directory::open(&self.work_dir).expect("open work directory");
        let environment_directory = work
            .mkdir_new(std::ffi::OsStr::new(COMPILER_ENV_DIRECTORY), 0o700)
            .expect("create compiler environment directory");
        environment_directory
            .mkdir_new(std::ffi::OsStr::new(COMPILER_HOME_DIRECTORY), 0o700)
            .expect("create private compiler home");
        environment_directory
            .mkdir_new(std::ffi::OsStr::new(COMPILER_TEMP_DIRECTORY), 0o700)
            .expect("create private compiler temporary directory");
        let logs = work
            .mkdir_new(std::ffi::OsStr::new(LOG_DIRECTORY), 0o700)
            .expect("create log directory");
        let environment = compiler_environment(&self.toolchain_root, &self.work_dir)
            .expect("build controlled compiler environment");
        let roots = vec![
            self.source_root.clone(),
            self.build_root.clone(),
            self.toolchain_root.clone(),
            self.work_dir.clone(),
        ];
        let identities = [
            PathIdentity::capture(&self.source_root, "source root").expect("capture source root"),
            PathIdentity::capture(&self.build_root, "build root").expect("capture build root"),
            PathIdentity::capture(&self.toolchain_root, "toolchain root")
                .expect("capture toolchain root"),
            PathIdentity::capture(&self.work_dir, "work directory")
                .expect("capture work directory"),
        ];
        let abort = Arc::new(AtomicBool::new(false));
        let warning_bytes = Arc::new(AtomicU64::new(0));
        let mut cancellation = cancellation;
        run_commands(
            commands,
            RunConfig {
                compiler: &self.compiler,
                working_directory: &self.build_root,
                work_dir: &self.work_dir,
                logs_directory: &logs,
                roots: &roots,
                identities: &identities,
                jobs,
                deadline: Instant::now() + timeout,
                resource_limits: ResourceLimits {
                    max_visible_rss_bytes: u64::MAX,
                    max_workspace_bytes: u64::MAX,
                    max_log_bytes: u64::MAX,
                },
                sample_limits: SampleLimits {
                    max_ps_bytes: 2 * 1024 * 1024,
                    max_ps_rows: 32_768,
                    max_history_entries: 32_768,
                    max_roots: roots.len(),
                    scan: ScanLimits {
                        max_entries: 10_000,
                        max_work_units: 20_001,
                    },
                },
                abort,
                warning_bytes,
                environment: &environment,
            },
            &mut cancellation,
        )
        .expect("run small compiler fixture set")
    }

    fn log(&self, index: usize, stream: &str) -> Vec<u8> {
        fs::read(
            self.work_dir
                .join(LOG_DIRECTORY)
                .join(format!("{index:04}.{stream}.log")),
        )
        .expect("read compiler log")
    }
}

#[test]
fn executes_fake_compiler_directly_and_saves_bounded_output() {
    let fixture = Fixture::new();
    let command = fixture.command(0, None);
    let summary = fixture.execute(
        std::slice::from_ref(&command),
        1,
        Duration::from_secs(10),
        || false,
    );

    assert_eq!(summary["worker_threads_started"], 1);
    assert_eq!(summary["completed"], 1);
    assert_eq!(summary["failure"], Value::Null);
    assert_eq!(
        fs::read(&command.object).expect("read compiler object"),
        b"object bytes\n"
    );
    assert_eq!(fixture.log(0, "stdout"), b"fixture compiler output\n");
    assert!(fixture.log(0, "stderr").is_empty());
}

#[test]
fn compiler_failure_cancels_active_sibling_and_retains_failure_logs() {
    let fixture = Fixture::new();
    let commands = [
        fixture.command(0, Some("-DFAIL")),
        fixture.command(1, Some("-DSLEEP")),
    ];
    let summary = fixture.execute(&commands, 2, Duration::from_secs(10), || false);

    assert_eq!(summary["worker_threads_started"], 2);
    assert_eq!(summary["completed"], 0);
    assert_eq!(summary["failed_index"], 0);
    assert!(summary["failure"].as_str().unwrap().contains("status 17"));
    assert!(
        String::from_utf8_lossy(&fixture.log(0, "stderr")).contains("fixture compiler failure")
    );
    assert!(!commands[1].object.exists());
    let runs = summary["compiler_runs"].as_array().expect("compiler runs");
    assert_eq!(runs.len(), 2);
    assert!(
        runs.iter()
            .all(|run| run["incomplete_process_cleanup"] == false)
    );
}

#[test]
fn per_stream_overflow_is_a_failure_with_a_bounded_truncation_log() {
    let fixture = Fixture::new();
    let command = fixture.command(0, Some("-DBURST"));
    let summary = fixture.execute(
        std::slice::from_ref(&command),
        1,
        Duration::from_secs(10),
        || false,
    );

    assert_eq!(summary["completed"], 0);
    assert!(summary["failure"].as_str().unwrap().contains("per-stream"));
    let stdout = fixture.log(0, "stdout");
    assert!(stdout.len() <= MAX_LOG_BYTES_PER_STREAM);
    assert!(
        stdout.ends_with(b"[truncated: retained bounded output prefix; compile attempt failed]\n")
    );
}

#[test]
fn overall_timeout_terminates_fake_compiler_process_group() {
    let fixture = Fixture::new();
    let command = fixture.command(0, Some("-DSLEEP"));
    let summary = fixture.execute(
        std::slice::from_ref(&command),
        1,
        Duration::from_millis(300),
        || false,
    );

    assert_eq!(summary["completed"], 0);
    assert!(summary["failure"].as_str().unwrap().contains("deadline"));
    assert!(!command.object.exists());
}

#[test]
fn caller_cancellation_terminates_fake_compiler_process_group() {
    let fixture = Fixture::new();
    let command = fixture.command(0, Some("-DSLEEP"));
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancelled);
    let trigger = thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        signal.store(true, Ordering::Release);
    });
    let summary = fixture.execute(
        std::slice::from_ref(&command),
        1,
        Duration::from_secs(10),
        || cancelled.load(Ordering::Acquire),
    );
    trigger.join().expect("join cancellation trigger");

    assert_eq!(summary["cancelled"], true);
    assert!(summary["failure"].as_str().unwrap().contains("cancelled"));
    assert!(!command.object.exists());
}

#[test]
fn success_without_a_regular_object_is_a_compile_failure() {
    let fixture = Fixture::new();
    let command = fixture.command(0, Some("-DOMIT"));
    let summary = fixture.execute(
        std::slice::from_ref(&command),
        1,
        Duration::from_secs(10),
        || false,
    );

    assert_eq!(summary["completed"], 0);
    assert!(
        summary["failure"]
            .as_str()
            .unwrap()
            .contains("without a regular object")
    );
    assert!(!command.object.exists());
}

#[test]
fn compiler_pin_accepts_only_the_expected_executable_bytes() {
    let fixture = Fixture::new();
    let expected = sha256_file(&fixture.compiler).expect("hash fake compiler");

    assert_eq!(
        verify_compiler(&fixture.compiler, &expected).unwrap(),
        expected
    );
    let wrong = "0".repeat(64);
    assert!(
        verify_compiler(&fixture.compiler, &wrong)
            .unwrap_err()
            .to_string()
            .contains("SHA-256 differs")
    );
}

#[test]
fn fresh_outputs_require_unique_missing_files_without_symlink_components() {
    let fixture = Fixture::new();
    let commands = (0..EXPECTED_OBJECTS)
        .map(|index| CompileCommand {
            source: fixture.source.clone(),
            object: fixture
                .build_root
                .join(format!("objects/object{index:04}.o")),
            argv: Vec::new(),
            include_paths: Vec::new(),
        })
        .collect::<Vec<_>>();

    validate_fresh_outputs(&commands, &fixture.build_root).expect("fresh planned outputs");

    fs::create_dir_all(commands[0].object.parent().unwrap()).expect("create output parent");
    fs::write(&commands[0].object, b"stale").expect("create stale output");
    assert!(
        validate_fresh_outputs(&commands, &fixture.build_root)
            .unwrap_err()
            .to_string()
            .contains("fresh Nouveau object output")
    );
    fs::remove_file(&commands[0].object).expect("remove stale output");
    symlink(&fixture.source, &commands[1].object).expect("create output symlink");
    assert!(
        validate_fresh_outputs(&commands, &fixture.build_root)
            .unwrap_err()
            .to_string()
            .contains("traverses a symlink")
    );
}

#[test]
fn truncated_stream_saves_short_prefix_without_slicing_past_it() {
    let saved = saved_stream(b"short prefix", true, true);

    assert!(saved.starts_with(b"short prefix"));
    assert!(
        saved.ends_with(b"[truncated: retained bounded output prefix; compile attempt failed]\n")
    );
    assert!(saved.len() < MAX_LOG_BYTES_PER_STREAM);
    assert!(saved_stream(b"short prefix", true, false).is_empty());
}

#[test]
fn historical_counter_preserves_recipe_and_refuses_ambiguous_mapping() {
    let mut plan = serde_json::json!({
        "source_root":"/source with spaces", "build_root":"/build",
        "ordered_object_paths":["/build/normal.o"],
        "commands":[{"object":"/build/normal.o", "source":"/source with spaces/a.c",
          "argv":["/tools/clang", "-I/build/SDK/include", "-ffile-prefix-map=/source with spaces=.",
          "-c", "/source with spaces/a.c", "-o", "/build/normal.o"]}]
    });
    let original = plan.clone();
    super::historical_counter_plan(&mut plan, "/historical/source").unwrap();
    assert_eq!(
        plan["commands"][0]["source"],
        original["commands"][0]["source"]
    );
    assert_eq!(plan["commands"][0]["argv"][1], "-I/build/SDK/include");
    assert_eq!(
        plan["commands"][0]["argv"][2],
        "-ffile-prefix-map=/source with spaces=/historical/source"
    );
    assert_eq!(
        plan["commands"][0]["object"],
        "/build/historical-prefix-counter/0.obj"
    );
    assert_eq!(
        plan["ordered_object_paths"][0],
        plan["commands"][0]["object"]
    );
    let mut ambiguous = original;
    ambiguous["commands"][0]["argv"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("-ffile-prefix-map=/source with spaces=."));
    assert!(super::historical_counter_plan(&mut ambiguous, "/historical/source").is_err());
    assert!(super::historical_counter_plan(&mut plan, "relative").is_err());
}
