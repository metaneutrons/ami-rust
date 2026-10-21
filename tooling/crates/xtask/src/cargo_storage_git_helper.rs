//! Actual host Cargo Git credential-helper lookup against a refusing loopback server.
//!
//! The fixture uses a real local Git repository only to create a valid lockfile.
//! Its test fetch is HTTP smart transport to loopback and always ends in 401.

use super::*;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    os::unix::fs::OpenOptionsExt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const FAKE_USERNAME: &str = "rc2-git-fixture-user";
const FAKE_PASSWORD: &str = "rc2-git-fixture-password";
const GIT_ROUTE: &str = "/repository/info/refs?service=git-upload-pack";
const MAX_HELPER_STDIN_BYTES: usize = 16 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_REQUESTS: usize = 24;
const MAX_HELPER_EVENTS: usize = 64;
const READ_TIMEOUT: Duration = Duration::from_millis(400);
const WRITE_TIMEOUT: Duration = Duration::from_millis(400);
const ACCEPT_POLL: Duration = Duration::from_millis(5);

#[derive(Clone, Debug)]
struct RequestObservation {
    route: &'static str,
    authorization_matches: bool,
    helper_get_preceded_authorization: bool,
}

/// Owns a bounded loopback-only HTTP server. Drop requests stop and joins it.
struct GitAuthFixture {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    observations: Arc<Mutex<Vec<RequestObservation>>>,
    worker: Option<JoinHandle<()>>,
}

impl GitAuthFixture {
    fn start(helper_observations: &Path) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let resolved = ("localhost", address.port())
            .to_socket_addrs()?
            .collect::<Vec<_>>();
        if resolved.is_empty() || resolved.iter().any(|address| !address.ip().is_loopback()) {
            return Err(std::io::Error::other(
                "localhost fixture resolution is not loopback-only",
            ));
        }

        if !address.ip().is_loopback() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "Git helper fixture did not bind to loopback",
            ));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let expected_authorization = expected_basic_authorization();
        let worker_stop = Arc::clone(&stop);
        let worker_observations = Arc::clone(&observations);
        let worker_helper_observations = helper_observations.to_path_buf();
        let worker = thread::Builder::new()
            .name("rc2-git-auth-fixture".to_owned())
            .spawn(move || {
                serve(
                    listener,
                    worker_stop,
                    worker_observations,
                    worker_helper_observations,
                    expected_authorization,
                );
            })?;
        Ok(Self {
            address,
            stop,
            observations,
            worker: Some(worker),
        })
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn repository_url(&self) -> String {
        format!("http://localhost:{}/repository", self.address.port())
    }

    fn sanitized_observations(&self) -> Vec<Value> {
        self.observations
            .lock()
            .map(|observations| {
                observations
                    .iter()
                    .map(|observation| {
                        json!({
                            "route": observation.route,
                            "authorization_matches": observation.authorization_matches,
                            "helper_get_preceded_authorization": observation.helper_get_preceded_authorization
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Drop for GitAuthFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Git credential-helper entry point for the parent xtask dispatcher.
///
/// Git appends `get`, `store`, or `erase` to the configured command. The helper
/// reads at most 16 KiB, never persists credential-protocol values, and emits
/// credentials only for a matching synthetic loopback `get` request.
pub(super) fn helper(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let (observation_dir, expected_host, action) = parse_helper_arguments(arguments)?;
    if !plain_directory(&observation_dir)? {
        return Err(Refusal::new(
            "Git credential helper observation path is not a plain directory",
        ));
    }
    let expected_socket = expected_host
        .parse::<SocketAddr>()
        .map_err(|_| Refusal::new("Git credential helper expected host is invalid"))?;
    if !expected_socket.ip().is_loopback() || expected_socket.port() == 0 {
        return Err(Refusal::new(
            "Git credential helper only accepts a nonzero loopback port",
        ));
    }

    let request = read_credential_request()?;
    // Pinned git2::CredentialHelper emits host only for URL Host::Domain;
    // the fixture uses localhost rather than an IPv4 literal for this reason.
    let protocol_host = format!("localhost:{}", expected_socket.port());
    let host_matches = request.host.as_deref() == Some(protocol_host.as_str());
    let protocol_matches = request.protocol.as_deref() == Some("http");
    let response_emitted = action == "get" && host_matches && protocol_matches;
    write_helper_observation(
        &observation_dir,
        &action,
        if host_matches {
            "loopback"
        } else {
            "other-or-missing"
        },
        if protocol_matches {
            "http"
        } else {
            "other-or-missing"
        },
        response_emitted,
    )?;

    if response_emitted {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(
            format!("username={FAKE_USERNAME}\npassword={FAKE_PASSWORD}\n\n").as_bytes(),
        )?;
        stdout.flush()?;
    }
    Ok(())
}

pub(super) fn run(probe: &mut Probe<'_>, report: &mut Value) -> Result<()> {
    report["fixture_kind"] = json!("storage-git-credential-helper");
    report["scope"] = json!(
        "Actual original/derived host Cargo lookup of a synthetic Git credential helper and expected HTTP 401 refusal; no successful authenticated smart-HTTP clone is qualified."
    );
    report["limitations"] = json!([
        "Uses fixed synthetic credentials and an IPv4 loopback HTTP server; it does not access real credentials or external Git hosts.",
        "The fetch backend is Cargo's default libgit2 path with net.git-fetch-with-cli=false; there is no Git CLI comparison.",
        "This fixture does not promise a successful authenticated smart-HTTP clone, full RC2 acceptance, consumer SDK activation, AROS qualification, or publication.",
        "Loopback routing is fixture-specific and is not a general network sandbox."
    ]);

    let control = tool(probe, "control-cargo")?;
    let derived = tool(probe, "derived-cargo")?;
    let rustc = tool(probe, "rustc")?;
    let rustdoc = tool(probe, "rustdoc")?;
    let git = tool(probe, "git")?;
    let helper_executable = fs::canonicalize(std::env::current_exe()?)
        .map_err(|error| Refusal::new(format!("cannot resolve helper executable: {error}")))?;

    let temporary = probe.work.join("temporary");
    create_private_directory(&temporary)?;
    let bootstrap = probe.work.join("git helper bootstrap with spaces");
    create_private_directory(&bootstrap)?;
    let bootstrap_home = bootstrap.join("home");
    let bootstrap_cargo_home = bootstrap.join("cargo home");
    create_private_directory(&bootstrap_home)?;
    create_private_directory(&bootstrap_cargo_home)?;
    probe.set_base_env(
        &bootstrap_cargo_home,
        &bootstrap_home,
        &rustc,
        &rustdoc,
        &git,
    );
    let git_env = probe.base_env.clone();

    let source_repository = probe.work.join("local Git source with spaces");
    let source_commit = prepare_source_repository(probe, &git, &git_env, &source_repository)?;
    report["fixtures"]["git_auth_source_commit"] = json!(source_commit);

    let mut cases = Vec::new();
    for (name, cargo, is_derived, selected) in [
        ("control-selected", &control, false, true),
        ("derived-selected", &derived, true, true),
        ("control-selector-absent", &control, false, false),
        ("derived-selector-absent", &derived, true, false),
    ] {
        cases.push(case_run(
            probe,
            report,
            name,
            &control,
            cargo,
            is_derived,
            selected,
            true,
            &git,
            &rustc,
            &rustdoc,
            &helper_executable,
            &source_repository,
            &source_commit,
        )?);
    }
    cases.push(case_run(
        probe,
        report,
        "derived-no-helper-negative",
        &control,
        &derived,
        true,
        true,
        false,
        &git,
        &rustc,
        &rustdoc,
        &helper_executable,
        &source_repository,
        &source_commit,
    )?);

    for (left, right, label) in [
        (0, 2, "control-selected-versus-selector-absent"),
        (1, 3, "derived-selected-versus-selector-absent"),
    ] {
        let left = &cases[left];
        let right = &cases[right];
        add_check(
            report,
            label,
            left["required_route_seen"] == right["required_route_seen"]
                && left["authenticated_retry_seen"] == right["authenticated_retry_seen"]
                && left["helper_get_preceded_matching_retry"]
                    == right["helper_get_preceded_matching_retry"]
                && left["helper_get_seen"] == right["helper_get_seen"]
                && left["cargo_auth_refusal_seen"] == right["cargo_auth_refusal_seen"]
                && left["no_checkout"] == right["no_checkout"],
            json!({"selected":left,"selector_absent":right}),
        )?;
    }

    let negative = &cases[4];
    add_check(
        report,
        "no-helper-negative-has-no-get-and-no-matching-authorization",
        negative["required_route_seen"] == true
            && negative["helper_get_seen"] == false
            && negative["authenticated_retry_seen"] == false
            && negative["no_matching_authorization_seen"] == true
            && negative["cargo_auth_refusal_seen"] == true
            && negative["no_checkout"] == true,
        json!({
            "required_route_seen":negative["required_route_seen"],
            "helper_get_seen":negative["helper_get_seen"],
            "authenticated_retry_seen":negative["authenticated_retry_seen"],
            "no_matching_authorization_seen":negative["no_matching_authorization_seen"],
            "cargo_auth_refusal_seen":negative["cargo_auth_refusal_seen"],
            "no_checkout":negative["no_checkout"]
        }),
    )?;
    report["fixtures"]["git_credential_helper"] = json!(cases);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn case_run(
    probe: &mut Probe<'_>,
    report: &mut Value,
    name: &str,
    lock_cargo: &Path,
    cargo: &Path,
    is_derived: bool,
    selected: bool,
    helper_enabled: bool,
    git: &Path,
    rustc: &Path,
    rustdoc: &Path,
    helper_executable: &Path,
    source_repository: &Path,
    source_commit: &str,
) -> Result<Value> {
    let root = probe.work.join(name);
    create_private_directory(&root)?;
    let home = root.join("private home with spaces");
    let cargo_home = root.join("original cargo home");
    let selected_store = root.join("selected storage root");
    let project = root.join("locked project with spaces");
    let seed_home = root.join("offline lock seed home");
    let seed_cargo_home = root.join("offline lock seed cargo home");
    let helper_observations = root.join("sanitized helper observations");
    for directory in [
        &home,
        &cargo_home,
        &selected_store,
        &project,
        &seed_home,
        &seed_cargo_home,
        &helper_observations,
    ] {
        create_private_directory(directory)?;
    }
    create_private_directory(&project.join("src"))?;

    probe.set_base_env(&cargo_home, &home, rustc, rustdoc, git);
    let mut cargo_env = probe.base_env.clone();
    insert_env(&mut cargo_env, "GIT_ALLOW_PROTOCOL", OsStr::new("http"));
    insert_env(&mut cargo_env, "GIT_TERMINAL_PROMPT", OsStr::new("0"));
    if selected {
        cargo_env = with_selector(&cargo_env, &selected_store);
    }

    write_text(
        &cargo_home.join("config.toml"),
        "[net]\ngit-fetch-with-cli = false\nretry = 0\n",
    )?;
    write_text(
        &cargo_home.join("credentials.toml"),
        "# Synthetic fixture intentionally stores no Cargo credentials.\n",
    )?;
    let original_config = file_fingerprint(&cargo_home.join("config.toml"))?;
    let original_credentials = file_fingerprint(&cargo_home.join("credentials.toml"))?;

    write_text(
        &seed_cargo_home.join("config.toml"),
        "[net]\ngit-fetch-with-cli = false\nretry = 0\n",
    )?;
    let server = GitAuthFixture::start(&helper_observations)?;
    let repository_url = server.repository_url();
    let expected_host = server.address().to_string();
    let file_rewrite = file_rewrite_config(source_repository, &repository_url)?;
    write_text(&seed_home.join(".gitconfig"), &file_rewrite)?;
    write_text(
        &project.join("Cargo.toml"),
        &format!(
            "[package]\nname = \"rc2-git-auth-client\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nrc2-git-auth-fixture = {{ git = \"{repository_url}\" }}\n"
        ),
    )?;
    write_text(&project.join("src/main.rs"), "fn main() {}\n")?;

    let mut lock_env = probe.base_env.clone();
    insert_env(&mut lock_env, "HOME", seed_home.as_os_str());
    insert_env(&mut lock_env, "CARGO_HOME", seed_cargo_home.as_os_str());
    insert_env(&mut lock_env, "GIT_ALLOW_PROTOCOL", OsStr::new("file:http"));
    probe.cargo(
        &format!("{name}-local-file-lock-seed"),
        lock_cargo,
        strings(["generate-lockfile"]),
        &project,
        &lock_env,
        0,
    )?;

    let lock_path = project.join("Cargo.lock");
    let lock_before = file_fingerprint(&lock_path)?;
    let lock_text = fs::read_to_string(&lock_path).map_err(|error| {
        Refusal::new(format!(
            "cannot read generated Git fixture lockfile: {error}"
        ))
    })?;
    let lock_is_valid_for_fixture = lock_text.contains("name = \"rc2-git-auth-fixture\"")
        && lock_text.contains(&repository_url)
        && lock_text.contains("source = \"git+")
        && lock_text.contains(source_commit);
    add_check(
        report,
        &format!("{name}-lockfile-identifies-local-git-source"),
        lock_is_valid_for_fixture,
        json!({
            "lockfile":file_fingerprint(&lock_path)?,
            "contains_fixture_package":lock_text.contains("name = \"rc2-git-auth-fixture\""),
            "contains_loopback_source":lock_text.contains(&repository_url),
            "contains_git_source":lock_text.contains("source = \"git+"),
            "contains_local_repository_commit":lock_text.contains(source_commit)
        }),
    )?;
    let lock_seed_requests = server.sanitized_observations();
    add_check(
        report,
        &format!("{name}-lock-generation-did-not-contact-loopback-server"),
        lock_seed_requests.is_empty(),
        json!({"request_count":lock_seed_requests.len(),"requests":lock_seed_requests}),
    )?;

    let helper_config = if helper_enabled {
        credential_helper_config(helper_executable, &helper_observations, &expected_host)?
    } else {
        "# Deliberately no credential.helper entry.\n".to_owned()
    };
    write_text(&home.join(".gitconfig"), &helper_config)?;
    let git_home_before = snapshot(&home)?;
    let original_cargo_home_before = snapshot(&cargo_home)?;

    let fetched = probe.cargo(
        &format!("{name}-fetch-locked-refusal"),
        cargo,
        strings(["fetch", "--locked"]),
        &project,
        &cargo_env,
        101,
    )?;
    let cargo_auth_refusal_seen = contains_auth_refusal_marker(&fetched.stderr);
    let requests = server.sanitized_observations();
    let required_route_requests = requests
        .iter()
        .filter(|row| row["route"] == GIT_ROUTE)
        .collect::<Vec<_>>();
    let required_route_seen = !required_route_requests.is_empty();
    let unauthenticated_request_seen = required_route_requests
        .iter()
        .any(|row| row["authorization_matches"] == false);
    let authenticated_retry_seen = required_route_requests
        .iter()
        .any(|row| row["authorization_matches"] == true);
    let helper_get_preceded_matching_retry = required_route_requests.iter().any(|row| {
        row["authorization_matches"] == true && row["helper_get_preceded_authorization"] == true
    });
    let no_matching_authorization_seen = required_route_seen && !authenticated_retry_seen;

    let helper_events = read_helper_observations(&helper_observations)?;
    let helper_get_seen = helper_events.iter().any(|row| {
        row["action"] == "get"
            && row["host"] == "loopback"
            && row["protocol"] == "http"
            && row["response_emitted"] == true
    });

    add_check(
        report,
        &format!("{name}-cargo-authentication-refusal"),
        cargo_auth_refusal_seen && unauthenticated_request_seen,
        json!({
            "exit_code":101,
            "authentication_refusal_marker":cargo_auth_refusal_seen,
            "unauthenticated_protected_request_seen":unauthenticated_request_seen
        }),
    )?;
    if helper_enabled {
        add_check(
            report,
            &format!("{name}-helper-get-followed-by-matching-protected-retry"),
            helper_get_seen && authenticated_retry_seen && helper_get_preceded_matching_retry,
            json!({
                "helper_events":helper_events,
                "requests":requests,
                "helper_get_preceded_matching_retry":helper_get_preceded_matching_retry,
                "required_route":GIT_ROUTE
            }),
        )?;
    } else {
        add_check(
            report,
            &format!("{name}-no-helper-get-and-no-matching-authorization"),
            helper_events.is_empty() && no_matching_authorization_seen,
            json!({
                "helper_event_count":helper_events.len(),
                "requests":requests,
                "required_route":GIT_ROUTE
            }),
        )?;
    }

    let config_after = file_fingerprint(&cargo_home.join("config.toml"))?;
    let credentials_after = file_fingerprint(&cargo_home.join("credentials.toml"))?;
    let lock_after = file_fingerprint(&lock_path)?;
    let cargo_home_intact =
        original_config == config_after && original_credentials == credentials_after;
    let lock_intact = lock_before == lock_after;
    add_check(
        report,
        &format!("{name}-original-cargo-config-credentials-and-lock-preserved"),
        cargo_home_intact
            && lock_intact
            && git_home_before == snapshot(&home)?
            && (!(selected && is_derived) || original_cargo_home_before == snapshot(&cargo_home)?),
        json!({
            "config_before":original_config,
            "config_after":config_after,
            "credentials_before":original_credentials,
            "credentials_after":credentials_after,
            "lock_before":lock_before,
            "lock_after":lock_after
        }),
    )?;

    let original_git = snapshot(&cargo_home.join("git"))?;
    let selected_git = snapshot(&selected_store.join("git"))?;
    let original_checkouts = checkout_manifest_count(&cargo_home.join("git/checkouts"))?;
    let selected_checkouts = checkout_manifest_count(&selected_store.join("git/checkouts"))?;
    let no_checkout = original_checkouts == 0 && selected_checkouts == 0;
    let wrong_store_git_absent = if selected && is_derived {
        original_git.is_empty()
    } else {
        selected_git.is_empty()
    };

    add_check(
        report,
        &format!("{name}-refusal-created-no-checkout"),
        no_checkout && wrong_store_git_absent,
        json!({
            "original_cargo_home_checkout_manifests":original_checkouts,
            "selected_storage_root_checkout_manifests":selected_checkouts,
            "wrong_store_git_absent":wrong_store_git_absent,
            "expected_cache_root":if selected && is_derived { "selected-storage-root" } else { "original-cargo-home" },
            "original_cargo_home_git_tree":original_git,
            "selected_storage_root_git_tree":selected_git
        }),
    )?;

    let helper_observation_count = helper_events.len();
    Ok(json!({
        "name":name,
        "cargo":if is_derived { "derived" } else { "control" },
        "selector_present":selected,
        "expected_cache_root":if selected && is_derived { "selected-storage-root" } else { "original-cargo-home" },
        "fetch_exit_code":101,
        "required_route_seen":required_route_seen,
        "unauthenticated_request_seen":unauthenticated_request_seen,
        "authenticated_retry_seen":authenticated_retry_seen,
        "helper_get_preceded_matching_retry":helper_get_preceded_matching_retry,
        "no_matching_authorization_seen":no_matching_authorization_seen,
        "helper_get_seen":helper_get_seen,
        "helper_observation_count":helper_observation_count,
        "cargo_auth_refusal_seen":cargo_auth_refusal_seen,
        "cargo_config_credentials_preserved":cargo_home_intact,
        "lockfile_preserved":lock_intact,
        "no_checkout":no_checkout,
        "requests":requests,
        "helper_events":helper_events,
        "original_cargo_home_git_tree":original_git,
        "selected_storage_root_git_tree":selected_git
    }))
}

fn prepare_source_repository(
    probe: &mut Probe<'_>,
    git: &Path,
    env: &BTreeMap<OsString, OsString>,
    repository: &Path,
) -> Result<String> {
    create_private_directory(repository)?;
    create_private_directory(&repository.join("src"))?;
    write_text(
        &repository.join("Cargo.toml"),
        "[package]\nname = \"rc2-git-auth-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[lib]\npath = \"src/lib.rs\"\n",
    )?;
    write_text(
        &repository.join("src/lib.rs"),
        "pub fn fixture_value() -> u8 { 7 }\n",
    )?;
    probe.command(
        "git-helper-source-init",
        git,
        strings(["init", "--quiet"]),
        repository,
        env,
        0,
    )?;
    probe.command(
        "git-helper-source-add",
        git,
        strings(["add", "--all"]),
        repository,
        env,
        0,
    )?;
    probe.command(
        "git-helper-source-commit",
        git,
        strings([
            "commit",
            "--quiet",
            "-m",
            "create synthetic Git credential source",
        ]),
        repository,
        env,
        0,
    )?;
    let commit = probe.command(
        "git-helper-source-rev-parse",
        git,
        strings(["rev-parse", "--verify", "HEAD"]),
        repository,
        env,
        0,
    )?;
    let commit = String::from_utf8(commit.stdout)
        .map_err(|_| Refusal::new("synthetic Git source commit id is not UTF-8"))?
        .trim()
        .to_owned();
    if !matches!(commit.len(), 40 | 64) || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Refusal::new("synthetic Git source commit id is malformed"));
    }
    Ok(commit)
}

fn file_rewrite_config(repository: &Path, source_url: &str) -> Result<String> {
    let local_url = file_uri(repository)?;
    Ok(format!(
        "[url \"{local_url}\"]\n\tinsteadOf = {source_url}\n"
    ))
}

fn credential_helper_config(
    executable: &Path,
    observations: &Path,
    expected_host: &str,
) -> Result<String> {
    let command = format!(
        "!{} --rc2-git-credential --observations {} --expected-host {}",
        shell_quote(executable.as_os_str())?,
        shell_quote(observations.as_os_str())?,
        shell_quote(OsStr::new(expected_host))?
    );
    Ok(format!("[credential]\n\thelper = {command}\n"))
}

fn shell_quote(value: &OsStr) -> Result<String> {
    let value = value
        .to_str()
        .ok_or_else(|| Refusal::new("Git helper command path is not UTF-8"))?;
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

fn tool(probe: &Probe<'_>, name: &str) -> Result<PathBuf> {
    probe
        .tools
        .iter()
        .find(|row| row.name == name)
        .map(|row| row.path.clone())
        .ok_or_else(|| Refusal::new(format!("missing prepared {name} tool")))
}

fn parse_helper_arguments(
    arguments: impl Iterator<Item = OsString>,
) -> Result<(PathBuf, String, String)> {
    let mut observation_dir = None;
    let mut expected_host = None;
    let mut action = None;
    let mut arguments = arguments;
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--observations") => {
                let value = arguments
                    .next()
                    .ok_or_else(|| Refusal::new("Git helper observation path is missing"))?;
                if observation_dir.replace(PathBuf::from(value)).is_some() {
                    return Err(Refusal::new("Git helper observation path was repeated"));
                }
            }
            Some("--expected-host") => {
                let value = arguments
                    .next()
                    .ok_or_else(|| Refusal::new("Git helper expected host is missing"))?;
                let value = value
                    .into_string()
                    .map_err(|_| Refusal::new("Git helper expected host is not UTF-8"))?;
                if expected_host.replace(value).is_some() {
                    return Err(Refusal::new("Git helper expected host was repeated"));
                }
            }
            Some(value @ ("get" | "store" | "erase")) => {
                if action.replace(value.to_owned()).is_some() {
                    return Err(Refusal::new("Git helper action was repeated"));
                }
            }
            _ => return Err(Refusal::new("unknown Git credential helper argument")),
        }
    }
    let observation_dir =
        observation_dir.ok_or_else(|| Refusal::new("Git helper observation path is required"))?;
    if !observation_dir.is_absolute() {
        return Err(Refusal::new("Git helper observation path must be absolute"));
    }
    Ok((
        observation_dir,
        expected_host.ok_or_else(|| Refusal::new("Git helper expected host is required"))?,
        action.ok_or_else(|| Refusal::new("Git helper action is required"))?,
    ))
}

#[derive(Default)]
struct CredentialRequest {
    protocol: Option<String>,
    host: Option<String>,
}

fn read_credential_request() -> Result<CredentialRequest> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take((MAX_HELPER_STDIN_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    parse_credential_request(&bytes)
}

fn parse_credential_request(bytes: &[u8]) -> Result<CredentialRequest> {
    // Pinned git2::CredentialHelper writes newline-terminated fields then EOF,
    // without Git CLI's extra blank line. Accept both finite wire forms.
    if bytes.len() > MAX_HELPER_STDIN_BYTES || !bytes.ends_with(b"\n") {
        return Err(Refusal::new(
            "Git credential helper request exceeds its bound or lacks its terminator",
        ));
    }
    if !bytes.is_ascii() {
        return Err(Refusal::new(
            "Git credential helper request must contain ASCII protocol fields",
        ));
    }
    let terminator = if bytes.ends_with(b"\n\n") { 2 } else { 1 };
    let body = &bytes[..bytes.len() - terminator];
    let text = std::str::from_utf8(body)
        .map_err(|_| Refusal::new("Git credential helper request is not UTF-8"))?;
    let mut request = CredentialRequest::default();
    if !text.is_empty() {
        for line in text.split('\n') {
            if line.is_empty() {
                return Err(Refusal::new(
                    "Git credential helper request has an empty field",
                ));
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| Refusal::new("Git credential helper request field is malformed"))?;
            if key == "protocol" {
                if request.protocol.replace(value.to_owned()).is_some() {
                    return Err(Refusal::new("Git credential helper protocol was repeated"));
                }
            } else if key == "host" && request.host.replace(value.to_owned()).is_some() {
                return Err(Refusal::new("Git credential helper host was repeated"));
            }
            // Other fields, including username, password, path and URL, are ignored.
        }
    }
    Ok(request)
}

fn write_helper_observation(
    directory: &Path,
    action: &str,
    host: &str,
    protocol: &str,
    response_emitted: bool,
) -> Result<()> {
    let observation = json!({
        "action": action,
        "host": host,
        "protocol": protocol,
        "response_emitted": response_emitted
    });
    let bytes = serde_json::to_vec(&observation).map_err(|error| {
        Refusal::new(format!(
            "cannot encode sanitized helper observation: {error}"
        ))
    })?;
    let path = directory.join(format!(
        "helper-{}-{}.json",
        std::process::id(),
        unix_millis()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&path).map_err(|error| {
        Refusal::new(format!(
            "cannot create sanitized helper observation: {error}"
        ))
    })?;
    file.write_all(&bytes).map_err(|error| {
        Refusal::new(format!(
            "cannot write sanitized helper observation: {error}"
        ))
    })?;
    Ok(())
}

fn read_helper_observations(directory: &Path) -> Result<Vec<Value>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| Refusal::new(format!("cannot read helper observations: {error}")))?
    {
        let entry =
            entry.map_err(|error| Refusal::new(format!("cannot read helper event: {error}")))?;
        paths.push(entry.path());
        if paths.len() > MAX_HELPER_EVENTS {
            return Err(Refusal::new("Git credential helper event limit exceeded"));
        }
    }
    paths.sort();
    let mut rows = Vec::new();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| Refusal::new(format!("cannot inspect helper observation: {error}")))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 4096 {
            return Err(Refusal::new(
                "Git helper observation is not a bounded plain file",
            ));
        }
        let bytes = fs::read(&path)
            .map_err(|error| Refusal::new(format!("cannot read helper observation: {error}")))?;
        let row: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Refusal::new("Git helper observation JSON is malformed"))?;
        if !matches!(row["action"].as_str(), Some("get" | "store" | "erase"))
            || !matches!(row["host"].as_str(), Some("loopback" | "other-or-missing"))
            || !matches!(row["protocol"].as_str(), Some("http" | "other-or-missing"))
            || !row["response_emitted"].is_boolean()
        {
            return Err(Refusal::new("Git helper observation is not sanitized"));
        }
        rows.push(row);
    }
    Ok(rows)
}

fn serve(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    observations: Arc<Mutex<Vec<RequestObservation>>>,
    helper_observations: PathBuf,
    expected_authorization: String,
) {
    let mut accepted = 0;
    while accepted < MAX_REQUESTS && !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _peer)) => {
                accepted += 1;
                let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
                let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
                let _ = handle_connection(
                    &mut stream,
                    &observations,
                    &helper_observations,
                    &expected_authorization,
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(_) => break,
        }
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    observations: &Mutex<Vec<RequestObservation>>,
    helper_observations: &Path,
    expected_authorization: &str,
) -> std::io::Result<()> {
    let observation = match read_http_request(stream, expected_authorization, helper_observations) {
        Ok(observation) => observation,
        Err(_) => {
            return write_unauthorized(stream);
        }
    };
    if let Ok(mut rows) = observations.lock()
        && rows.len() < MAX_REQUESTS
    {
        rows.push(observation.clone());
    }
    if observation.route == GIT_ROUTE {
        write_unauthorized(stream)
    } else {
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    }
}

fn read_http_request(
    stream: &mut TcpStream,
    expected_authorization: &str,
    helper_observations: &Path,
) -> std::io::Result<RequestObservation> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        if bytes.len() >= MAX_HTTP_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Git fixture request exceeds header bound",
            ));
        }
        let available = (MAX_HTTP_HEADER_BYTES - bytes.len()).min(chunk.len());
        let count = stream.read(&mut chunk[..available])?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Git fixture request ended before its header terminator",
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
    };
    if bytes[header_end + 4..]
        .iter()
        .any(|byte| *byte != b'\r' && *byte != b'\n')
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Git fixture accepts header-only requests",
        ));
    }
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if !header.is_ascii() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Git fixture headers must be ASCII",
        ));
    }
    let mut lines = header.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut request_parts = request_line.split(' ');
    let method = request_parts.next().unwrap_or_default();
    let target = request_parts.next().unwrap_or_default();
    let version = request_parts.next().unwrap_or_default();
    let valid_request_line = method == "GET"
        && target.starts_with('/')
        && matches!(version, "HTTP/1.0" | "HTTP/1.1")
        && request_parts.next().is_none();

    let expected_route_seen = valid_request_line && target == GIT_ROUTE;
    let mut authorization_seen = false;
    let mut authorization_matches = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("authorization")
        {
            if authorization_seen {
                authorization_matches = false;
                break;
            }
            authorization_seen = true;
            authorization_matches = value.trim() == expected_authorization;
        }
    }
    let authorization_matches = authorization_seen && authorization_matches;
    let helper_get_preceded_authorization =
        authorization_matches && has_recorded_helper_get(helper_observations)?;
    Ok(RequestObservation {
        route: if expected_route_seen {
            GIT_ROUTE
        } else {
            "other"
        },
        authorization_matches,
        helper_get_preceded_authorization,
    })
}

fn has_recorded_helper_get(directory: &Path) -> std::io::Result<bool> {
    let mut count = 0;
    for entry in fs::read_dir(directory)? {
        count += 1;
        if count > MAX_HELPER_EVENTS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Git helper marker count exceeds its bound",
            ));
        }
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 4096 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Git helper marker is not a bounded plain file",
            ));
        }
        let bytes = fs::read(path)?;
        let row: Value = serde_json::from_slice(&bytes)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        if row["action"] == "get"
            && row["host"] == "loopback"
            && row["protocol"] == "http"
            && row["response_emitted"] == true
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn write_unauthorized(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.write_all(
        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"rc2-git-helper-fixture\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
}

fn expected_basic_authorization() -> String {
    let credentials = format!("{FAKE_USERNAME}:{FAKE_PASSWORD}");
    format!("Basic {}", base64(credentials.as_bytes()))
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let (chunks, remainder) = bytes.as_chunks::<3>();
    for chunk in chunks {
        let first = chunk[0];
        let second = chunk[1];
        let third = chunk[2];
        output.push(char::from(TABLE[(first >> 2) as usize]));
        output.push(char::from(
            TABLE[(((first & 0x03) << 4) | (second >> 4)) as usize],
        ));
        output.push(char::from(
            TABLE[(((second & 0x0f) << 2) | (third >> 6)) as usize],
        ));
        output.push(char::from(TABLE[(third & 0x3f) as usize]));
    }
    if let Some(first) = remainder.first() {
        output.push(char::from(TABLE[(first >> 2) as usize]));
        if let Some(second) = remainder.get(1) {
            output.push(char::from(
                TABLE[(((first & 0x03) << 4) | (second >> 4)) as usize],
            ));
            output.push(char::from(TABLE[((second & 0x0f) << 2) as usize]));
            output.push('=');
        } else {
            output.push(char::from(TABLE[((first & 0x03) << 4) as usize]));
            output.push_str("==");
        }
    }
    output
}

fn checkout_manifest_count(root: &Path) -> Result<usize> {
    let rows = snapshot(root)?;
    Ok(rows
        .iter()
        .filter(|row| {
            row["kind"] == "file"
                && row["path"]
                    .as_str()
                    .is_some_and(|path| path == "Cargo.toml" || path.ends_with("/Cargo.toml"))
        })
        .count())
}

fn contains_auth_refusal_marker(stderr: &[u8]) -> bool {
    let stderr = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    ["401", "authenticate", "authentication", "credential"]
        .iter()
        .any(|needle| stderr.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_fields_accept_pinned_git2_eof_and_refuse_malformed_requests() {
        for bytes in [
            b"protocol=http\nhost=127.0.0.1:1234\n".as_slice(),
            b"protocol=http\nhost=127.0.0.1:1234\n\n",
        ] {
            let request = parse_credential_request(bytes).unwrap();
            assert_eq!(request.protocol.as_deref(), Some("http"));
            assert_eq!(request.host.as_deref(), Some("127.0.0.1:1234"));
        }
        assert!(parse_credential_request(b"protocol=http\nhost=missing-newline").is_err());
        assert!(parse_credential_request(b"host=first\nhost=second\n").is_err());
        assert!(parse_credential_request(b"protocol=http\n\nhost=extra\n").is_err());
        assert!(parse_credential_request(&vec![b'x'; MAX_HELPER_STDIN_BYTES + 1]).is_err());
    }
}
