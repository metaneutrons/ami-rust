#!/usr/bin/env python3
"""Open or safely squash-merge the attested ami-rust Homebrew formula PR."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


TAP_REPOSITORY = "metaneutrons/homebrew-tap"
TAP_URL = "https://github.com/metaneutrons/homebrew-tap.git"
BOT_LOGIN = "metaneutrons-homebrew[bot]"
RECEIPT_SCHEMA = "ami-rust-homebrew-tap-receipt-v1"
CANDIDATE_SCHEMA = "ami-rust-package-candidate-v1"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_FORMULA_BYTES = 1024 * 1024
MAX_README_BYTES = 2 * 1024 * 1024
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
SOURCE = Path(__file__).resolve().parents[1]


class TapPublicationError(ValueError):
    """Raised when tap state or the publication receipt violates the contract."""


def _json_bytes(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                           allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise TapPublicationError("publication metadata is not valid JSON data") from error


def _parse_json(raw: bytes, label: str) -> object:
    def unique_pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        parsed: dict[str, object] = {}
        for key, value in rows:
            if key in parsed:
                raise TapPublicationError(f"{label} contains a duplicate JSON key")
            parsed[key] = value
        return parsed

    def reject_constant(value: str) -> None:
        raise TapPublicationError(f"{label} contains a nonstandard JSON constant: {value}")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                          parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise TapPublicationError(f"{label} is not bounded UTF-8 JSON") from error


def _read_regular(path: Path, label: str, limit: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise TapPublicationError(f"cannot open {label} as a regular file") from error
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size <= 0 or info.st_size > limit):
            raise TapPublicationError(f"{label} is linked, empty, non-regular or oversized")
        chunks: list[bytes] = []
        size = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, limit - size + 1))
            if not block:
                break
            size += len(block)
            if size > limit:
                raise TapPublicationError(f"{label} exceeds its byte bound")
            chunks.append(block)
        if size != info.st_size:
            raise TapPublicationError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def api(path: str, *, method: str = "GET", data: object | None = None,
        missing: bool = False) -> object | None:
    """Call the GitHub API with the action's installation token in its header."""
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise TapPublicationError("GH_TOKEN is required")
    if (not path or path.startswith("/") or ".." in path.split("/")
            or path.startswith(("http:", "https:"))):
        raise TapPublicationError("invalid GitHub API path")
    body = None if data is None else _json_bytes(data)
    request = Request(
        "https://api.github.com/" + path,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        data=body,
    )
    try:
        with urlopen(request, timeout=60) as response:
            raw = response.read(MAX_JSON_BYTES + 1)
    except HTTPError as error:
        if missing and error.code == 404:
            return None
        raise TapPublicationError(f"GitHub {method} {path} failed with HTTP {error.code}") from None
    except (URLError, TimeoutError, OSError) as error:
        raise TapPublicationError(f"GitHub {method} {path} request failed: {type(error).__name__}") from None
    if len(raw) > MAX_JSON_BYTES:
        raise TapPublicationError("GitHub API response exceeded its byte bound")
    return _parse_json(raw, f"GitHub {method} {path}")


def _require_sha(value: object, label: str) -> str:
    if type(value) is not str or SHA_RE.fullmatch(value) is None:
        raise TapPublicationError(f"{label} is not a lowercase Git object id")
    return value


def _load_pins() -> dict[str, object]:
    raw = _read_regular(SOURCE / "packaging" / "pins.json", "packaging/pins.json", MAX_JSON_BYTES)
    pins = _parse_json(raw, "packaging/pins.json")
    if type(pins) is not dict:
        raise TapPublicationError("packaging/pins.json must be a JSON object")
    version = pins.get("sdk_version")
    revision = pins.get("packaging_revision")
    if (type(version) is not str or VERSION_RE.fullmatch(version) is None
            or type(revision) is not int or revision < 1
            or pins.get("package_version") != f"{version}-{revision}"):
        raise TapPublicationError("packaging pins do not identify a stable package version")
    return pins


def _attested_formula(path: Path) -> tuple[bytes, str]:
    """Require the selected file to match its adjacent sealed candidate inventory."""
    if path.name != "ami-rust.rb":
        raise TapPublicationError("--formula must name the exact ami-rust.rb candidate asset")
    formula = _read_regular(path, "candidate formula", MAX_FORMULA_BYTES)
    candidate_raw = _read_regular(path.parent / "candidate.json", "candidate.json", MAX_JSON_BYTES)
    candidate = _parse_json(candidate_raw, "candidate.json")
    if (type(candidate) is not dict or candidate.get("schema") != CANDIDATE_SCHEMA
            or type(candidate.get("assets")) is not list):
        raise TapPublicationError("candidate.json is not a sealed package candidate")
    rows = [row for row in candidate["assets"]
            if type(row) is dict and row.get("path") == "ami-rust.rb"]
    digest = hashlib.sha256(formula).hexdigest()
    if (len(rows) != 1 or set(rows[0]) != {"path", "bytes", "sha256"}
            or type(rows[0]["bytes"]) is not int or rows[0]["bytes"] != len(formula)
            or rows[0]["sha256"] != digest):
        raise TapPublicationError("formula bytes differ from candidate.json inventory")
    try:
        formula.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TapPublicationError("candidate formula is not UTF-8 text") from error
    return formula, digest


def _preflight() -> tuple[str, dict[str, object]]:
    repositories = api("installation/repositories?per_page=100")
    if (type(repositories) is not dict or type(repositories.get("total_count")) is not int
            or repositories["total_count"] != 1 or type(repositories.get("repositories")) is not list
            or len(repositories["repositories"]) != 1
            or type(repositories["repositories"][0]) is not dict
            or repositories["repositories"][0].get("full_name") != TAP_REPOSITORY):
        raise TapPublicationError("installation token must be scoped only to metaneutrons/homebrew-tap")

    bot_path = "users/" + quote(BOT_LOGIN, safe="-_.")
    bot = api(bot_path)
    if (type(bot) is not dict or bot.get("login") != BOT_LOGIN or bot.get("type") != "Bot"
            or type(bot.get("id")) is not int or bot["id"] <= 0):
        raise TapPublicationError("cannot measure the public tap bot identity")

    protection = api(f"repos/{TAP_REPOSITORY}/branches/main/protection")
    if type(protection) is not dict:
        raise TapPublicationError("main branch protection is unavailable")
    checks = protection.get("required_status_checks")
    contexts = checks.get("contexts") if type(checks) is dict else None
    admins = protection.get("enforce_admins")
    if (type(checks) is not dict or checks.get("strict") is not True
            or type(contexts) is not list or "Formula qualification" not in contexts
            or type(admins) is not dict or admins.get("enabled") is not True):
        raise TapPublicationError("tap main must strictly require Formula qualification and enforce admins")

    branch = api(f"repos/{TAP_REPOSITORY}/branches/main")
    if type(branch) is not dict or type(branch.get("commit")) is not dict:
        raise TapPublicationError("cannot read tap main branch")
    main_sha = _require_sha(branch["commit"].get("sha"), "tap main SHA")
    return main_sha, bot


def _contents(path: str, ref: str, *, missing: bool = False) -> bytes | None:
    endpoint = (f"repos/{TAP_REPOSITORY}/contents/" + quote(path, safe="/"))
    endpoint += "?" + urlencode({"ref": ref})
    result = api(endpoint, missing=missing)
    if result is None:
        return None
    if (type(result) is not dict or result.get("type") != "file"
            or result.get("encoding") != "base64" or type(result.get("content")) is not str):
        raise TapPublicationError(f"tap content endpoint returned an invalid file: {path}")
    encoded = result["content"].replace("\n", "")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise TapPublicationError(f"tap file is not valid base64: {path}") from error
    limit = MAX_FORMULA_BYTES if path == "Formula/ami-rust.rb" else MAX_README_BYTES
    if len(raw) > limit:
        raise TapPublicationError(f"tap file exceeds its byte bound: {path}")
    return raw


def _clean_child_env(home: Path) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": os.devnull,
    }
    return env


def _anonymous_clone(destination: Path) -> str:
    """Clone the public tap without credentials and return its checked-out HEAD."""
    if destination.exists() or destination.is_symlink():
        raise TapPublicationError("anonymous clone destination is not fresh")
    destination.parent.mkdir(parents=True, exist_ok=True)
    home = destination.parent / "empty-home"
    home.mkdir(mode=0o700)
    env = _clean_child_env(home)
    try:
        subprocess.run(
            ["git", "-c", "credential.helper=", "clone", "--quiet", "--no-tags",
             "--single-branch", "--branch", "main", TAP_URL, str(destination)],
            check=True, timeout=180, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"], cwd=destination,
            check=True, timeout=30, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise TapPublicationError(f"anonymous tap clone failed ({type(error).__name__})") from None
    head = result.stdout.decode("ascii", "strict").strip()
    return _require_sha(head, "anonymous tap clone HEAD")


def _render_readme(clone: Path, formula: bytes) -> bytes:
    formula_dir = clone / "Formula"
    try:
        formula_dir_info = formula_dir.lstat()
        if not stat.S_ISDIR(formula_dir_info.st_mode):
            raise TapPublicationError("tap Formula path is not a real directory")
    except OSError as error:
        raise TapPublicationError("tap Formula directory is missing") from error
    formula_path = formula_dir / "ami-rust.rb"
    try:
        existing = _read_regular(formula_path, "existing tap formula", MAX_FORMULA_BYTES)
    except TapPublicationError as error:
        if not (formula_path.exists() is False and not formula_path.is_symlink()):
            raise
        existing = None
    if existing is not None and existing != formula:
        raise TapPublicationError("tap already contains a different ami-rust formula")
    if existing is None:
        try:
            descriptor = os.open(formula_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | getattr(os, "O_NOFOLLOW", 0), 0o644)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(formula)
        except OSError as error:
            raise TapPublicationError("cannot add exact formula to the fresh tap clone") from error

    script = clone / "scripts" / "generate-readme.sh"
    try:
        info = script.lstat()
    except OSError as error:
        raise TapPublicationError("protected tap README generator is missing") from error
    if not stat.S_ISREG(info.st_mode):
        raise TapPublicationError("protected tap README generator is not a regular file")
    readme_path = clone / "README.md"
    try:
        info = readme_path.lstat()
    except OSError as error:
        raise TapPublicationError("tap README.md is missing") from error
    if not stat.S_ISREG(info.st_mode):
        raise TapPublicationError("tap README.md is not a regular file")
    env = _clean_child_env(clone.parent / "empty-home")
    env["FORMULA_DIR"] = "Formula"
    try:
        subprocess.run(["bash", str(script), "README.md"], cwd=clone, env=env,
                       check=True, timeout=60, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise TapPublicationError(f"protected tap README generation failed ({type(error).__name__})") from None
    return _read_regular(readme_path, "generated tap README", MAX_README_BYTES)


def _commit_identity(bot: dict[str, object]) -> dict[str, str]:
    login = bot["login"]
    user_id = bot["id"]
    assert type(login) is str and type(user_id) is int
    return {"name": login, "email": f"{user_id}+{login}@users.noreply.github.com"}


def _compare(base_sha: str, head_sha: str) -> dict[str, object]:
    result = api(f"repos/{TAP_REPOSITORY}/compare/{base_sha}...{head_sha}")
    if type(result) is not dict:
        raise TapPublicationError("cannot verify tap branch comparison")
    return result


def _validate_branch(base_sha: str, head_sha: str, formula: bytes, readme: bytes,
                     bot: dict[str, object], branch_name: str,
                     pins: dict[str, object]) -> None:
    commit = api(f"repos/{TAP_REPOSITORY}/commits/{head_sha}")
    if type(commit) is not dict or commit.get("sha") != head_sha:
        raise TapPublicationError("tap publication branch head cannot be read")
    parents = commit.get("parents")
    if (type(parents) is not list or len(parents) != 1 or type(parents[0]) is not dict
            or parents[0].get("sha") != base_sha):
        raise TapPublicationError("tap publication branch must be one commit on the measured main SHA")
    details = commit.get("commit")
    identity = _commit_identity(bot)
    author = details.get("author") if type(details) is dict else None
    committer = details.get("committer") if type(details) is dict else None
    if (type(details) is not dict or details.get("message") != _commit_message(pins)
            or type(author) is not dict or type(committer) is not dict
            or any(author.get(key) != value or committer.get(key) != value
                   for key, value in identity.items())):
        raise TapPublicationError("tap publication commit identity or message differs")
    comparison = _compare(base_sha, head_sha)
    merge_base = comparison.get("merge_base_commit")
    files = comparison.get("files")
    expected_paths = {"Formula/ami-rust.rb", "README.md"}
    if (comparison.get("status") != "ahead" or comparison.get("ahead_by") != 1
            or comparison.get("behind_by") != 0 or type(merge_base) is not dict
            or merge_base.get("sha") != base_sha or type(files) is not list
            or {row.get("filename") for row in files if type(row) is dict} != expected_paths
            or len(files) != 2):
        raise TapPublicationError("tap branch must change only the formula and generated README")
    if _contents("Formula/ami-rust.rb", branch_name) != formula:
        raise TapPublicationError("tap branch formula does not match the attested bytes")
    if _contents("README.md", branch_name) != readme:
        raise TapPublicationError("tap branch README differs from the protected generator output")


def _commit_message(pins: dict[str, object]) -> str:
    return (f"feat: distribute ami-rust {pins['sdk_version']} "
            f"packaging {pins['packaging_revision']}")


def _branch_name(pins: dict[str, object]) -> str:
    return f"fix/ami-rust-{pins['sdk_version']}-packaging-{pins['packaging_revision']}"


def _pull_requests(branch_name: str) -> list[dict[str, object]]:
    query = urlencode({"head": f"metaneutrons:{branch_name}", "base": "main",
                       "state": "all", "per_page": "100"})
    result = api(f"repos/{TAP_REPOSITORY}/pulls?{query}")
    if type(result) is not list or len(result) >= 100 or any(type(row) is not dict for row in result):
        raise TapPublicationError("tap pull request listing is malformed or truncated")
    return result


def _pull_receipt(pr: dict[str, object], branch_name: str, base_sha: str,
                  formula_sha: str, formula_bytes: int,
                  readme: bytes) -> dict[str, object]:
    number = pr.get("number")
    url = pr.get("html_url")
    head = pr.get("head")
    base = pr.get("base")
    if (type(number) is not int or number <= 0 or type(url) is not str
            or type(head) is not dict or head.get("ref") != branch_name
            or type(head.get("sha")) is not str or SHA_RE.fullmatch(head["sha"]) is None
            or type(head.get("repo")) is not dict
            or head["repo"].get("full_name") != TAP_REPOSITORY
            or type(base) is not dict or base.get("ref") != "main"
            or type(base.get("repo")) is not dict
            or base["repo"].get("full_name") != TAP_REPOSITORY
            or type(base.get("sha")) is not str or SHA_RE.fullmatch(base["sha"]) is None
            or base["sha"] != base_sha):
        raise TapPublicationError("tap pull request does not match the measured branch and main base")
    return {
        "schema": RECEIPT_SCHEMA,
        "status": "OPEN_PULL_REQUEST",
        "repository": TAP_REPOSITORY,
        "pull_request": {"number": number, "url": url},
        "branch": branch_name,
        "head_sha": head["sha"],
        "base_ref": "main",
        "base_sha": base_sha,
        "source_formula_sha256": formula_sha,
        "source_formula_bytes": formula_bytes,
        "readme_sha256": hashlib.sha256(readme).hexdigest(),
        "readme_bytes": len(readme),
    }


def _new_receipt_path(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise TapPublicationError("receipt output must be fresh")
    if not path.parent.is_dir():
        raise TapPublicationError("receipt output parent must already exist")


def _write_receipt(path: Path, record: dict[str, object]) -> None:
    raw = _json_bytes(record)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as error:
        raise TapPublicationError("receipt output is not fresh or cannot be created") from error
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def open_publication(formula_path: Path, receipt_path: Path) -> dict[str, object]:
    formula, formula_sha = _attested_formula(formula_path)
    pins = _load_pins()
    branch_name = _branch_name(pins)
    _new_receipt_path(receipt_path)
    base_sha, bot = _preflight()
    main_formula = _contents("Formula/ami-rust.rb", "main", missing=True)

    with tempfile.TemporaryDirectory(prefix="ami-rust-homebrew-tap-") as temporary:
        clone = Path(temporary) / "tap"
        clone_head = _anonymous_clone(clone)
        if clone_head != base_sha:
            raise TapPublicationError("anonymous tap clone HEAD differs from API-measured main SHA")
        base_readme = _contents("README.md", "main")
        cloned_readme = _read_regular(clone / "README.md", "cloned tap README", MAX_README_BYTES)
        if base_readme != cloned_readme:
            raise TapPublicationError("anonymous tap README differs from API-measured main")
        expected_readme = _render_readme(clone, formula)

        if main_formula is not None:
            if main_formula != formula:
                raise TapPublicationError("public tap already has different ami-rust formula bytes")
            if expected_readme != base_readme:
                raise TapPublicationError("public formula is exact but tap README is not generated from it")
            record: dict[str, object] = {
                "schema": RECEIPT_SCHEMA,
                "status": "ALREADY_DELIVERED",
                "repository": TAP_REPOSITORY,
                "pull_request": None,
                "branch": branch_name,
                "head_sha": base_sha,
                "base_ref": "main",
                "base_sha": base_sha,
                "source_formula_sha256": formula_sha,
                "source_formula_bytes": len(formula),
                "readme_bytes": len(base_readme),
                "readme_sha256": hashlib.sha256(base_readme).hexdigest(),
            }
            _write_receipt(receipt_path, record)
            return record

        ref_path = f"repos/{TAP_REPOSITORY}/git/ref/heads/{quote(branch_name, safe='/')}"
        ref = api(ref_path, missing=True)
        if ref is None:
            main_commit = api(f"repos/{TAP_REPOSITORY}/git/commits/{base_sha}")
            if type(main_commit) is not dict or type(main_commit.get("tree")) is not dict:
                raise TapPublicationError("cannot read measured main Git tree")
            base_tree = _require_sha(main_commit["tree"].get("sha"), "tap main tree SHA")
            tree = api(f"repos/{TAP_REPOSITORY}/git/trees", method="POST", data={
                "base_tree": base_tree,
                "tree": [
                    {"path": "Formula/ami-rust.rb", "mode": "100644", "type": "blob",
                     "content": formula.decode("utf-8")},
                    {"path": "README.md", "mode": "100644", "type": "blob",
                     "content": expected_readme.decode("utf-8")},
                ],
            })
            if type(tree) is not dict:
                raise TapPublicationError("GitHub did not create the tap publication tree")
            tree_sha = _require_sha(tree.get("sha"), "tap publication tree SHA")
            identity = _commit_identity(bot)
            commit = api(f"repos/{TAP_REPOSITORY}/git/commits", method="POST", data={
                "message": _commit_message(pins),
                "tree": tree_sha,
                "parents": [base_sha],
                "author": identity,
                "committer": identity,
            })
            if type(commit) is not dict:
                raise TapPublicationError("GitHub did not create the tap publication commit")
            head_sha = _require_sha(commit.get("sha"), "tap publication commit SHA")
            created_ref = api(f"repos/{TAP_REPOSITORY}/git/refs", method="POST",
                              data={"ref": "refs/heads/" + branch_name, "sha": head_sha})
            if type(created_ref) is not dict:
                raise TapPublicationError("GitHub did not create the tap publication branch")
            # A failed API operation stops this attempt. A deliberate later
            # retry validates any existing branch through the normal read path;
            # it never issues fallback requests after a rate-limit response.
        else:
            if type(ref) is not dict or type(ref.get("object")) is not dict:
                raise TapPublicationError("existing tap publication ref is malformed")
            head_sha = _require_sha(ref["object"].get("sha"), "existing tap branch SHA")

        _validate_branch(base_sha, head_sha, formula, expected_readme, bot, branch_name, pins)
        matching = _pull_requests(branch_name)
        if len(matching) > 1:
            raise TapPublicationError("more than one tap pull request exists for the publication branch")
        if matching:
            pr = matching[0]
            if pr.get("head", {}).get("sha") != head_sha:
                raise TapPublicationError("existing tap pull request head differs from the verified branch")
            if pr.get("state") == "closed" and pr.get("merged") is not True:
                pr = api(f"repos/{TAP_REPOSITORY}/pulls/{pr['number']}", method="PATCH",
                         data={"state": "open"})
            if type(pr) is not dict or pr.get("state") != "open":
                if type(pr) is dict and pr.get("merged") is True:
                    raise TapPublicationError("publication branch was merged while open-mode recovery ran")
                raise TapPublicationError("existing tap pull request is not open")
        else:
            pr = api(f"repos/{TAP_REPOSITORY}/pulls", method="POST", data={
                "title": _commit_message(pins),
                "body": ("Add the exact attested ami-rust formula and regenerate the tap README.\n\n"
                         f"Formula SHA-256: `{formula_sha}`\n"
                         f"Base: `main` at `{base_sha}`\n\n"
                         "The required Formula qualification check must pass before squash merge."),
                "head": branch_name,
                "base": "main",
                "draft": False,
            })
        if type(pr) is not dict:
            raise TapPublicationError("GitHub did not return a tap pull request")
        record = _pull_receipt(pr, branch_name, base_sha, formula_sha, len(formula),
                               expected_readme)
        if record["head_sha"] != head_sha:
            raise TapPublicationError("tap pull request head changed during creation or recovery")
        _write_receipt(receipt_path, record)
        return record


def _load_receipt(path: Path) -> dict[str, object]:
    raw = _read_regular(path, "open-mode receipt", MAX_JSON_BYTES)
    value = _parse_json(raw, "open-mode receipt")
    if type(value) is not dict or value.get("schema") != RECEIPT_SCHEMA:
        raise TapPublicationError("open-mode receipt schema is invalid")
    if (value.get("status") != "OPEN_PULL_REQUEST" or value.get("repository") != TAP_REPOSITORY
            or value.get("base_ref") != "main"):
        raise TapPublicationError("receipt does not describe an open tap pull request")
    pr = value.get("pull_request")
    if type(pr) is not dict or type(pr.get("number")) is not int or pr["number"] <= 0:
        raise TapPublicationError("receipt pull request identity is malformed")
    _require_sha(value.get("head_sha"), "receipt head SHA")
    _require_sha(value.get("base_sha"), "receipt base SHA")
    if (type(value.get("branch")) is not str or not value["branch"].startswith("fix/ami-rust-")
            or type(value.get("source_formula_sha256")) is not str
            or SHA256_RE.fullmatch(value["source_formula_sha256"]) is None
            or type(value.get("source_formula_bytes")) is not int
            or value["source_formula_bytes"] <= 0
            or type(value.get("readme_sha256")) is not str
            or SHA256_RE.fullmatch(value["readme_sha256"]) is None
            or type(value.get("readme_bytes")) is not int
            or value["readme_bytes"] <= 0):
        raise TapPublicationError("receipt formula or branch identity is malformed")
    return value


def _validate_pr_base(pr: dict[str, object], receipt: dict[str, object],
                      *, merged: bool) -> None:
    head = pr.get("head")
    base = pr.get("base")
    receipt_pr = receipt.get("pull_request")
    expected = receipt["branch"]
    if (type(receipt_pr) is not dict or pr.get("number") != receipt_pr.get("number")
            or type(head) is not dict or head.get("ref") != expected
            or head.get("sha") != receipt["head_sha"]
            or type(head.get("repo")) is not dict
            or head["repo"].get("full_name") != TAP_REPOSITORY
            or type(base) is not dict or base.get("ref") != "main"
            or type(base.get("repo")) is not dict
            or base["repo"].get("full_name") != TAP_REPOSITORY):
        raise TapPublicationError("pull request branch, head or base differs from the open receipt")
    if not merged and base.get("sha") != receipt["base_sha"]:
        raise TapPublicationError("pull request base SHA changed since the open receipt")


def _validate_required_check(head_sha: str) -> None:
    endpoint = (f"repos/{TAP_REPOSITORY}/commits/{head_sha}/check-runs?"
                + urlencode({"filter": "latest", "per_page": "100"}))
    result = api(endpoint)
    if (type(result) is not dict or type(result.get("check_runs")) is not list
            or type(result.get("total_count")) is not int
            or result["total_count"] != len(result["check_runs"])
            or len(result["check_runs"]) >= 100):
        raise TapPublicationError("tap head check-run listing is malformed")
    matches = [row for row in result["check_runs"]
               if type(row) is dict and row.get("name") == "Formula qualification"]
    if (len(matches) != 1 or matches[0].get("status") != "completed"
            or matches[0].get("conclusion") != "success"):
        raise TapPublicationError("exactly one completed successful Formula qualification check is required")


def merge_publication(formula_path: Path, open_receipt_path: Path,
                      receipt_path: Path) -> dict[str, object]:
    formula, formula_sha = _attested_formula(formula_path)
    pins = _load_pins()
    _new_receipt_path(receipt_path)
    opened = _load_receipt(open_receipt_path)
    if opened["branch"] != _branch_name(pins):
        raise TapPublicationError("open receipt branch does not match the pinned package version")
    if (opened["source_formula_sha256"] != formula_sha
            or opened["source_formula_bytes"] != len(formula)):
        raise TapPublicationError("merge formula differs from the open receipt")

    main_sha, bot = _preflight()
    number = opened["pull_request"]["number"]
    pr = api(f"repos/{TAP_REPOSITORY}/pulls/{number}")
    if type(pr) is not dict:
        raise TapPublicationError("tap pull request response is malformed")
    _validate_pr_base(pr, opened, merged=pr.get("merged") is True)
    head_sha = opened["head_sha"]
    branch_readme = _contents("README.md", head_sha)
    if (branch_readme is None or len(branch_readme) != opened["readme_bytes"]
            or hashlib.sha256(branch_readme).hexdigest() != opened["readme_sha256"]):
        raise TapPublicationError("tap branch README differs from the open receipt")
    _validate_branch(opened["base_sha"], head_sha, formula, branch_readme,
                     bot, opened["branch"], pins)

    merged_already = pr.get("state") == "closed" and pr.get("merged") is True
    if merged_already:
        published = _contents("Formula/ami-rust.rb", "main", missing=True)
        if published != formula:
            raise TapPublicationError("merged tap pull request does not publish the exact formula bytes")
        merge_sha = _require_sha(pr.get("merge_commit_sha"), "merged pull request commit SHA")
        record = dict(opened)
        record.update({"status": "ALREADY_MERGED", "merge_commit_sha": merge_sha,
                       "published_formula_sha256": hashlib.sha256(published).hexdigest()})
        _write_receipt(receipt_path, record)
        return record
    if pr.get("state") != "open" or pr.get("draft") is True:
        raise TapPublicationError("tap pull request must be open and ready for review")
    if main_sha != opened["base_sha"]:
        raise TapPublicationError("tap main advanced after PR creation; recreate and requalify the publication")
    if pr.get("base", {}).get("sha") != main_sha:
        raise TapPublicationError("tap pull request is not based on the current main tip")
    if pr.get("mergeable") is not True or pr.get("mergeable_state") != "clean":
        raise TapPublicationError("tap pull request is not cleanly mergeable")
    comparison = _compare(main_sha, head_sha)
    merge_base = comparison.get("merge_base_commit")
    if (comparison.get("status") != "ahead" or comparison.get("ahead_by") != 1
            or comparison.get("behind_by") != 0 or type(merge_base) is not dict
            or merge_base.get("sha") != main_sha):
        raise TapPublicationError("tap publication branch is behind or requires an update")
    _validate_required_check(head_sha)

    # Do not merge over an independently published or conflicting formula.
    current = _contents("Formula/ami-rust.rb", "main", missing=True)
    if current is not None:
        if current == formula:
            raise TapPublicationError("exact formula is already on main while this PR remains open")
        raise TapPublicationError("main already contains different ami-rust formula bytes")
    response = api(f"repos/{TAP_REPOSITORY}/pulls/{number}/merge", method="PUT",
                   data={"merge_method": "squash", "sha": head_sha,
                         "commit_title": _commit_message(pins)})
    if type(response) is not dict or response.get("merged") is not True:
        raise TapPublicationError("GitHub did not confirm the squash merge")
    merge_sha = _require_sha(response.get("sha"), "squash merge commit SHA")
    updated_pr = api(f"repos/{TAP_REPOSITORY}/pulls/{number}")
    if (type(updated_pr) is not dict or updated_pr.get("state") != "closed"
            or updated_pr.get("merged") is not True
            or updated_pr.get("merge_commit_sha") != merge_sha):
        raise TapPublicationError("GitHub pull request readback does not confirm the squash merge")
    published = _contents("Formula/ami-rust.rb", "main", missing=True)
    if published != formula:
        raise TapPublicationError("published main formula differs from exact attested bytes")
    record = dict(opened)
    record.update({"status": "MERGED", "merge_commit_sha": merge_sha,
                   "published_formula_sha256": hashlib.sha256(published).hexdigest()})
    _write_receipt(receipt_path, record)
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("open", "merge"))
    parser.add_argument("--formula", required=True, type=Path,
                        help="exact attested ami-rust.rb candidate asset")
    parser.add_argument("--receipt", required=True, type=Path,
                        help="fresh JSON receipt output")
    parser.add_argument("--open-receipt", type=Path,
                        help="open-mode receipt required by merge mode")
    args = parser.parse_args(argv)
    try:
        if args.mode == "open":
            if args.open_receipt is not None:
                parser.error("open mode does not accept --open-receipt")
            record = open_publication(args.formula, args.receipt)
        else:
            if args.open_receipt is None:
                parser.error("merge mode requires --open-receipt")
            record = merge_publication(args.formula, args.open_receipt, args.receipt)
        print(json.dumps({"status": record["status"],
                          "pull_request": record["pull_request"],
                          "head_sha": record["head_sha"],
                          "base_sha": record["base_sha"]}, sort_keys=True))
        return 0
    except TapPublicationError as error:
        print(f"publish_tap: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
