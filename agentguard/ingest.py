from __future__ import annotations

import shutil
import ipaddress
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

MAX_BYTES = 100 * 1024 * 1024
MAX_FILES = 10_000
ALLOWED_GIT_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})


class IngestionError(Exception):
    pass


def _validate_remote_url(source: str) -> urllib.parse.ParseResult:
    if not source or source.startswith("-") or any(char in source for char in "\r\n\x00"):
        raise IngestionError("Invalid source URL")
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme != "https" or parsed.hostname is None:
        raise IngestionError("Remote sources must use HTTPS")
    if parsed.username or parsed.password or parsed.port:
        raise IngestionError("Remote URLs must not contain credentials or explicit ports")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname not in ALLOWED_GIT_HOSTS:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise IngestionError("IP-literal and private network URLs are not allowed")
        raise IngestionError(f"Remote host is not allowlisted: {hostname}")
    if parsed.query or parsed.fragment:
        raise IngestionError("Remote URLs must not contain query strings or fragments")
    return parsed


def _safe_copytree(source: Path, target: Path) -> int:
    source = source.resolve()
    count = 0
    for path in source.rglob("*"):
        if path.is_symlink():
            resolved = path.resolve()
            if source not in resolved.parents:
                raise IngestionError(f"Symlink escapes source directory: {path}")
            continue
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        count += 1
        if count > MAX_FILES:
            raise IngestionError("Source contains too many files")
        if sum(item.stat().st_size for item in target.rglob("*") if item.is_file()) > MAX_BYTES:
            raise IngestionError("Source exceeds the size limit")
    return count


def _safe_member_path(root: Path, member_name: str) -> Path:
    relative = PurePosixPath(member_name)
    if relative.is_absolute() or ".." in relative.parts:
        raise IngestionError(f"Archive traversal path rejected: {member_name}")
    destination = (root / Path(*relative.parts)).resolve()
    if root.resolve() not in destination.parents and destination != root.resolve():
        raise IngestionError(f"Archive path escapes destination: {member_name}")
    return destination


def _extract_zip(source: Path, destination: Path) -> int:
    total = 0
    count = 0
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            count += 1
            if count > MAX_FILES:
                raise IngestionError("Archive contains too many files")
            target = _safe_member_path(destination, info.filename)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += info.file_size
            if total > MAX_BYTES:
                raise IngestionError("Archive exceeds the uncompressed size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as input_file, target.open("wb") as output_file:
                shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
    return count


def _extract_tar(source: Path, destination: Path) -> int:
    count = 0
    total = 0
    with tarfile.open(source) as archive:
        for member in archive.getmembers():
            count += 1
            if count > MAX_FILES:
                raise IngestionError("Archive contains too many files")
            target = _safe_member_path(destination, member.name)
            if member.issym() or member.islnk():
                raise IngestionError(f"Archive link rejected: {member.name}")
            if member.isfile():
                total += member.size
                if total > MAX_BYTES:
                    raise IngestionError("Archive exceeds the uncompressed size limit")
            archive.extract(member, destination)
    return count


def _download(url: str, destination: Path) -> Path:
    parsed = urllib.parse.urlparse(url)
    suffix = Path(parsed.path).suffix or ".download"
    target = destination / f"source{suffix}"
    total = 0
    with urllib.request.urlopen(url, timeout=30) as response, target.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_BYTES:
                raise IngestionError("Downloaded source exceeds the size limit")
            output.write(chunk)
    return target


def _git_clone_spec(source: str) -> tuple[str, str, str | None, str | None] | None:
    """Return a clone URL, optional branch, and optional repository subpath."""
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme != "https" or parsed.hostname is None or parsed.hostname.lower() not in ALLOWED_GIT_HOSTS:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None
    owner, repository = parts[0], parts[1]
    if repository.endswith(".git"):
        repository = repository[:-4]
    branch = None
    subpath = None
    if len(parts) >= 4 and parts[2] == "tree":
        branch = parts[3]
        subpath = "/".join(parts[4:]) or None
    host = parsed.hostname.lower()
    return f"https://{host}/{owner}/{repository}.git", host, branch, subpath


def _github_clone_spec(source: str) -> tuple[str, str | None, str | None] | None:
    spec = _git_clone_spec(source)
    if spec is None:
        return None
    clone_url, _host, branch, subpath = spec
    return clone_url, branch, subpath


def materialize(source: str, workspace: Path) -> tuple[Path, dict[str, object]]:
    """Materialize a local directory, archive, Git URL, or downloadable archive."""
    workspace.mkdir(parents=True, exist_ok=True)
    source_path = Path(source).expanduser()
    if source_path.exists():
        if source_path.is_dir():
            skill_dirs = sorted({path.parent for path in source_path.rglob("SKILL.md") if path.is_file()})
            if len(skill_dirs) > 1:
                raise IngestionError("Directory contains multiple skills; provide one skill directory")
            target = workspace / "skill"
            count = _safe_copytree(source_path, target)
            return target, {"kind": "directory", "files": count}
        archive_dir = workspace / "skill"
        archive_dir.mkdir()
        name = source_path.name.lower()
        count = _extract_tar(source_path, archive_dir) if name.endswith((".tar.gz", ".tgz", ".tar")) else _extract_zip(source_path, archive_dir)
        return archive_dir, {"kind": "archive", "files": count}

    parsed = urllib.parse.urlparse(source)
    if parsed.scheme:
        _validate_remote_url(source)
    if parsed.scheme == "https" and parsed.path.endswith((".zip", ".tar.gz", ".tgz")):
        downloaded = _download(source, workspace)
        archive_dir = workspace / "skill"
        archive_dir.mkdir()
        name = downloaded.name.lower()
        count = _extract_tar(downloaded, archive_dir) if name.endswith((".tar.gz", ".tgz")) else _extract_zip(downloaded, archive_dir)
        return archive_dir, {"kind": "remote_archive", "files": count}

    git_spec = _git_clone_spec(source)
    if git_spec:
        clone_url, _host, branch, subpath = git_spec
        target = workspace / "skill"
        command = [
            "git", "-c", "core.hooksPath=/dev/null", "clone", "--depth", "1",
            "--no-recurse-submodules", "--no-checkout",
        ]
        if branch:
            command.extend(["--branch", branch])
        command.extend(["--", clone_url, str(target)])
        completed = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
        if completed.returncode:
            raise IngestionError(completed.stderr.strip() or "Git clone failed")
        checkout = subprocess.run(
            ["git", "-C", str(target), "checkout", "--force", "HEAD", "--"],
            capture_output=True, text=True, timeout=120, check=False,
        )
        if checkout.returncode:
            raise IngestionError(checkout.stderr.strip() or "Git checkout failed")
        if subpath:
            if any(part in {"", ".", ".."} for part in PurePosixPath(subpath).parts):
                raise IngestionError("Git repository subpath is unsafe")
            selected = (target / Path(*PurePosixPath(subpath).parts)).resolve()
            if target.resolve() not in selected.parents or not selected.is_dir():
                raise IngestionError(f"GitHub tree path not found: {subpath}")
            target = selected
        skill_dirs = sorted({path.parent for path in target.rglob("SKILL.md") if path.is_file()})
        if len(skill_dirs) > 1 and subpath is None:
            raise IngestionError("Repository contains multiple skills; provide a /tree/<ref>/skills/<name> URL")
        commit = subprocess.run(
            ["git", "-C", str(workspace / "skill"), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=30, check=False,
        ).stdout.strip()
        return target, {
            "kind": "github",
            "url": source,
            "clone_url": clone_url,
            "branch": branch or "default",
            "subpath": subpath,
            "files": sum(1 for _ in target.rglob("*") if _.is_file()),
            "commit_sha": commit,
        }

    raise IngestionError("Source must be a local directory, archive, GitHub URL, or archive URL")


def temporary_workspace(base_dir: Path) -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(prefix="agentguard-", dir=str(base_dir) if base_dir.exists() else None)
