from __future__ import annotations

import shutil
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

MAX_BYTES = 100 * 1024 * 1024
MAX_FILES = 10_000


class IngestionError(Exception):
    pass


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


def _github_clone_spec(source: str) -> tuple[str, str | None, str | None] | None:
    """Return a clone URL, optional branch, and optional repository subpath."""
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != "github.com":
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
    return f"https://github.com/{owner}/{repository}.git", branch, subpath


def materialize(source: str, workspace: Path) -> tuple[Path, dict[str, object]]:
    """Materialize a local directory, archive, Git URL, or downloadable archive."""
    workspace.mkdir(parents=True, exist_ok=True)
    source_path = Path(source).expanduser()
    if source_path.exists():
        if source_path.is_dir():
            target = workspace / "skill"
            shutil.copytree(source_path, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            return target, {"kind": "directory", "files": sum(1 for _ in target.rglob("*"))}
        archive_dir = workspace / "skill"
        archive_dir.mkdir()
        name = source_path.name.lower()
        count = _extract_tar(source_path, archive_dir) if name.endswith((".tar.gz", ".tgz", ".tar")) else _extract_zip(source_path, archive_dir)
        return archive_dir, {"kind": "archive", "files": count}

    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in {"http", "https"} and parsed.path.endswith((".zip", ".tar.gz", ".tgz")):
        downloaded = _download(source, workspace)
        archive_dir = workspace / "skill"
        archive_dir.mkdir()
        name = downloaded.name.lower()
        count = _extract_tar(downloaded, archive_dir) if name.endswith((".tar.gz", ".tgz")) else _extract_zip(downloaded, archive_dir)
        return archive_dir, {"kind": "remote_archive", "files": count}

    github_spec = _github_clone_spec(source)
    if github_spec:
        clone_url, branch, subpath = github_spec
        target = workspace / "skill"
        command = ["git", "clone", "--depth", "1", "--no-recurse-submodules"]
        if branch:
            command.extend(["--branch", branch])
        command.extend([clone_url, str(target)])
        completed = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
        if completed.returncode:
            raise IngestionError(completed.stderr.strip() or "Git clone failed")
        if subpath:
            selected = (target / Path(*PurePosixPath(subpath).parts)).resolve()
            if target.resolve() not in selected.parents or not selected.is_dir():
                raise IngestionError(f"GitHub tree path not found: {subpath}")
            target = selected
        return target, {
            "kind": "github",
            "url": source,
            "clone_url": clone_url,
            "branch": branch or "default",
            "subpath": subpath,
            "files": sum(1 for _ in target.rglob("*")),
        }

    raise IngestionError("Source must be a local directory, archive, GitHub URL, or archive URL")


def temporary_workspace(base_dir: Path) -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(prefix="agentguard-", dir=str(base_dir) if base_dir.exists() else None)
