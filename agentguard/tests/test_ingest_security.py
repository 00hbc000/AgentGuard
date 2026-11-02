import pytest

from agentguard.ingest import IngestionError, _validate_remote_url, materialize


@pytest.mark.parametrize("source", [
    "http://github.com/acme/skill",
    "https://user:pass@github.com/acme/skill",
    "file:///etc/passwd",
    "ssh://git@github.com/acme/skill",
    "https://localhost/acme/skill",
    "https://127.0.0.1/acme/skill",
    "https://github.com/acme/skill?token=secret",
    "-https://github.com/acme/skill",
])
def test_remote_url_validation_rejects_unsafe_sources(source):
    with pytest.raises(IngestionError):
        _validate_remote_url(source)


def test_remote_url_validation_accepts_public_git_hosts():
    for host in ("github.com", "gitlab.com", "bitbucket.org"):
        assert _validate_remote_url(f"https://{host}/acme/skill").hostname == host


def test_multi_skill_repository_is_rejected_for_unselected_remote(tmp_path, monkeypatch):
    source = tmp_path / "source"
    (source / "one").mkdir(parents=True)
    (source / "two").mkdir()
    (source / "one" / "SKILL.md").write_text("---\nname: one\ndescription: one\n---\n", encoding="utf-8")
    (source / "two" / "SKILL.md").write_text("---\nname: two\ndescription: two\n---\n", encoding="utf-8")
    with pytest.raises(IngestionError):
        materialize(str(source), tmp_path / "workspace")


def test_cloned_repository_symlinks_are_removed(tmp_path):
    from agentguard.ingest import _remove_symlinks

    (tmp_path / "SKILL.md").write_text("---\nname: x\ndescription: x\n---\n")
    (tmp_path / "leak").symlink_to("/etc/passwd")
    (tmp_path / ".git").mkdir()
    assert _remove_symlinks(tmp_path) == 1
    assert not (tmp_path / "leak").is_symlink() and (tmp_path / "SKILL.md").exists()
