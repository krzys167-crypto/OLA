import io
import pathlib
import tarfile
import pytest
from scripts.ai_studio_archive import ArchiveError, extract_verified, inspect_archive

PREFIX = 'AI_STUDIO_3.6.0_PRODUCTION/'
FILES = {
    'backend/main.py': b'from fastapi import FastAPI\napp = FastAPI()\n',
    'frontend/index.html': b'<!doctype html><title>AI STUDIO</title>',
    'Dockerfile': b'FROM python:3.12-slim\n',
    '.env.example': b'ENVIRONMENT=production\nOPENAI_API_KEY=\n',
    'requirements.txt': b'fastapi==0.1\n',
    'tests/test_import.py': b'def test_x(): assert True\n',
}

def archive(path, extra=None, symlink=None):
    with tarfile.open(path, 'w:gz') as t:
        for name, content in {**FILES, **(extra or {})}.items():
            entry = tarfile.TarInfo(PREFIX + name)
            entry.size = len(content)
            t.addfile(entry, io.BytesIO(content))
        if symlink:
            entry = tarfile.TarInfo(PREFIX + symlink)
            entry.type = tarfile.SYMTYPE
            entry.linkname = '/etc/passwd'
            t.addfile(entry)

def test_integrity_requires_pinned_digest(tmp_path):
    a = tmp_path / 'studio.tgz'
    archive(a)
    import hashlib
    sha = hashlib.sha256(a.read_bytes()).hexdigest()
    assert inspect_archive(a, expected_sha=sha)['files'] == len(FILES)
    with pytest.raises(ArchiveError, match='SHA256'):
        inspect_archive(a, expected_sha='0' * 64)

def test_rejects_path_traversal_and_symlinks(tmp_path):
    a = tmp_path / 'bad.tgz'
    archive(a, extra={'../escape.txt': b'evil'})
    with pytest.raises(ArchiveError, match='unsafe'):
        inspect_archive(a, expected_sha=None)
    archive(a, symlink='leak')
    with pytest.raises(ArchiveError, match='unsafe'):
        inspect_archive(a, expected_sha=None)

def test_extract_is_non_destructive(tmp_path):
    a = tmp_path / 'studio.tgz'
    archive(a)
    target = tmp_path / 'run'
    extract_verified(a, target, expected_sha=None)
    assert (target / 'frontend/index.html').read_bytes() == FILES['frontend/index.html']
    assert (target / 'docker-compose.ola.yml').exists()
    assert (target / '.env').exists()
    with pytest.raises(ArchiveError, match='exists'):
        extract_verified(a, target, expected_sha=None)

def test_missing_module_rejected(tmp_path):
    a = tmp_path / 'missing.tgz'
    with tarfile.open(a, 'w:gz') as t:
        entry = tarfile.TarInfo(PREFIX + 'README.md')
        entry.size = 1
        t.addfile(entry, io.BytesIO(b'x'))
    with pytest.raises(ArchiveError, match='missing'):
        inspect_archive(a, expected_sha=None)


def test_rejects_packaged_private_key(tmp_path):
    a = tmp_path / "secret.tgz"
    archive(a, extra={"data/evidence_ed25519.key": b"not-a-key"})
    with pytest.raises(ArchiveError, match="unsafe secret"):
        inspect_archive(a, expected_sha=None)
