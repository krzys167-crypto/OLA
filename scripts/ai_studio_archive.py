"""Fail-closed installer for the existing, independently deployed AI STUDIO 3.6.0.

The upstream OLA database, API, and identity system are NOT modified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile

ROOT = 'AI_STUDIO_3.6.0_PRODUCTION'
PINNED_SHA256 = '29b9c6614e8af1a702e01993e766240760ee55837f1a68d0d94925fb7f99d890'
REQUIRED = {'backend/main.py', 'frontend/index.html', 'Dockerfile', 'requirements.txt', '.env.example'}
MAX_UNCOMPRESSED = 25_000_000
MAX_MEMBERS = 400

COMPOSE = '''# Separate, loopback-only staging service; OLA Core remains unchanged.
services:
  ai-studio:
    build:
      context: .
    ports:
      - "127.0.0.1:${OLA_STUDIO_PORT:-8001}:8000"
    env_file:
      - .env
    environment:
      ENVIRONMENT: development
    volumes:
      - ./data:/app/data
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"]
      interval: 30s
      timeout: 5s
      retries: 3
'''

class ArchiveError(ValueError):
    """Archive or installation failed a mandatory integrity/safety check."""


def _safe_name(member: tarfile.TarInfo) -> str | None:
    if not (member.isfile() or member.isdir()):
        raise ArchiveError(f'unsafe member type: {member.name}')
    path = member.name.rstrip('/')
    parts = path.split('/')
    if any(p in ('', '.', '..') for p in parts) or '\\' in path or path.startswith('/'):
        raise ArchiveError(f'unsafe member path: {member.name}')
    if parts[0] != ROOT:
        raise ArchiveError(f'unsafe archive root: {member.name}')
    return '/'.join(parts[1:]) or None


def inspect_archive(path: str | Path, expected_sha: str | None = PINNED_SHA256) -> dict:
    archive = Path(path)
    if not archive.is_file():
        raise ArchiveError(f'archive missing: {archive}')
    if archive.stat().st_size > 25_000_000:
        raise ArchiveError('unsafe compressed archive size')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if expected_sha is not None and digest != expected_sha:
        raise ArchiveError(f'SHA256 mismatch: got {digest}, expected {expected_sha}')
    files: set[str] = set()
    seen: set[str] = set()
    size = 0
    try:
        with tarfile.open(archive, mode='r:gz') as src:
            members = src.getmembers()
            if len(members) > MAX_MEMBERS:
                raise ArchiveError('unsafe number of archive members')
            for member in members:
                name = _safe_name(member)
                if name is None:
                    continue
                if name in seen:
                    raise ArchiveError(f'unsafe duplicate member: {name}')
                if name == '.env' or (name.startswith('data/') and (name.endswith('.key') or name.endswith('.db'))):
                    raise ArchiveError(f'unsafe secret or runtime data: {name}')
                seen.add(name)
                if member.isfile():
                    files.add(name)
                    size += member.size
                if size > MAX_UNCOMPRESSED:
                    raise ArchiveError('unsafe uncompressed archive size')
    except (tarfile.TarError, OSError) as exc:
        raise ArchiveError(f'archive format error: {exc}') from exc
    missing = REQUIRED - files
    if missing:
        raise ArchiveError(f'missing required files: {sorted(missing)}')
    return {'sha256': digest, 'files': len(files), 'bytes_uncompressed': size, 'status': 'ARCHIVE_VERIFIED'}


def extract_verified(path: str | Path, target: str | Path, expected_sha: str | None = PINNED_SHA256) -> dict:
    result = inspect_archive(path, expected_sha)
    dest = Path(target).absolute()
    if dest.exists():
        raise ArchiveError(f'target already exists (will not overwrite): {dest}')
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix='.studio-verify-', dir=dest.parent))
    try:
        with tarfile.open(path, mode='r:gz') as src:
            for member in src.getmembers():
                name = _safe_name(member)
                if name is None:
                    continue
                out = tmp.joinpath(*PurePosixPath(name).parts)
                if member.isdir():
                    out.mkdir(parents=True, exist_ok=True)
                else:
                    out.parent.mkdir(parents=True, exist_ok=True)
                    stream = src.extractfile(member)
                    if stream is None:
                        raise ArchiveError(f'could not read member: {name}')
                    with stream, out.open('wb') as dst:
                        shutil.copyfileobj(stream, dst)
        env = tmp / '.env.example'
        if not env.is_file():
            raise ArchiveError('missing .env.example')
        env_text = env.read_text(encoding='utf-8')
        env_text = '\n'.join(
            'ENVIRONMENT=development' if line.startswith('ENVIRONMENT=') else line
            for line in env_text.splitlines()
        ) + '\n'
        (tmp / '.env').write_text(env_text, encoding='utf-8')
        os.chmod(tmp / '.env', 0o600)
        (tmp / 'docker-compose.ola.yml').write_text(COMPOSE, encoding='utf-8')
        (tmp / 'OLA_ARCHIVE_SOURCE.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        os.replace(tmp, dest)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return {**result, 'installed_at': str(dest), 'mode': 'isolated_staging'}


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('command', choices=['verify', 'install'])
    cli.add_argument('--archive', required=True, type=Path)
    cli.add_argument('--target', type=Path)
    args = cli.parse_args()
    if args.command == 'install':
        if args.target is None:
            cli.error('install requires --target')
        result = extract_verified(args.archive, args.target)
    else:
        result = inspect_archive(args.archive)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
