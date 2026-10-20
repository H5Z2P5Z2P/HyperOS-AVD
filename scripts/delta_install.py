#!/usr/bin/env python3
"""Stage an exact release from a verified immutable version and bounded deltas."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse

import bundle_runtime
from common import sha256
from https_transport import secure_urlopen
import incremental

CHUNK = 1024 * 1024
MANIFEST_LIMIT = 2 * 1024 * 1024


def validate_descriptor(value, manifest):
    """Validate the optional transport without changing the complete release."""
    revision = bundle_runtime.REVISION_PATTERN
    tag = (r'pad-v\d+\.\d+\.\d+-a17-hyperos4-yingtian-r' + revision
           if manifest.get('variant') == 'os4-pad'
           else r'v\d+\.\d+\.\d+-a17-hyperos4-hongkong-r' + revision)
    if (not isinstance(value, dict)
            or set(value) != {'protocol', 'from_version', 'from_manifest_sha256', 'parts'}
            or value.get('protocol') != incremental.PROTOCOL
            or not isinstance(value.get('from_version'), str)
            or not re.fullmatch(tag, value['from_version'])
            or value['from_version'] == manifest.get('version')
            or not isinstance(value.get('from_manifest_sha256'), str)
            or not re.fullmatch(r'[0-9a-f]{64}', value['from_manifest_sha256'])
            or not isinstance(value.get('parts'), list) or not value['parts']):
        raise RuntimeError('Invalid incremental release descriptor.')
    seen = {part['name'] for part in manifest.get('parts', [])}
    for part in value['parts']:
        if (not isinstance(part, dict) or set(part) != {'name', 'size', 'sha256'}
                or not isinstance(part.get('name'), str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', part['name'])
                or part['name'] in seen or type(part.get('size')) is not int or part['size'] <= 0
                or not isinstance(part.get('sha256'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', part['sha256'])):
            raise RuntimeError('Invalid incremental archive integrity metadata.')
        seen.add(part['name'])
    return value


def _read_manifest(path, root):
    bundle_runtime.regular(path, root)
    if path.stat().st_size > MANIFEST_LIMIT:
        raise RuntimeError('Oversized installed release manifest.')
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError('Invalid installed release manifest.')
    return value


def _verify_file(path, root, info):
    bundle_runtime.regular(path, root)
    if path.stat().st_size != info['size'] or sha256(path) != info['sha256']:
        raise RuntimeError('Incremental source checksum mismatch: ' + str(path))


def _source_context(root, manifest, descriptor):
    """Authenticate the active source or the pinned full base for delta-only releases."""
    pinned = bundle_runtime.delta_base(manifest)
    use_base = (pinned is not None and descriptor['from_version'] == pinned['version']
                and descriptor['from_manifest_sha256'] == bundle_runtime.manifest_digest(pinned))
    old = pinned if use_base else _read_manifest(root / 'local/installed-release.json', root)
    if (old.get('version') != descriptor['from_version']
            or bundle_runtime.manifest_digest(old) != descriptor['from_manifest_sha256']):
        raise RuntimeError('Release does not match the incremental source.')
    incremental.validate_sources(old, manifest)
    source = root / 'versions' / old['version']
    if use_base:
        try:
            bundle_runtime.verify_staged(source, old)
        except (RuntimeError, OSError, ValueError, TypeError, KeyError) as error:
            raise RuntimeError('The cached incremental base is missing or corrupt. Inspect it before retrying: '
                               + str(source)) from error
        return source, old
    saved = _read_manifest(source / 'local/installed-release.json', root)
    if saved != old:
        raise RuntimeError('Immutable incremental source manifest has changed.')
    # Both copied files and changed patch bases must still match their release.
    for name, info in old['files'].items():
        if name in manifest['files']:
            _verify_file(source / name, root, info)
    return source, old


def select_delta(root, manifest):
    """Choose a smaller applicable delta, or keep the complete-package fallback."""
    root = Path(root).resolve()
    # A delta-only release has no complete fallback. Authenticate its pinned
    # source independently of the active manifest, including on fresh installs.
    pinned = bundle_runtime.delta_base(manifest)
    if pinned is not None:
        if manifest['distribution'] == bundle_runtime.HISTORY_DISTRIBUTION:
            # A current repair user takes its own direct patch, even if the
            # original full base is cached or its patch happens to be smaller.
            try:
                active = _read_manifest(root / 'local/installed-release.json', root)
                descriptor = next((value for value in manifest['deltas']
                    if value['from_version'] == active.get('version')
                    and value['from_manifest_sha256'] == bundle_runtime.manifest_digest(active)), None)
                if descriptor is not None:
                    source, old = _source_context(root, manifest, descriptor)
                    return descriptor, source, old
            except (RuntimeError, OSError, ValueError, TypeError, KeyError):
                pass
        source = root / 'versions' / pinned['version']
        if (root / 'versions').is_symlink():
            raise RuntimeError('Invalid release versions directory.')
        if not source.exists() and not source.is_symlink():
            return None
        descriptor = next(value for value in manifest['deltas']
                          if value['from_version'] == pinned['version']
                          and value['from_manifest_sha256'] == bundle_runtime.manifest_digest(pinned))
        source, old = _source_context(root, manifest, descriptor)
        return descriptor, source, old
    values = manifest.get('deltas', [])
    if not isinstance(values, list):
        return None
    try:
        bundle_runtime.validate_envelope(manifest)
        candidates = []
        for value in values:
            if isinstance(value, dict) and value.get('protocol') != incremental.PROTOCOL:
                continue
            descriptor = validate_descriptor(value, manifest)
            size = sum(part['size'] for part in descriptor['parts'])
            if size >= sum(part['size'] for part in manifest['parts']):
                continue
            candidates.append((size, descriptor))
        for _, descriptor in sorted(candidates, key=lambda candidate: candidate[0]):
            try:
                source, old = _source_context(root, manifest, descriptor)
            except (RuntimeError, OSError, ValueError, TypeError, KeyError):
                continue
            return descriptor, source, old
    except (RuntimeError, OSError, ValueError, TypeError, KeyError):
        return None
    return None


def stage_base(root, base_manifest_path, base_manifest):
    """Cache a full immutable delta source without installing or activating it."""
    import manage
    import setup
    bundle_runtime.validate_envelope(base_manifest)
    if bundle_runtime.delta_base(base_manifest) is not None:
        raise RuntimeError('An incremental base must be a complete release.')
    root = Path(root).resolve()
    versions = root / 'versions'
    target = versions / base_manifest['version']
    if versions.is_symlink() or target.is_symlink():
        raise RuntimeError('Invalid incremental base cache directory.')
    if target.exists():
        try:
            bundle_runtime.verify_staged(target, base_manifest)
        except (RuntimeError, OSError, ValueError, TypeError, KeyError) as error:
            raise RuntimeError('The cached incremental base is incomplete or corrupt. Inspect it before retrying: '
                               + str(target)) from error
        return target
    root.mkdir(parents=True, exist_ok=True)
    required = (sum(info['size'] for info in base_manifest['files'].values())
                + 2 * sum(info['size'] for info in base_manifest['parts']) + 2 * 1024**3)
    if shutil.disk_usage(root).free < required:
        raise RuntimeError('Not enough free disk space to stage the complete incremental base.')
    versions.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.delta-base-', dir=versions) as temporary:
        files = Path(temporary) / 'release'
        files.mkdir()
        try:
            with manage.scope(files):
                setup.stage_bundle(str(base_manifest_path))
        except OSError as error:
            raise RuntimeError('The complete incremental base could not be staged. Keep its manifest and all '
                               'archive parts together, or retry the online update: '
                               + str(base_manifest_path)) from error
        bundle_runtime.verify_staged(files, base_manifest)
        # These archives were downloaded only for this temporary extraction.
        shutil.rmtree(files / 'downloads', ignore_errors=True)
        if target.exists() or target.is_symlink():
            raise RuntimeError('The incremental base cache appeared during staging. Inspect it before retrying: '
                               + str(target))
        files.rename(target)
    return target


def _copy_part(source, output, info):
    """Reject short/oversized transport while holding at most one chunk in RAM."""
    digest = hashlib.sha256()
    remaining = info['size']
    while remaining:
        data = source.read(min(CHUNK, remaining))
        if not data:
            raise RuntimeError('Incremental archive size mismatch: ' + info['name'])
        remaining -= len(data)
        digest.update(data)
        output.write(data)
    if source.read(1) or digest.hexdigest() != info['sha256']:
        raise RuntimeError('Incremental archive checksum mismatch: ' + info['name'])


def _fetch_parts(manifest_path, descriptor, directory):
    value = str(manifest_path)
    remote = value.startswith('https://')
    base = value.rsplit('/', 1)[0] + '/' if remote else Path(value).expanduser().resolve().parent
    paths = []
    for info in descriptor['parts']:
        path = directory / info['name']
        with ExitStack() as stack:
            if remote:
                source = stack.enter_context(secure_urlopen(urllib.parse.urljoin(base, info['name']), timeout=30))
            else:
                original = base / info['name']
                metadata = original.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise RuntimeError('Incremental archive part is not a regular file.')
                source = stack.enter_context(original.open('rb'))
            output = stack.enter_context(path.open('xb'))
            _copy_part(source, output, info)
        paths.append(path)
    return paths


class _PartsReader:
    """Present verified compressed parts sequentially without concatenating them."""
    def __init__(self, paths):
        self.paths = iter(paths)
        self.current = None

    def read(self, size):
        result = bytearray()
        while len(result) < size:
            if self.current is None:
                path = next(self.paths, None)
                if path is None:
                    break
                self.current = path.open('rb')
            data = self.current.read(size - len(result))
            if data:
                result.extend(data)
            else:
                self.current.close()
                self.current = None
        return bytes(result)

    def close(self):
        if self.current is not None:
            self.current.close()
            self.current = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class _RegularMember(tarfile.TarInfo):
    def _proc_member(self, archive):
        # Reject extension headers before tarfile reads their attacker-sized
        # metadata. The producer emits plain regular members with exact names.
        if self.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
            raise RuntimeError('Incremental archive contains a nonregular entry.')
        return super()._proc_member(archive)


def _template_check(directory):
    import setup
    properties = dict(line.split('=', 1) for line in (directory / 'config/avd.ini').read_text().splitlines()
                      if '=' in line)
    if (properties.get('target') != 'android-37.0' or properties.get('hw.cpu.arch') != 'arm64'
            or any(key in properties for key in ('image.sysdir.1', 'path', 'path.rel'))):
        raise RuntimeError('Invalid or nonportable OS4 AVD template.')
    setup.validate_memory(properties)


def _clone_source(source, destination):
    """Try a same-volume clone only inside the new private staging tree."""
    if (sys.platform != 'darwin' or source.stat().st_size < CHUNK
            or source.stat().st_dev != destination.parent.stat().st_dev):
        return False
    if destination.exists() or destination.is_symlink():
        raise RuntimeError('Incremental clone requires an unused staging path.')
    try:
        subprocess.run(['/bin/cp', '-c', str(source), str(destination)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        bundle_runtime.regular(destination, destination.parent)
        destination.chmod(stat.S_IMODE(destination.stat().st_mode) | stat.S_IWUSR)
    except (OSError, subprocess.CalledProcessError):
        # Only this new staging path may have been created by the failed clone.
        destination.unlink(missing_ok=True)
        return False
    return True


def stage_delta(root, target, manifest_path, manifest, descriptor, source_root, old_manifest):
    """Reconstruct and verify a fresh version before publishing its directory."""
    root, requested_target = Path(root).resolve(), Path(target)
    if requested_target.is_symlink():
        raise RuntimeError('Invalid incremental target directory.')
    target = requested_target.resolve()
    bundle_runtime.validate_envelope(manifest)
    validate_descriptor(descriptor, manifest)
    if descriptor not in manifest.get('deltas', []):
        raise RuntimeError('Incremental descriptor is not in the target release manifest.')
    if target != root / 'versions' / manifest['version'] or target.exists() or target.is_symlink():
        raise RuntimeError('Incremental staging requires an unused release version directory.')
    source, old = _source_context(root, manifest, descriptor)
    if Path(source_root) != source or old_manifest != old:
        raise RuntimeError('Incremental source changed after selection.')
    versions = root / 'versions'
    if versions.is_symlink():
        raise RuntimeError('Invalid release versions directory.')
    required = (sum(info['size'] for info in manifest['files'].values())
                + sum(info['size'] for info in descriptor['parts']) + 2 * 1024**3)
    if shutil.disk_usage(root).free < required:
        raise RuntimeError('Not enough free disk space to reconstruct the incremental release.')
    versions.mkdir(parents=True, exist_ok=True)
    changed = {name for name, info in manifest['files'].items() if old['files'].get(name) != info}
    with tempfile.TemporaryDirectory(prefix='.delta-', dir=versions) as temporary:
        staging = Path(temporary)
        transport = staging / 'transport'; transport.mkdir()
        files = staging / 'release'; files.mkdir()
        parts = _fetch_parts(manifest_path, descriptor, transport)
        for name, info in manifest['files'].items():
            if name in changed:
                continue
            original, destination = source / name, files / name
            _verify_file(original, root, info)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if _clone_source(original, destination):
                destination.chmod(0o644)
            else:
                with original.open('rb') as incoming, destination.open('xb') as outgoing:
                    _copy_part(incoming, outgoing, {'name': name, **info})
            _verify_file(original, root, info)
            _verify_file(destination, files, info)
        seen = set()
        with _PartsReader(parts) as incoming:
            try:
                with tarfile.open(fileobj=incoming, mode='r|gz', tarinfo=_RegularMember) as archive:
                    for member in archive:
                        name = member.name
                        if name not in changed or name in seen:
                            raise RuntimeError('Unexpected or duplicate incremental archive entry: ' + name)
                        info = manifest['files'][name]
                        if member.size < 0 or member.size > incremental.patch_limit(info['size']):
                            raise RuntimeError('Oversized incremental patch member: ' + name)
                        destination = files / name
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        original = source / name if name in old['files'] else None
                        old_size = old['files'][name]['size'] if original is not None else 0
                        if original is not None:
                            _verify_file(original, root, old['files'][name])
                        seeded = original is not None and _clone_source(original, destination)
                        with archive.extractfile(member) as patch, destination.open('r+b' if seeded else 'xb') as output:
                            incremental.apply_patch(original, patch, output, old_size, info['size'], seeded=seeded)
                            if patch.read(1):
                                raise RuntimeError('Trailing bytes in incremental patch: ' + name)
                        if seeded:
                            destination.chmod(0o644)
                        if original is not None:
                            _verify_file(original, root, old['files'][name])
                        _verify_file(destination, files, info)
                        seen.add(name)
            except (tarfile.TarError, EOFError) as error:
                raise RuntimeError('Invalid incremental archive.') from error
        if seen != changed:
            raise RuntimeError('Incremental archive is incomplete.')
        # Recheck the source identity after all reads, before the new version
        # becomes visible, and authenticate every resulting target file.
        current_source, current_old = _source_context(root, manifest, descriptor)
        if current_source != source or current_old != old:
            raise RuntimeError('Incremental source changed during staging.')
        _template_check(files)
        local = files / 'local'; local.mkdir()
        (local / 'build.json').write_text(json.dumps(manifest['build'], indent=2) + '\n')
        (local / 'installed-release.json').write_text(json.dumps(manifest, indent=2) + '\n')
        bundle_runtime.verify_staged(files, manifest)
        files.rename(target)
    return target
