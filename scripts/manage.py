#!/usr/bin/env python3
"""Bilingual release manager with isolated instances and recoverable upgrades."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

import common
import setup
from https_transport import secure_urlopen
from common import REPO_ROOT, avd_home, host_check, port_free, sdk_path, sha256

VERSION = '1.3.0'
MODULE_UPGRADE_PREFLIGHT = 'phone-owned-module-guards-v1'
FORWARD_UPGRADE_POLICY = 'same-family-forward-v1'
REPOSITORY = 'NEORUAA/HyperOS-AVD'
HOME = Path(os.environ.get('HYPEROS_AVD_HOME', Path.home() / 'HyperOS-AVD')).expanduser().resolve()
LANG = 'zh'


def tr(zh, en):
    return zh if LANG == 'zh' else en


def say(zh, en):
    print(tr(zh, en), flush=True)


def ask(zh, en, default=''):
    value = input(tr(zh, en) + (f' [{default}]' if default != '' else '') + ': ').strip()
    return value or str(default)


class Back(Exception):
    """Return to the dashboard before any mutating operation."""


def display_width(value):
    return sum(0 if unicodedata.combining(c) else
               2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1 for c in value)


def wrap_line(value, width):
    line = ''
    for char in str(value):
        if char == '\n' or display_width(line + char) > width:
            yield line
            line = ''
        if char != '\n':
            line += char
    yield line


def panel(title, rows, width=None):
    """Draw ASCII borders with correct Chinese terminal-cell alignment."""
    width = width or max(36, min(88, shutil.get_terminal_size((88, 24)).columns - 2))
    inner = width - 4
    border = '+' + '-' * (width - 2) + '+'
    print(border)
    for section in ([title], rows):
        for row in section:
            for line in wrap_line(row, inner):
                print('| ' + line + ' ' * (inner - display_width(line)) + ' |')
        print(border)


def choose(title, rows, default=1):
    panel(title, [f'[{i}] {row}' for i, row in enumerate(rows, 1)] +
          [tr('[0] 返回主菜单', '[0] Back to dashboard')])
    while True:
        value = ask('选择', 'Select', default)
        if value == '0':
            raise Back()
        if value.isdigit() and 1 <= int(value) <= len(rows):
            return int(value) - 1
        say('编号超出范围，请重新选择。', 'Out of range; choose a listed number.')


def progress(name, received, total):
    fraction = received / max(total, 1)
    filled = min(24, int(fraction * 24))
    bar = '[' + '#' * filled + '-' * (24 - filled) + ']'
    print(f'\r{bar} {fraction:6.1%}  {received / 1024**2:.1f}/{total / 1024**2:.1f} MiB',
          end='', flush=True)


def release_variant(release):
    tag = release.get('tag_name', '').lower()
    if tag in ('v0.1.0', 'v0.1.0-a16-hyperos3-fuxi-r1') or re.fullmatch(r'v\d+\.\d+\.\d+-a\d+-hyperos3-.+', tag):
        return 'os3'
    if re.fullmatch(r'pad-v\d+\.\d+\.\d+-a17-hyperos4-yingtian-r\d+(?:\.\d+)*', tag):
        return 'os4-pad'
    # Unpublished shared-version Pad tags must not appear as phone images.
    if re.fullmatch(r'v\d+\.\d+\.\d+-a\d+-hyperos4-yingtian-.+', tag):
        return None
    if re.fullmatch(r'v\d+\.\d+\.\d+-a\d+-hyperos4-.+', tag):
        return 'os4-official'
    return None


def version_key(tag):
    match = re.match(r'(?:pad-)?v?(\d+)\.(\d+)\.(\d+)', tag)
    return tuple(map(int, match.groups())) if match else (0, 0, 0)


def release_order(version):
    revision = re.search(r'(?:-|_)r(\d+(?:\.\d+)*)$', version)
    parts = tuple(map(int, revision.group(1).split('.'))) if revision else (0,)
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return version_key(version), parts


def request(url):
    return urllib.request.Request(url, headers={'User-Agent': 'HyperOS-AVD/' + VERSION,
        'Accept': 'application/vnd.github+json'})


def remote_json(url):
    with secure_urlopen(request(url), timeout=30) as response:
        data = response.read(2 * 1024**2 + 1)
    if len(data) > 2 * 1024**2:
        raise RuntimeError('Oversized remote metadata.')
    return json.loads(data)


def release_rows():
    for page in range(1, 11):
        rows = remote_json(f'https://api.github.com/repos/{REPOSITORY}/releases?per_page=100&page={page}')
        yield from rows
        if len(rows) < 100:
            break


def catalog(variant='all', stable_only=False):
    """List prereleases too; GitHub's latest endpoint omits this project's builds."""
    found = []
    for release in release_rows():
        kind = release_variant(release)
        if (release.get('draft') or stable_only and release.get('prerelease')
                or not kind or variant != 'all' and variant != kind):
            continue
        assets = {item['name']: item for item in release.get('assets', [])}
        if 'manifest.json' in assets:
            found.append({**release, 'asset_map': assets})
    return sorted(found, key=lambda item: (release_order(item['tag_name']), item.get('published_at', '')), reverse=True)


def installer_catalog():
    rows = release_rows()
    return sorted([r for r in rows if not r.get('draft') and not r.get('prerelease')
                   and re.fullmatch(r'installer-v\d+\.\d+\.\d+', r.get('tag_name', ''))],
                  key=lambda r: version_key(r['tag_name'].removeprefix('installer-')), reverse=True)


def download(url, target, size, checksum):
    """Resume a partial transfer; validate before promoting it to the cache."""
    if not re.fullmatch(r'[0-9a-f]{64}', checksum) or size < 0:
        raise RuntimeError('Invalid download checksum or size.')
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_file() and target.stat().st_size == size and sha256(target) == checksum:
        return target
    partial = target.with_name(target.name + '.partial')
    if partial.exists() and partial.stat().st_size > size:
        partial.unlink()
    for attempt in range(3):
        offset = partial.stat().st_size if partial.exists() else 0
        if offset == size:
            if sha256(partial) != checksum:
                partial.unlink()
                if attempt == 2:
                    raise RuntimeError('Download checksum mismatch: ' + target.name)
                continue
            partial.replace(target)
            return target
        req = request(url)
        if offset:
            req.add_header('Range', f'bytes={offset}-')
        try:
            print(tr('下载：', 'Downloading: ') + target.name, flush=True)
            with secure_urlopen(req, timeout=60) as response:
                status = response.getcode()
                if offset and status != 206:
                    offset = 0  # Some release CDNs ignore Range; restart safely.
                if status == 206 and not response.headers.get('Content-Range', '').startswith(f'bytes {offset}-'):
                    raise RuntimeError('Invalid partial download response.')
                last = time.monotonic()
                with partial.open('ab' if offset else 'wb') as output:
                    while True:
                        block = response.read(1024**2)
                        if not block:
                            break
                        offset += len(block)
                        if offset > size:
                            raise RuntimeError('Download exceeds manifest size.')
                        output.write(block)
                        if time.monotonic() - last > 2:
                            progress(target.name, offset, size)
                            last = time.monotonic()
            progress(target.name, offset, size)
            print(flush=True)
        except (OSError, urllib.error.URLError, http.client.HTTPException):
            if attempt == 2:
                raise
        # Verification occurs on the next iteration, or here after the final attempt.
    if partial.stat().st_size != size or sha256(partial) != checksum:
        raise RuntimeError('Incomplete or corrupt download: ' + target.name)
    partial.replace(target)
    return target


def local_base_bundle(manifest_path, base):
    """Find an offline full dependency beside or inside the patch directory."""
    from bundle_runtime import manifest_digest, regular
    parent = Path(manifest_path).resolve().parent
    for directory in (parent / base['version'], parent.parent / base['version']):
        path = directory / 'manifest.json'
        try:
            regular(path, directory)
            if path.stat().st_size <= 2 * 1024**2 and manifest_digest(json.loads(path.read_text())) == manifest_digest(base):
                return path
        except (OSError, RuntimeError, ValueError, TypeError):
            continue
    return None


def prepare_delta_base(root, manifest_path, manifest, *, cache=None):
    """Cache a full dependency without installing it or touching active data."""
    from bundle_runtime import delta_base
    from delta_install import stage_base
    base = delta_base(manifest)
    if base is None:
        return
    target = root / 'versions' / base['version']
    path = local_base_bundle(manifest_path, base)
    if not target.exists() and path is None:
        if cache is None:
            raise RuntimeError('This delta-only release requires the full base bundle ' + base['version']
                               + '. Place its release folder beside the patch folder, or install online.')
        say('先下载所需的完整包：' + base['version'], 'Downloading the required full base: ' + base['version'])
        release = remote_json('https://api.github.com/repos/' + REPOSITORY + '/releases/tags/'
                              + urllib.parse.quote(base['version'], safe=''))
        if release.get('draft') or release.get('tag_name') != base['version']:
            raise RuntimeError('The required complete base release is unavailable.')
        release['asset_map'] = {item['name']: item for item in release.get('assets', [])}
        path = fetch_release(release, cache, expected_manifest=base)
    with lock(root):
        stage_base(root, path or manifest_path, base)


def fetch_release(release, cache, root=None, *, expected_manifest=None):
    assets = release['asset_map']
    cache = Path(cache) / release['tag_name']
    cache.mkdir(parents=True, exist_ok=True)
    entry = assets['manifest.json']
    checksum = entry.get('digest') or ''
    if checksum.startswith('sha256:'):
        checksum = checksum[7:]
    else:
        sums = assets.get('SHA256SUMS')
        if not sums:
            raise RuntimeError('Release is missing manifest integrity metadata.')
        with secure_urlopen(request(sums['browser_download_url']), timeout=30) as response:
            lines = response.read(65536).decode().splitlines()
        matches = [line.split()[0] for line in lines if line.split()[-1:] == ['manifest.json']]
        if len(matches) != 1:
            raise RuntimeError('Ambiguous manifest checksum.')
        checksum = matches[0]
    manifest_path = download(entry['browser_download_url'], cache / 'manifest.json', entry['size'], checksum)
    manifest, _ = setup.read_install_manifest(str(manifest_path))
    if manifest['version'] != release['tag_name']:
        # OS3 r1 used v0.1.0 as its bundle version; only that known legacy mapping is accepted.
        if (manifest['version'], release['tag_name']) != ('v0.1.0', 'v0.1.0-a16-hyperos3-fuxi-r1'):
            raise RuntimeError('Manifest does not match the selected release.')
    if expected_manifest is not None:
        from bundle_runtime import manifest_digest
        if manifest_digest(manifest) != manifest_digest(expected_manifest):
            raise RuntimeError('The downloaded base manifest differs from the patch dependency.')
    minimum = manifest.get('compatibility', {}).get('minimum_installer', '0.2.1')
    if version_key(minimum) > version_key(VERSION):
        raise RuntimeError('This release needs a newer installer; download the latest stable Installer Release.')

    def fetch_parts(parts):
        for part in parts:
            asset = assets.get(part['name'])
            if not asset or asset['size'] != part['size']:
                raise RuntimeError('Release is missing a matching archive part.')
            download(asset['browser_download_url'], cache / part['name'], part['size'], part['sha256'])

    from bundle_runtime import delta_base
    base = delta_base(manifest)
    if base is not None and root is None:
        raise RuntimeError('A delta-only release requires an instance root to reconstruct its complete base.')
    if root is not None:
        from bundle_runtime import has_protocol, verify_staged
        from delta_install import select_delta, stage_delta
        root = Path(root).expanduser().resolve()
        target = root / 'versions' / manifest['version']
        if has_protocol(manifest):
            if (target / 'local/installed-release.json').is_file():
                verify_staged(target, manifest)
                say('目标版本已在本地，直接使用。', 'Using the verified local target version.')
                return manifest_path
            if base is not None:
                prepare_delta_base(root, manifest_path, manifest, cache=cache.parent)
                selection = select_delta(root, manifest)
                if selection is None:
                    raise RuntimeError('The complete base could not be prepared for this delta-only release.')
                descriptor, source, old = selection
                size = sum(part['size'] for part in descriptor['parts'])
                say(f'仅增量修复：{size / 1024**2:.1f} MiB', f'Delta-only repair: {size / 1024**2:.1f} MiB')
                fetch_parts(descriptor['parts'])
                with lock(root):
                    current = select_delta(root, manifest)
                    if current != selection:
                        raise RuntimeError('Incremental base changed during download.')
                    if target.exists():
                        verify_staged(target, manifest)
                    else:
                        stage_delta(root, target, manifest_path, manifest, descriptor, source, old)
                say('增量还原与校验完成。', 'Incremental reconstruction and verification complete.')
                return manifest_path
            selection = select_delta(root, manifest)
            if selection is not None:
                descriptor, source, old = selection
                delta_size = sum(part['size'] for part in descriptor['parts'])
                full_size = sum(part['size'] for part in manifest['parts'])
                say(f'增量更新：{delta_size / 1024**2:.1f} MiB（完整包 {full_size / 1024**2:.1f} MiB）',
                    f'Incremental update: {delta_size / 1024**2:.1f} MiB (full bundle {full_size / 1024**2:.1f} MiB)')
                try:
                    fetch_parts(descriptor['parts'])
                    # Download outside the instance lock, then repeat source
                    # selection under the lock before constructing a new version.
                    with lock(root):
                        current = select_delta(root, manifest)
                        if current is None or current != selection:
                            raise RuntimeError('Incremental source changed during download.')
                        if target.exists():
                            verify_staged(target, manifest)
                        else:
                            stage_delta(root, target, manifest_path, manifest, descriptor, source, old)
                    say('增量还原与校验完成。', 'Incremental reconstruction and verification complete.')
                    return manifest_path
                except (OSError, RuntimeError, ValueError, EOFError, tarfile.TarError, http.client.HTTPException):
                    say('增量更新未完成，改用完整包。', 'Incremental update unavailable; using the full bundle.')
    fetch_parts(manifest['parts'])
    return manifest_path


def properties(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines() if '=' in line)


def instances():
    """Discover project instances by registry ownership; never contact a guest."""
    results = []
    for registry in sorted(avd_home().glob('*.ini')):
        try:
            avd = Path(properties(registry)['path']).expanduser().resolve()
            root = avd.parent.parent
            runtime = json.loads((root / 'local/runtime.json').read_text())
            if avd != root / 'avd' / (runtime['name'] + '.avd') or registry.stem != runtime['name']:
                continue
            installed = root / 'local/installed-release.json'
            metadata = json.loads(installed.read_text()) if installed.is_file() else {}
            build = root / 'local/build.json'
            source = json.loads(build.read_text()).get('source') if build.is_file() else None
            if source is None:
                source = metadata.get('build', {}).get('source', metadata.get('source'))
            variant = {common.OS4_SOURCE: 'os4-official',
                       'official-yingtian-ota': 'os4-pad'}.get(source)
            template = root / 'config/avd.ini'
            legacy_os3 = ((root / 'scripts/build_image.py').is_file() and template.is_file()
                          and properties(template).get('target') == 'android-36'
                          and properties(template).get('hw.cpu.arch') == 'arm64')
            if not variant and metadata.get('project') != 'HyperOS-AVD' and not legacy_os3:
                continue
            results.append({'root': root, 'runtime': runtime, 'version': metadata.get('version', 'legacy'),
                            'variant': variant or 'os3'})
        except (OSError, ValueError, KeyError):
            continue
    return results


def validate_name(name):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name):
        raise RuntimeError('AVD names support 1-64 ASCII letters, digits, dots, underscores and hyphens.')


def choose_port():
    reserved = {entry['runtime'].get('port') for entry in instances()}
    for port in range(5580, 5683, 2):
        if port in reserved:
            continue
        try:
            port_free(port)
            return port
        except RuntimeError:
            continue
    raise RuntimeError('No free emulator port.')


def idle(root, name, port):
    """Protect the instance even if Studio chose a different console port."""
    port_free(port)
    if (root / 'local/instances.json').is_file():
        for saved in json.loads((root / 'local/instances.json').read_text()).values():
            port_free(saved)
    rows = subprocess.check_output(['ps', '-ax', '-o', 'command='], text=True)
    import shlex
    for row in rows.splitlines():
        if 'qemu-system-' not in row and '/emulator/emulator ' not in row:
            continue
        try:
            args = shlex.split(row)
        except ValueError:
            continue
        if ('-avd' in args and args[args.index('-avd') + 1] == name
                or '-sysdir' in args and Path(args[args.index('-sysdir') + 1]).resolve() == (root / 'images').resolve()):
            raise RuntimeError('Close this AVD before changing its files. No emulator was stopped.')


def owner(root, name):
    registry = avd_home() / (name + '.ini')
    if registry.exists() and Path(properties(registry).get('path', '/nonexistent')).expanduser().resolve() != root / 'avd' / (name + '.avd'):
        raise RuntimeError('AVD name belongs to another workspace.')


@contextmanager
def lock(root):
    folder = root / 'local'
    folder.mkdir(parents=True, exist_ok=True)
    with (folder / '.manager.lock').open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another manager is working on this instance.') from None
        yield


def clone(source, target):
    """Use APFS clones where possible; copy across volumes as a fallback."""
    source, target = Path(source), Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(['cp', '-c', '-p', str(source), str(target)], capture_output=True)
    if result.returncode:
        shutil.copy2(source, target)
    return target


def backup(root, name):
    folder = root / 'backups' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    folder.mkdir(parents=True)
    data = root / 'avd' / (name + '.avd')
    if data.is_dir():
        shutil.copytree(data, folder / 'avd', copy_function=clone, symlinks=True)
    hashes = {}
    for path in (folder / 'avd').rglob('*') if (folder / 'avd').exists() else ():
        if path.is_file() and not path.is_symlink() and ('userdata' in path.name or 'encryption' in path.name):
            hashes[path.relative_to(folder).as_posix()] = sha256(path)
    for source in (root / 'local', root / 'Start.command'):
        if source.is_dir():
            shutil.copytree(source, folder / 'local', ignore=shutil.ignore_patterns('.manager.lock'), copy_function=clone)
        elif source.is_file():
            clone(source, folder / source.name)
    registry = avd_home() / (name + '.ini')
    if registry.exists():
        clone(registry, folder / 'registry.ini')
    (folder / 'backup.json').write_text(json.dumps({'name': name, 'files': hashes}, indent=2) + '\n')
    print(tr('数据备份：', 'Data backup: ') + str(folder), flush=True)
    return folder


def data_size(sdk, path):
    return json.loads(subprocess.check_output([str(sdk / 'emulator/qemu-img'), 'info', '--output=json', str(path)], text=True))


def validate_userdata(sdk, avd):
    """Refuse overlays the Emulator would discard for an unexpected backing name."""
    for stem in ('userdata-qemu.img', 'encryptionkey.img'):
        overlay = avd / (stem + '.qcow2')
        if not overlay.is_file():
            continue
        info = data_size(sdk, overlay)
        if info.get('backing-filename') != stem or not (avd / stem).is_file():
            raise RuntimeError('Unexpected userdata/key backing chain; preserved without booting: ' + str(overlay))


def resize(sdk, avd, gib, *, allow_guest=False, backup=None):
    """Grow and verify the effective ext4, even when its virtual disk is already larger."""
    from userdata_resize import resize_userdata
    if allow_guest:
        options = {'allow_guest': True}
        if backup is not None:
            options['backup'] = backup
        return resize_userdata(sdk, avd, gib * 1024**3, **options)
    return resize_userdata(sdk, avd, gib * 1024**3)


def storage_boot_metadata(root, folder):
    """Pin owned local builds without weakening installed-release verification."""
    manifest = root / 'local/installed-release.json'
    if manifest.exists():
        return json.loads(manifest.read_text())
    build_path = root / 'local/build.json'
    build = json.loads(build_path.read_text()) if build_path.is_file() else {}
    variant = {common.OS4_SOURCE: 'os4-official',
               'official-yingtian-ota': 'os4-pad'}.get(build.get('source'))
    version = build.get('hyperos')
    if (not variant or build.get('android_api') != 37 or not isinstance(version, str)
            or not version.startswith(('OS4.', '4.'))):
        raise RuntimeError('Guest storage repair requires a known installed release or local OS4 build.')
    files = {}
    for relative in ('images/system.img', 'images/vendor.img', 'images/kernel-ranchu',
                     'images/ramdisk.img', 'tools/ksud-aarch64-linux-android'):
        path = root / relative
        if not path.is_file():
            raise RuntimeError('Missing local storage repair firmware: ' + relative)
        files[relative] = {'sha256': sha256(path)}
    metadata = {'variant': variant, 'build': build, 'files': files,
                'verification': 'owned-local-build-snapshot'}
    json_write(folder / 'storage-boot-inputs.json', metadata)
    return metadata


def prepare_storage(root, name, port, sdk, gib, folder):
    """Repair legacy encrypted capacity only through the owned decrypted guest."""
    root, sdk, folder = Path(root), Path(sdk), Path(folder)
    validate_name(name)
    owner(root, name)
    idle(root, name, port)
    avd = root / 'avd' / (name + '.avd')
    result = resize(sdk, avd, gib, allow_guest=True, backup=folder)
    if not result.get('guest_required'):
        return result
    manifest = storage_boot_metadata(root, folder)
    if manifest.get('variant') not in ('os3', 'os4-official', 'os4-pad'):
        raise RuntimeError('Guest storage repair requires a known installed release.')
    saved = json.loads((root / 'local/runtime.json').read_text())
    if saved.get('name') != name or saved.get('port') != port:
        raise RuntimeError('Guest storage repair belongs to a different instance.')
    for relative in ('images/system.img', 'images/vendor.img', 'images/kernel-ranchu',
                     'images/ramdisk.img', 'tools/ksud-aarch64-linux-android'):
        expected = manifest.get('files', {}).get(relative, {}).get('sha256')
        if not expected or sha256(root / relative) != expected:
            raise RuntimeError('Storage repair firmware differs from the installed release: ' + relative)
    current = properties(avd / 'config.ini')
    config = {**saved, 'sdk': str(sdk), 'userdata_capacity_token': result['userdata_capacity_token']}
    command = [str(sdk / 'emulator/emulator'), '-avd', name, '-sysdir', str(root / 'images'),
               '-port', str(port), '-no-window', '-no-snapshot-load', '-no-snapshot-save',
               '-accel', 'on', '-gpu', 'host', '-memory', current.get('hw.ramSize', '4096'),
               '-cores', current.get('hw.cpu.ncore', '2'), '-crash-report-mode', 'never']
    from launch import vulkan_features
    from rear_display_config import runtime_options
    command += vulkan_features(manifest.get('build', {}))
    command += runtime_options(manifest.get('build', {}))
    say('正在检查加密用户分区的实际容量；完整备份已保存。',
        'Checking the decrypted userdata filesystem; a full backup is saved.')
    log = folder / 'storage-repair-emulator.log'
    process, validated_guest, record = None, False, None
    try:
        with log.open('wb') as output:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('Storage repair emulator exited; inspect ' + str(log))
            try:
                state = common.adb(config, 'get-state', capture_output=True, text=True, timeout=10)
                if 'unauthorized' in state.stderr:
                    raise RuntimeError('Authorize this AVD computer connection before retrying storage repair.')
                if state.returncode == 0 and state.stdout.strip() == 'device':
                    identity = common.adb(config, 'emu', 'avd', 'name', capture_output=True,
                                          text=True, check=True, timeout=15)
                    if identity.stdout.splitlines()[:1] != [name]:
                        raise RuntimeError('Storage repair connected to a different AVD.')
                    validated_guest = True
                    boot = common.adb(config, 'shell', 'getprop sys.boot_completed',
                                      capture_output=True, text=True, timeout=15)
                    if boot.returncode == 0 and boot.stdout.strip() == '1':
                        break
            except subprocess.TimeoutExpired:
                pass
            time.sleep(2)
        else:
            raise RuntimeError('Storage repair guest did not finish booting; inspect ' + str(log))
        from userdata_guest import verify_and_grow
        record = verify_and_grow(config, gib * 1024**3, backup=folder)
        common.adb(config, 'shell', 'su -W -c sync', check=True, timeout=30)
    finally:
        if process is not None and process.poll() is None:
            if validated_guest:
                try:
                    identity = common.adb(config, 'emu', 'avd', 'name', capture_output=True,
                                          text=True, timeout=15)
                    if identity.returncode == 0 and identity.stdout.splitlines()[:1] == [name]:
                        stopped = common.adb(config, 'emu', 'kill', capture_output=True, timeout=15)
                        if stopped.returncode:
                            process.terminate()
                    else:
                        process.terminate()
                except (OSError, subprocess.SubprocessError):
                    process.terminate()
            else:
                process.terminate()
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                raise RuntimeError('Storage repair guest is still running. Close only ' + name
                                   + ' before restoring its saved backup.') from None
    idle(root, name, port)
    from userdata_resize import publish_guest_capacity
    published = publish_guest_capacity(sdk, avd, gib * 1024**3, record)
    json_write(folder / 'storage-repair.json', record)
    return published


def hardware(ram, storage, cores, variant=None):
    if not 2 <= ram <= 64 or not 6 <= storage <= 1024 or not 1 <= cores <= (os.cpu_count() or 1):
        raise RuntimeError('Use RAM 2-64 GiB, storage 6-1024 GiB, and available host CPU cores.')
    values = {'hw.ramSize': str(round(ram * 1024)), 'hw.cpu.ncore': str(cores), 'disk.dataPartition.size': f'{storage}G'}
    return values


def family(manifest):
    if manifest.get('format') == 3:
        declared = manifest.get('compatibility', {}).get('userdata_family')
        expected = {'os4-official': 'os4-hongkong-api37-ranchu-4k',
                    'os4-pad': setup.PAD_FAMILY}.get(manifest.get('variant'))
        return declared if declared == expected else None
    if manifest.get('format') == 2 and manifest.get('variant') == 'os4-official' and manifest.get('android_api') == 37:
        return 'os4-hongkong-api37-ranchu-4k'
    if manifest.get('format') == 1 and manifest.get('android_api', 36) == 36:
        return 'os3-fuxi-api36-ranchu'
    return None


def compatible(old, new, *, firmware_specific=True):
    if not family(old) or family(old) != family(new):
        raise RuntimeError('Incompatible userdata family. Install a separate AVD for this image.')
    for field in ('images/encryptionkey.img',):
        before = old.get('files', {}).get(field, {}).get('sha256')
        after = new.get('files', {}).get(field, {}).get('sha256')
        if not before or before != after:
            raise RuntimeError('Encryption template changed; automatic data migration is unsafe.')
    if release_order(new['version']) < release_order(old['version']):
        raise RuntimeError('Data-preserving downgrades are not supported. Use a separate AVD.')
    migration = new.get('compatibility', {}).get('module_upgrade_preflight')
    policy = new.get('compatibility', {}).get('upgrade_policy')
    if policy:
        if policy != FORWARD_UPGRADE_POLICY or new.get('variant') != 'os4-official':
            raise RuntimeError('Unknown release upgrade policy; update the installer.')
        if firmware_specific:
            from phone_profile import profile_from_build
            # Firmware authentication belongs to the verified target runtime.
            profile_from_build(old.get('build', {}))
            profile_from_build(new.get('build', {}))
    if migration:
        if migration != MODULE_UPGRADE_PREFLIGHT:
            raise RuntimeError('Unknown release module migration; update the installer.')
        allowed = new['compatibility'].get('upgrade_from', [])
        if not policy and old['version'] != new['version'] and old['version'] not in allowed:
            raise RuntimeError('This source release has not been validated for this data-preserving upgrade.')


def firmware_change(old, new):
    return (new.get('compatibility', {}).get('module_upgrade_preflight') == MODULE_UPGRADE_PREFLIGHT
            and old.get('hyperos') != new.get('hyperos'))


def upgrade_transaction(root, folder, name, port):
    """Record rollback paths before staging may write retained userdata."""
    paths, real = {}, {}
    for key in ('images', 'tools', 'config'):
        path = root / key
        real[key] = path.exists() and not path.is_symlink()
        paths[key] = (str(root / 'versions' / ('legacy-' + folder.name) / key)
                      if real[key] else str(path.resolve()) if path.exists() else None)
    transaction = {'name': name, 'port': port, 'paths': paths, 'real': real, 'backup': str(folder)}
    json_write(folder / 'transaction.json', transaction)
    json_write(root / 'local/upgrade-pending.json', transaction)
    return transaction


def migration_guard(script, incremental):
    """Keep old module code usable on rollback, but inactive on new firmware."""
    if not script.startswith('#!/system/bin/sh\n') or '\x00' in script:
        raise RuntimeError('Unexpected owned module startup script.')
    gate = ('# HyperOS-AVD firmware upgrade guard; original payload retained.\n'
            '[ "$(getprop ro.mi.os.version.incremental)" = '
            + shlex.quote(incremental) + ' ] || exit 0\n')
    if script.startswith('#!/system/bin/sh\n' + gate):
        return script
    return '#!/system/bin/sh\n' + gate + script[len('#!/system/bin/sh\n'):]


def validate_owned_module(module_id, prop, manifest, system_prop='', has_system=False):
    """Validate only the known project modules; unrelated modules are untouched."""
    values = dict(line.split('=', 1) for line in prop.splitlines() if '=' in line)
    if values.get('id') != module_id or values.get('author') != 'HyperOS-AVD' or has_system:
        raise RuntimeError('Refused unknown module ownership or automatic mount tree: ' + module_id)
    revision = manifest.get('revision')
    if type(revision) is not int:
        raise RuntimeError('Unknown owned module revision: ' + module_id)
    if module_id == 'hyperos_avd_navigation':
        valid = (revision in range(2, 12) and manifest.get('property') == 'ro.miui.product.home'
                 and manifest.get('value') == 'com.miui.home'
                 and manifest.get('component') == 'com.miui.home/com.miui.home.recents.RecentsActivity')
        allowed = {'ro.miui.product.home=com.miui.home', 'persist.miui.home_sf_anim=true',
                   'persist.miui.home_sf_anim=false'}
        if set(system_prop.splitlines()) - allowed:
            valid = False
    elif module_id == 'hyperos_avd_flutter_render':
        from phone_profile import LEGACY_PINS
        from patch_flutter import PROFILES
        native = manifest.get('system', {})
        valid = (revision in (6, 7, 8) and isinstance(manifest.get('packages'), dict)
                 and set(manifest['packages']) <= {'com.miui.home', 'com.miui.weather2'}
                 and native.get('target') == '/system_ext/lib64/libhyper_os_flutter.so'
                 and native.get('before') == LEGACY_PINS['flutter']
                 and native.get('after') == PROFILES[LEGACY_PINS['flutter']]['output'])
        if system_prop.strip():
            valid = False
    elif module_id == 'hyperos_avd_xiaomi_camera':
        from phone_profile import LEGACY_PINS
        valid = (revision in (1, 2) and manifest.get('experimental') is True
                 and manifest.get('apk_sha256') == LEGACY_PINS['camera_apk']
                 and manifest.get('runtime_sha256') == LEGACY_PINS['android_runtime']
                 and len(manifest.get('targets', [])) == 2
                 and {item.get('target') for item in manifest.get('targets', [])} == {
                     '/vendor/bin/hw/android.hardware.camera.provider@2.7-service-google',
                     '/vendor/lib64/libgooglecamerahwl_impl.so'})
        if system_prop.strip():
            valid = False
    else:
        valid = False
    if not valid:
        raise RuntimeError('Unknown owned module schema: ' + module_id)


def audit_legacy_startup(config, module):
    """Reject unguarded early controls when skipping frozen source generations."""
    script = 'set -e\n'
    for directory in (Path(module), *Path(module).parents):
        path = shlex.quote(str(directory))
        script += f'test -d {path}\ntest ! -L {path}\n'
    for name in ('post-mount.sh', 'boot-completed.sh', 'sepolicy.rule', 'zygisk', 'system',
                 'initrc', 'uninstall.sh',
                 'post-fs-data.sh.next', 'service.sh.next'):
        path = shlex.quote(module + '/' + name)
        script += f'test ! -e {path}\ntest ! -L {path}\n'
    for name in ('module.prop', 'manifest.json', 'post-fs-data.sh', 'service.sh', 'system.prop'):
        path = shlex.quote(module + '/' + name)
        script += (f'test ! -L {path}\n'
                   f'if [ -e {path} ]; then test -f {path}; test "$(stat -c %h {path})" = 1; fi\n')
    try:
        common.adb(config, 'shell', 'su -W -c ' + shlex.quote(script),
                   capture_output=True, text=True, check=True, timeout=30)
    except subprocess.CalledProcessError as error:
        raise RuntimeError('Unknown or aliased historical startup controls are preserved: ' + module) from error


def guarded_modules(config, directory, incremental, target_hyperos=None, *, strict=False):
    """Gate stale early mounts without removing manifests, serials or flags."""
    def guest(command):
        return common.adb(config, 'shell', 'su -W -c ' + shlex.quote('set -e\n' + command),
                          capture_output=True, text=True, check=True, timeout=30).stdout.strip()
    staged, receipt = [], []
    for module_id in ('hyperos_avd_navigation', 'hyperos_avd_flutter_render', 'hyperos_avd_xiaomi_camera'):
        module = '/data/adb/modules/' + module_id
        if guest(f'if [ -d {module} ]; then echo yes; fi') != 'yes':
            continue
        if strict:
            audit_legacy_startup(config, module)
        prop = guest(f'cat {module}/module.prop')
        saved = json.loads(guest(f'cat {module}/manifest.json'))
        auto = guest(f'if [ -e {module}/system ]; then echo yes; fi') == 'yes'
        properties = guest(f'if [ -f {module}/system.prop ]; then cat {module}/system.prop; fi')
        validate_owned_module(module_id, prop, saved, properties, auto)
        if (module_id == 'hyperos_avd_xiaomi_camera' and saved['revision'] == 1
                and target_hyperos not in (None, '4.0.17.0.XFRCNXM')):
            raise RuntimeError('XiaomiCamera revision 1 cannot migrate to OS' + target_hyperos + '. '
                               'Recover or start the existing r2 firmware and update its camera '
                               'bridge to revision 2 before retrying Upgrade. '
                               'Firmware and module disable/remove flags were not changed.')
        flags = guest(f'for flag in disable remove; do [ ! -e {module}/$flag ] || echo "$flag"; done')
        scripts = []
        for name in ('post-fs-data.sh', 'service.sh'):
            original = common.adb(config, 'exec-out', 'su -W -c ' + shlex.quote(f'cat {module}/{name}'),
                                  capture_output=True, text=True, check=True, timeout=30).stdout
            guarded = migration_guard(original, incremental)
            local = directory / (module_id + '-' + name)
            local.write_text(guarded)
            staged.append((module, name, local, hashlib.sha256(guarded.encode()).hexdigest()))
            scripts.append({'name': name, 'before': hashlib.sha256(original.encode()).hexdigest(),
                            'guarded': hashlib.sha256(guarded.encode()).hexdigest()})
        receipt.append({'id': module_id, 'revision': saved['revision'], 'flags': flags.splitlines(),
                        'manifest_sha256': hashlib.sha256(json.dumps(saved, sort_keys=True).encode()).hexdigest(),
                        'scripts': scripts})
    # Validate every module before replacing any of their startup scripts.
    for module, name, local, checksum in staged:
        remote = '/data/local/tmp/' + local.name
        common.adb(config, 'push', str(local), remote, check=True, capture_output=True, timeout=30)
        guest(f'cp {remote} {module}/{name}.next\nchmod 755 {module}/{name}.next\n'
              f'sh -n {module}/{name}.next\n'
              f'test "$(sha256sum {module}/{name}.next | cut -d " " -f 1)" = {checksum}\n'
              f'mv {module}/{name}.next {module}/{name}\nrm {remote}')
    for saved in receipt:
        module = '/data/adb/modules/' + saved['id']
        actual = json.loads(guest(f'cat {module}/manifest.json'))
        checksum = hashlib.sha256(json.dumps(actual, sort_keys=True).encode()).hexdigest()
        flags = guest(f'for flag in disable remove; do [ ! -e {module}/$flag ] || echo "$flag"; done')
        if checksum != saved['manifest_sha256'] or flags.splitlines() != saved['flags']:
            raise RuntimeError('Owned module metadata or user flags changed during migration: ' + saved['id'])
    return receipt


def validate_upgrade_guest(config, incremental):
    """Reject recovery/safe-mode boots before snapshotting module choices."""
    probe = common.adb(config, 'shell', 'su -W -c ' + shlex.quote(
        'id; getenforce; getprop ro.mi.os.version.incremental'),
        capture_output=True, text=True, check=True, timeout=30).stdout.splitlines()
    if (not probe or 'uid=0(' not in probe[0] or probe[1:] != ['Enforcing', incremental]):
        raise RuntimeError('Previous firmware root, SELinux or version does not match the release.')
    for key in ('persist.sys.safemode', 'ro.sys.safemode'):
        value = common.adb(config, 'shell', 'getprop', key, capture_output=True, text=True,
                           check=True, timeout=15).stdout.strip()
        if value not in ('', '0'):
            raise RuntimeError('Previous firmware is in safe mode; refusing to adopt forced module disable flags.')


def prepare_module_upgrade(root, old, new, name, port, sdk, folder):
    """Boot only the old registered guest to neutralize stale owned early code."""
    from phone_profile import profile_from_build
    old_build = old.get('build', {})
    profile = profile_from_build(old_build)
    if (old.get('variant') != 'os4-official' or profile['hyperos'] != '4.0.17.0.XFRCNXM'
            or new.get('hyperos') != '4.0.18.0.XFRCNXM'):
        raise RuntimeError('Unsupported firmware pair for owned module migration.')
    _stage_module_upgrade(root, old, new, name, port, sdk, folder, profile, legacy=True)


def firmware_upgrade_profiles(old, new):
    """Authenticate a forward source change independently of release revisions."""
    from phone_profile import profile_from_build
    if any(value.get('variant') != 'os4-official' for value in (old, new)):
        raise RuntimeError('Unsupported firmware family for owned module migration.')
    selected = tuple(profile_from_build(value.get('build', {})) for value in (old, new))
    if any(value.get('hyperos') != profile['hyperos'] for value, profile in zip((old, new), selected)):
        raise RuntimeError('Firmware manifest and source profile disagree.')
    order = lambda profile: tuple(int(part) for part in profile['hyperos'].split('.')[:4])
    if order(selected[0]) >= order(selected[1]):
        raise RuntimeError('Unsupported firmware pair: only registered forward sources may migrate.')
    return selected


def prepare_firmware_upgrade(root, old, new, name, port, sdk, folder):
    """Retain the frozen bootstrap; audit adaptive owners for later source changes."""
    before, after = firmware_upgrade_profiles(old, new)
    if (before['hyperos'], after['hyperos']) == ('4.0.17.0.XFRCNXM', '4.0.18.0.XFRCNXM'):
        return prepare_module_upgrade(root, old, new, name, port, sdk, folder)
    return _stage_module_upgrade(root, old, new, name, port, sdk, folder, before, legacy=False)


def audit_module_inventory(config, directory, manifest):
    """Reject added early entry points while retaining mutable module choices."""
    from apply_flutter_fix import root as guest
    allowed = {name.split('/')[0] for name in manifest['files_sha256']}
    allowed |= {'manifest.json', 'SHA256SUMS', 'disable', 'remove', 'cache', 'state',
                'features.disabled', 'runtime.log', 'runtime.log.next'}
    if any(not re.fullmatch('[A-Za-z0-9_.-]+', name) for name in allowed):
        raise RuntimeError('Invalid firmware staging module inventory.')
    # These exact leases are produced by an already authenticated Core runtime,
    # not arbitrary added module controls. Apps has no corresponding root lease.
    core = manifest.get('id') == 'hyperos_avd_native_compat'
    script = f'''directory={shlex.quote(directory)}
inventory_fail() {{ printf '%s\\n' "Unreviewed module content preserved: $1" >&2; exit 1; }}
inventory_regular() {{
    [ ! -L "$1" ] && [ -f "$1" ] &&
        [ "$(stat -c %h "$1")" = 1 ] && [ "$(stat -c %u:%g "$1")" = 0:0 ] || inventory_fail "$1 (type or ownership)"
}}
'''
    if core:
        script += '''inventory_core_lock() {
    local path=$1 field value
    case "${path##*/}" in
        service.lock.guard)
            inventory_regular "$path"
            [ "$(stat -c %s "$path")" = 0 ] || inventory_fail "$path (nonempty guard)"
            return ;;
    esac
    [ ! -L "$path" ] && [ -d "$path" ] &&
        [ "$(stat -c %u:%g "$path")" = 0:0 ] || inventory_fail "$path (type or ownership)"
    for field in "$path"/* "$path"/.[!.]* "$path"/..?*; do
        [ -e "$field" ] || [ -L "$field" ] || continue
        case "${field##*/}" in pid|boot) ;; *) inventory_fail "$field (unknown lease field)" ;; esac
        inventory_regular "$field"
        value=$(cat "$field")
        case "${field##*/}" in
            pid)
                case "$value" in ''|*[!0-9]*) inventory_fail "$field (invalid PID)" ;; esac
                [ "${#value}" -le 10 ] && [ "$value" -gt 0 ] &&
                    [ "$(stat -c %s "$field")" = "$((${#value} + 1))" ] || inventory_fail "$field (invalid PID)" ;;
            boot)
                printf '%s\\n' "$value" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' &&
                    [ "$(stat -c %s "$field")" = 37 ] || inventory_fail "$field (invalid boot identity)" ;;
        esac
    done
}
'''
    leases = 'service.lock|service.lock.guard) inventory_core_lock "$entry" ;; ' if core else ''
    script += f'''for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    case "${{entry##*/}}" in {leases}{'|'.join(sorted(allowed))}) ;; *) inventory_fail "$entry (unknown top-level entry)" ;; esac
done'''
    guest(config, script)


def audit_firmware_modules(config, old, workspace, *, guarded_ids=()):
    """Authenticate existing controls without invalidating their migration receipts."""
    from apply_flutter_fix import root as guest
    import apply_native_compat as core
    import apply_app_compat as apps
    import app_compat_migration as legacy_apps
    from app_compat_catalog import catalog_files, previous_manifests
    from core_legacy import ROLES, inspect_legacy
    from native_module_history import checksum_for
    from package_native_module import module_files

    # A pending KSU owner can activate before the new host context is supplied.
    # Keep it intact and reject the switch instead of adopting or cancelling it.
    identifiers = sorted(set(ROLES) | set(legacy_apps.MODULES) | {core.MODULE_ID, apps.MODULE_ID})
    for identifier in identifiers:
        pending = '/data/adb/modules_update/' + identifier
        if guest(config, f'if [ -e {pending} ] || [ -L {pending} ]; then echo pending; fi'):
            raise RuntimeError('Firmware migration preserves a pending KernelSU owner: ' + identifier)

    receipt = []
    native = core._module(config, core.MODULE)
    if native is not None:
        if not native['flags']:
            saved = core._manifest(config, native)
            current = module_files()
            expected = json.loads(current['manifest.json'])
            checksum = (hashlib.sha256(current['SHA256SUMS']).hexdigest()
                        if saved == expected else checksum_for(saved))
            if checksum is None:
                raise RuntimeError('Unknown Core controls are preserved; firmware was not switched.')
            core._verify_assets(config, core.MODULE, checksum)
            audit_module_inventory(config, core.MODULE, saved)
        receipt.append({'id': core.MODULE_ID, 'flags': native['flags'], 'mode': 'content-adaptive'})

    catalog = apps.recipes()
    current = json.loads(catalog_files(catalog)['manifest.json'])
    reviewed = [current, *previous_manifests()]
    app = apps._inspect(config, '/data/adb/modules/' + apps.MODULE_ID, apps.MODULE_ID,
                        allowed_revisions={str(value['revision']) for value in reviewed})
    if app is not None:
        if not app['flags']:
            for expected in reviewed:
                try:
                    apps._saved(config, app, expected)
                except apps.CatalogMismatch:
                    continue
                audit_module_inventory(config, app['directory'], expected)
                break
            else:
                raise RuntimeError('Unknown Apps controls are preserved; firmware was not switched.')
        receipt.append({'id': apps.MODULE_ID, 'flags': app['flags'], 'mode': 'content-adaptive'})

    # Exact frozen legacy owners already gate by source firmware or native/APK
    # content. Leave their hooks unchanged so Core/Apps can import their choices
    # and retire the complete directories after normal activation.
    build = old.get('build', {})
    context = {'boot_services': build.get('boot_service_fix'),
               'rear': build.get('rear_display_wake_fix')}
    for item in inspect_legacy(guest, config, context):
        if item['id'] in guarded_ids:
            continue
        if item['status'] != 'audited' and item['reason'] != 'legacy-lifecycle-choice':
            raise RuntimeError('Unknown legacy Core owner is preserved: ' + item['id'])
        receipt.append({'id': item['id'], 'mode': item['status'], 'reason': item['reason']})
    planned = legacy_apps.plan(config, catalog=catalog, workspace=workspace)
    for item in planned['preserved']:
        if item['module'] in guarded_ids:
            continue
        if item['reason'] in ('pending', 'unknown-or-custom'):
            raise RuntimeError('Unknown legacy Apps owner is preserved: ' + item['module'])
    receipt += [{'id': item['id'], 'flags': item['flags'], 'mode': 'audited-legacy'}
                for item in planned['modules'] if item['id'] not in guarded_ids]
    receipt += [{'id': item['module'], 'flags': item['reason'], 'mode': 'preserved'}
                for item in planned['preserved'] if item['module'] not in guarded_ids]
    return receipt


def _stage_module_upgrade(root, old, new, name, port, sdk, folder, profile, *, legacy):
    """Run the verified old image only inside the existing backup transaction."""
    # Never execute modified old firmware/tool inputs as an upgrade helper.
    required = {'images/system.img', 'images/kernel-ranchu', 'images/ramdisk.img',
                'tools/ksud-aarch64-linux-android'}
    if not legacy:
        required.update(path for path in old.get('files', {}) if path.startswith('images/'))
    for relative in sorted(required):
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts:
            raise RuntimeError('Invalid installed staging input path: ' + relative)
        if not legacy and (not (root / relative).is_file() or (root / relative).is_symlink()):
            raise RuntimeError('Aliased installed staging input is preserved: ' + relative)
        expected = old.get('files', {}).get(relative, {}).get('sha256')
        if not expected or sha256(root / relative) != expected:
            raise RuntimeError('Installed staging input differs from its release: ' + relative)
    idle(root, name, port)
    config = {'sdk': str(sdk), 'name': name, 'port': port}
    current = properties(root / 'avd' / (name + '.avd') / 'config.ini')
    command = [str(sdk / 'emulator/emulator'), '-avd', name, '-sysdir', str(root / 'images'),
               '-port', str(port), '-no-window', '-no-snapshot-load', '-no-snapshot-save',
               '-accel', 'on', '-gpu', 'host', '-memory', current.get('hw.ramSize', '6144'),
               '-cores', current.get('hw.cpu.ncore', '4'), '-crash-report-mode', 'never']
    if not legacy:
        from launch import vulkan_features
        from rear_display_config import runtime_options
        command += vulkan_features(old.get('build', {}))
        command += runtime_options(old.get('build', {}))
    say('正在启动升级前镜像，隔离旧补丁；完整用户数据备份已保存。',
        'Starting the previous firmware to gate old patches; full userdata backup is saved.')
    log = folder / 'module-upgrade-emulator.log'
    process = None
    validated_guest = False
    try:
        with log.open('wb') as output:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('Previous firmware staging emulator exited; inspect ' + str(log))
            try:
                state = common.adb(config, 'get-state', capture_output=True, text=True, timeout=10)
            except subprocess.TimeoutExpired:
                continue
            if 'unauthorized' in state.stderr:
                raise RuntimeError('Authorize this AVD computer connection, then retry the upgrade. Firmware was not switched.')
            if state.returncode == 0 and state.stdout.strip() == 'device':
                break
            time.sleep(2)
        else:
            raise RuntimeError('Previous firmware ADB did not become ready; inspect ' + str(log))
        avd = common.adb(config, 'emu', 'avd', 'name', capture_output=True, text=True, check=True, timeout=15)
        if avd.stdout.splitlines()[:1] != [name]:
            raise RuntimeError('Upgrade staging connected to a different AVD.')
        validated_guest = True
        validate_upgrade_guest(config, profile['incremental'])
        guarded = []
        if legacy or profile['hyperos'] == '4.0.17.0.XFRCNXM':
            staging = folder / 'module-guards'
            staging.mkdir()
            guarded = guarded_modules(config, staging, profile['incremental'], new['hyperos'],
                                      **({'strict': True} if not legacy else {}))
        if legacy:
            receipt = guarded
        else:
            receipt = audit_firmware_modules(config, old, root,
                **({'guarded_ids': {item['id'] for item in guarded}} if guarded else {}))
        # Retained users may have changed all three awake settings. Declare
        # them seeded before the new runtime boots; never rewrite their values.
        from os4_defaults import AWAKE_STAMP
        common.adb(config, 'shell', 'su -W -c ' + shlex.quote(
            f'touch {AWAKE_STAMP}\ntest -f {AWAKE_STAMP}'), check=True, timeout=30)
        json_write(folder / 'module-upgrade.json', {'schema': 1, 'name': name, 'port': port,
            'from': old['version'], 'to': new['version'],
            **({'guarded_modules': receipt} if legacy else {'retained_modules': receipt,
                **({'guarded_modules': guarded} if guarded else {})}),
            'preserved_defaults': {'awake_stamp': AWAKE_STAMP}})
        common.adb(config, 'shell', 'su -W -c sync', check=True, timeout=30)
    finally:
        if process is not None and process.poll() is None:
            # Only a validated guest receives a console stop; otherwise signal
            # our own child PID rather than risking a concurrent port claimant.
            if validated_guest:
                common.adb(config, 'emu', 'kill', capture_output=True, timeout=15)
            else:
                process.terminate()
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                raise RuntimeError('Upgrade staging AVD is still running. Close only ' + name
                                   + ' before using Recover; no firmware was switched.') from None
    idle(root, name, port)


def json_write(path, data):
    temporary = path.with_name(path.name + '.next')
    temporary.write_text(json.dumps(data, indent=2) + '\n')
    temporary.replace(path)


@contextmanager
def scope(root):
    previous = setup.ROOT, common.ROOT
    setup.ROOT = common.ROOT = root
    try:
        yield
    finally:
        setup.ROOT, common.ROOT = previous


def point(root, target):
    for name in ('images', 'tools', 'config'):
        path = root / name
        if path.exists() and not path.is_symlink():
            legacy = root / 'versions' / ('legacy-' + str(time.time_ns()))
            legacy.mkdir(parents=True)
            path.rename(legacy / name)
        temporary = path.with_name(name + '.next')
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(os.path.relpath(target / name, root), target_is_directory=True)
        temporary.replace(path)


def wrapper(root):
    file = root / 'Start.command'
    file.write_text('''#!/bin/zsh
cd "${0:A:h}" || exit 1
exec python3 - "$PWD" <<'PYTHON'
import json, os, pathlib, subprocess, sys, tempfile
root = pathlib.Path(sys.argv[1])
state = json.loads((root / 'local/manager.json').read_text())
env = dict(os.environ, HYPEROS_AVD_WORKSPACE=str(root))
for name in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP'):
    env.pop(name, None)
with tempfile.TemporaryDirectory(prefix='python-launch-', dir=root / 'local') as cache:
    env['PYTHONPYCACHEPREFIX'] = cache
    result = subprocess.call([sys.executable, '-B', str(root / state['runtime'] / 'scripts/launch.py')], env=env)
raise SystemExit(result)
PYTHON
''')
    file.chmod(0o755)


def restore(root, folder):
    """Recover a failed switch or roll back an upgrade including encrypted data."""
    root, folder = root.resolve(), folder.resolve()
    if root / 'backups' not in folder.parents:
        raise RuntimeError('Backup must belong to this instance.')
    saved = json.loads((folder / 'transaction.json').read_text())
    name = saved['name']
    current = root / 'local/runtime.json'
    if current.exists() and json.loads(current.read_text()).get('name') != name:
        raise RuntimeError('Backup belongs to another AVD.')
    metadata = json.loads((folder / 'backup.json').read_text())
    for relative, checksum in metadata['files'].items():
        if Path(relative).is_absolute() or '..' in Path(relative).parts or sha256(folder / relative) != checksum:
            raise RuntimeError('Backup integrity check failed.')
    for key, value in saved['paths'].items():
        path = root / key
        if path.is_symlink():
            path.unlink()
        elif path.exists():
            # A directory was not moved yet when the failure occurred.
            if value == str(path) or saved['real'].get(key) and not Path(value).exists():
                continue
            raise RuntimeError('Rollback encountered an unexpected real directory.')
        if value:
            origin = Path(value)
            if saved['real'].get(key):
                if origin.exists():
                    origin.rename(path)
            else:
                path.symlink_to(os.path.relpath(origin, root), target_is_directory=True)
    data = root / 'avd' / (name + '.avd')
    if (folder / 'avd').exists():
        if data.exists():
            data.rename(root / 'backups' / ('failed-data-' + str(time.time_ns())))
        shutil.copytree(folder / 'avd', data, copy_function=clone, symlinks=True)
    elif data.exists() and saved.get('fresh_userdata') is True:
        # Retain even partially initialized images for inspection, while
        # allowing a failed clean install to be retried without adopting them.
        data.rename(root / 'backups' / ('failed-data-' + str(time.time_ns())))
    elif data.exists() and not any(data.glob('*userdata*')) and not any(data.glob('*encryptionkey*')):
        # A failed fresh configuration created only generated files, not user data.
        shutil.rmtree(data)
    if (folder / 'local').is_dir():
        for path in (root / 'local').iterdir():
            if path.name != '.manager.lock':
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
        shutil.copytree(folder / 'local', root / 'local', dirs_exist_ok=True, copy_function=clone)
    registry = avd_home() / (name + '.ini')
    if (folder / 'registry.ini').exists():
        clone(folder / 'registry.ini', registry)
    elif registry.exists():
        registry.unlink()
    if (folder / 'Start.command').exists():
        clone(folder / 'Start.command', root / 'Start.command')
    else:
        (root / 'Start.command').unlink(missing_ok=True)
    (root / 'local/upgrade-pending.json').unlink(missing_ok=True)
    say('已恢复升级前的镜像、配置和用户数据。', 'Previous firmware, configuration and userdata restored.')


def switch(root, target, manifest, name, port, sdk, options, folder, camera=False):
    """Persist recovery instructions before the first active-path change."""
    transaction = upgrade_transaction(root, folder, name, port)
    paths, real = transaction['paths'], transaction['real']
    try:
        for key in paths:
            path = root / key
            if real[key]:
                destination = Path(paths[key])
                destination.parent.mkdir(parents=True, exist_ok=True)
                path.rename(destination)
        point(root, target)
        json_write(root / 'local/installed-release.json', manifest)
        if 'build' in manifest:
            json_write(root / 'local/build.json', manifest['build'])
        json_write(root / 'local/runtime.json', {'sdk': str(sdk), 'name': name, 'port': port, 'hardware': options, 'camera_bridge': camera})
        with scope(root):
            setup.configure(sdk, name, port)
        data = root / 'avd' / (name + '.avd')
        capacity = int(options['disk.dataPartition.size'][:-1])
        resize(sdk, data, capacity)
        userdata = data / 'userdata-qemu.img'
        if not userdata.exists():
            # Frozen release runtimes may grow only the virtual disk. Prepare
            # its real ext4 before handing control to any bundled launcher.
            for path in (data / 'userdata-qemu.img.qcow2', data / '.userdata-resize-pending'):
                if path.exists() or path.is_symlink():
                    raise RuntimeError('Refused to initialize userdata over an orphan overlay or pending resize.')
            transaction['fresh_userdata'] = True
            json_write(folder / 'transaction.json', transaction)
            json_write(root / 'local/upgrade-pending.json', transaction)
            clone(root / 'images/userdata.img', userdata)
            resize(sdk, data, capacity)
        runtime = target / 'runtime' if (target / 'runtime/scripts/launch.py').is_file() else REPO_ROOT
        json_write(root / 'local/manager.json', {'schema': 1, 'version': manifest['version'],
            'runtime': os.path.relpath(runtime, root), 'backup': str(folder)})
        wrapper(root)
        (root / 'local/upgrade-pending.json').unlink()
    except BaseException:
        restore(root, folder)
        raise


def install(root, manifest_path, name, port, sdk, options, camera=False):
    from bundle_runtime import has_protocol
    manifest, _ = setup.read_install_manifest(str(manifest_path))
    if has_protocol(manifest):
        return install_via_runtime(root, manifest_path, manifest, name, port, sdk, options, camera)
    return install_transaction(root, manifest_path, name, port, sdk, options, camera)


def install_via_runtime(root, manifest_path, manifest, name, port, sdk, options, camera=False):
    """Stage all bytes before invoking the protocol's single fixed entrypoint."""
    from bundle_runtime import ENTRYPOINT, INSTALL_PROTOCOL, manifest_digest, validate_envelope, verify_staged
    validate_envelope(manifest)
    manifest_path = Path(manifest_path)
    root = Path(root).expanduser().resolve()
    validate_name(name)
    if type(port) is not int or port % 2 or not 5556 <= port <= 5682:
        raise RuntimeError('Use a free even emulator console port between 5556 and 5682.')
    hardware(int(options['hw.ramSize']) / 1024,
             int(options['disk.dataPartition.size'][:-1]), int(options['hw.cpu.ncore']))
    if version_key(manifest['compatibility']['minimum_installer']) > version_key(VERSION):
        raise RuntimeError('This release needs a newer installer; download the latest stable Installer Release.')
    from userdata_resize import check_dependencies
    check_dependencies(sdk)
    owner(root, name)
    idle(root, name, port)
    target = root / 'versions' / manifest['version']
    with lock(root):
        if (root / 'local/upgrade-pending.json').exists():
            raise RuntimeError('An interrupted upgrade needs recovery first: use the Recover menu.')
        saved = root / 'local/runtime.json'
        if saved.exists():
            previous = json.loads(saved.read_text())
            if previous.get('name') != name or previous.get('port') != port:
                raise RuntimeError('Upgrade must retain the instance name and console port.')
        data = root / 'avd' / (name + '.avd')
        if data.exists():
            old_path = root / 'local/installed-release.json'
            if not old_path.is_file():
                raise RuntimeError('Existing userdata has no release manifest; migration refused.')
            validate_userdata(sdk, data)
            compatible(json.loads(old_path.read_text()), manifest, firmware_specific=False)
            wanted = int(options['disk.dataPartition.size'][:-1]) * 1024**3
            if any(data_size(sdk, p)['virtual-size'] > wanted for p in data.glob('userdata-qemu.img*')
                   if p.name in ('userdata-qemu.img', 'userdata-qemu.img.qcow2')):
                raise RuntimeError('Storage cannot shrink during an upgrade.')
        if (root / 'versions').is_symlink() or target.is_symlink():
            raise RuntimeError('Bundle staging directory must not be a symlink.')
        if not (target / 'local/installed-release.json').is_file():
            if target.exists():
                raise RuntimeError('An incomplete version directory exists; inspect it before retrying: ' + str(target))
            from delta_install import select_delta, stage_delta
            from bundle_runtime import delta_base
            delta_only = delta_base(manifest) is not None
            if delta_only:
                # Already holding the instance lock; stage_base never activates
                # a dependency or obtains the lock recursively.
                from delta_install import stage_base
                base = delta_base(manifest)
                base_target = root / 'versions' / base['version']
                base_path = local_base_bundle(manifest_path, base)
                if not base_target.exists() and base_path is None:
                    raise RuntimeError('This delta-only release requires the full base bundle ' + base['version']
                                       + '. Place its release folder beside the patch folder, or install online.')
                stage_base(root, base_path or manifest_path, base)
            selection = select_delta(root, manifest)
            if selection is not None and all((manifest_path.parent / part['name']).is_file()
                                             for part in selection[0]['parts']):
                descriptor, source, old = selection
                try:
                    stage_delta(root, target, manifest_path, manifest, descriptor, source, old)
                except (OSError, RuntimeError, ValueError, EOFError, tarfile.TarError, http.client.HTTPException):
                    if delta_only:
                        raise
                    if not all((manifest_path.parent / part['name']).is_file() for part in manifest['parts']):
                        raise RuntimeError('Incremental bundle verification failed. Retry the online upgrade '
                                           'or provide the full bundle; the installed version was preserved.') from None
                    say('增量校验失败，使用本地完整包。', 'Incremental verification failed; using the local full bundle.')
            if not target.exists():
                if delta_only:
                    raise RuntimeError('Missing incremental archive parts; download the complete patch release.')
                total = sum(item['size'] for item in manifest['files'].values())
                if shutil.disk_usage(root).free < total + sum(item['size'] for item in manifest['parts']) + 2 * 1024**3:
                    raise RuntimeError('Insufficient free storage for staging and archive validation.')
                target.mkdir(parents=True)
                with scope(target):
                    setup.stage_bundle(str(manifest_path))
        verify_staged(target, manifest)
    # The child obtains the normal instance lock and repeats ownership/idle
    # checks. No inherited lock or environment flag can bypass its transaction.
    with tempfile.TemporaryDirectory(prefix='bundle-install-', dir=root / 'local') as temporary:
        temporary = Path(temporary)
        request, report = temporary / 'request.json', temporary / 'report.json'
        json_write(request, {'schema': 1, 'protocol': INSTALL_PROTOCOL, 'root': str(root),
            'target': str(target), 'name': name, 'port': port, 'sdk': str(sdk),
            'options': options, 'camera': camera, 'manifest_sha256': manifest_digest(manifest)})
        env = os.environ.copy()
        for key in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP'):
            env.pop(key, None)
        env['PYTHONPYCACHEPREFIX'] = str(temporary / 'bytecode')
        env['HYPEROS_AVD_WORKSPACE'] = str(root)
        verify_staged(target, manifest)
        subprocess.run([sys.executable, '-B', str(target / ENTRYPOINT), '--request', str(request),
                        '--report', str(report)], cwd=temporary, env=env, check=True)
        if report.is_symlink() or not report.is_file():
            raise RuntimeError('Verified runtime did not return an installation report.')
        result = json.loads(report.read_text())
        if (not isinstance(result, dict) or set(result) != {'schema', 'protocol', 'backup'}
                or type(result['schema']) is not int or result['schema'] != 1
                or result['protocol'] != INSTALL_PROTOCOL or not isinstance(result['backup'], str)):
            raise RuntimeError('Invalid verified runtime installation report.')
        folder = Path(result['backup'])
        if folder.is_symlink() or folder.parent != root / 'backups' or not folder.is_dir():
            raise RuntimeError('Invalid verified runtime backup location.')
        return folder


def install_transaction(root, manifest_path, name, port, sdk, options, camera=False):
    root = Path(root).expanduser().resolve()
    validate_name(name)
    manifest, _ = setup.read_manifest(str(manifest_path))
    hardware(int(options['hw.ramSize']) / 1024,
             int(options['disk.dataPartition.size'][:-1]), int(options['hw.cpu.ncore']))
    minimum = manifest.get('compatibility', {}).get('minimum_installer', '0.2.1')
    if version_key(minimum) > version_key(VERSION):
        raise RuntimeError('This release needs a newer installer; download the latest stable Installer Release.')
    from userdata_resize import check_dependencies
    check_dependencies(sdk)
    owner(root, name)
    if (root / 'local/runtime.json').exists():
        saved_runtime = json.loads((root / 'local/runtime.json').read_text())
        if saved_runtime.get('name') != name or saved_runtime.get('port') != port:
            raise RuntimeError('Upgrade must retain the instance name and console port.')
    idle(root, name, port)
    with lock(root):
        if (root / 'local/upgrade-pending.json').exists():
            raise RuntimeError('An interrupted upgrade needs recovery first: use the Recover menu.')
        data = root / 'avd' / (name + '.avd')
        old_path = root / 'local/installed-release.json'
        old = None
        if data.exists():
            if not old_path.exists():
                raise RuntimeError('Existing userdata has no release manifest; migration refused.')
            validate_userdata(sdk, data)
            old = json.loads(old_path.read_text())
            compatible(old, manifest)
            if (root / 'local/runtime.json').exists() and json.loads((root / 'local/runtime.json').read_text())['name'] != name:
                raise RuntimeError('This workspace belongs to a different instance.')
            wanted = int(options['disk.dataPartition.size'][:-1]) * 1024**3
            if any(data_size(sdk, p)['virtual-size'] > wanted for p in data.glob('userdata-qemu.img*') if p.name in ('userdata-qemu.img', 'userdata-qemu.img.qcow2')):
                raise RuntimeError('Storage cannot shrink during an upgrade.')
        root.mkdir(parents=True, exist_ok=True)
        target = root / 'versions' / manifest['version']
        if not (target / 'local/installed-release.json').is_file():
            if target.exists():
                raise RuntimeError('An incomplete version directory exists; remove it after inspection: ' + str(target))
            total = sum(item['size'] for item in manifest['files'].values())
            if shutil.disk_usage(root).free < total + sum(item['size'] for item in manifest['parts']) + 2 * 1024**3:
                raise RuntimeError('Insufficient free storage for staging and archive validation.')
            target.mkdir(parents=True)
            with scope(target):
                setup.install_bundle(str(manifest_path))
        else:
            from bundle_runtime import has_protocol, verify_staged
            if has_protocol(manifest):
                verify_staged(target, manifest)
            else:
                # Frozen releases predate isolated Python caches. Preserve their
                # original checksum contract; launches ignore in-place caches.
                for path, info in manifest['files'].items():
                    if sha256(target / path) != info['sha256']:
                        raise RuntimeError('Cached firmware differs from the release manifest.')
        idle(root, name, port)
        folder = backup(root, name)
        if old is not None:
            upgrade_transaction(root, folder, name, port)
            try:
                prepare_storage(root, name, port, sdk,
                                int(options['disk.dataPartition.size'][:-1]), folder)
            except BaseException:
                idle(root, name, port)
                restore(root, folder)
                raise
        if old is not None and firmware_change(old, manifest):
            upgrade_transaction(root, folder, name, port)
            try:
                prepare_firmware_upgrade(root, old, manifest, name, port, sdk, folder)
            except BaseException:
                # A still-running staging guest keeps the transaction pending;
                # Recover is safe only after the user closes that owned AVD.
                idle(root, name, port)
                restore(root, folder)
                raise
        switch(root, target, manifest, name, port, sdk, options, folder, camera)
    print(tr('安装完成：', 'Installed: ') + str(root / 'Start.command'), flush=True)
    return folder


def start(instance, headless=False, skip_oobe=False):
    root = instance['root']
    state = root / 'local/manager.json'
    runtime = root / json.loads(state.read_text())['runtime'] if state.is_file() else REPO_ROOT
    env = dict(os.environ, HYPEROS_AVD_WORKSPACE=str(root))
    for key in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP'):
        env.pop(key, None)
    command = [sys.executable, '-B', str(runtime / 'scripts/launch.py')]
    if headless:
        command.append('--headless')
    if skip_oobe:
        command.append('--skip-oobe')
    # A new external cache prefix also prevents Python from reading stale or
    # unauthenticated caches left beside an installed runtime by older launchers.
    (root / 'local').mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='python-launch-', dir=root / 'local') as cache:
        env['PYTHONPYCACHEPREFIX'] = cache
        subprocess.run(command, env=env, check=True)


def pick_instance():
    entries = instances()
    if not entries:
        raise RuntimeError(tr('未找到本项目 AVD，请先安装。', 'No project AVD found. Install one first.'))
    labels = [f"[{variant_label(item['variant'])}] "
              f"{item['runtime']['name']} | {item['version']}\n    {item['root']}" for item in entries]
    return entries[choose(tr('选择已安装实例', 'Select an installed instance'), labels)]


def pick_release(variant='all'):
    say('正在查询 OS3 / OS4 / OS4 Pad 镜像发布...', 'Checking OS3 / OS4 / OS4 Pad image releases...')
    releases = catalog(variant)
    if not releases:
        raise RuntimeError('No published compatible release found.')
    labels = [f"[{variant_label(release_variant(r))}] {r['tag_name']}"
              + (' | Pre-release' if r.get('prerelease') else ' | Stable') for r in releases]
    return releases[choose(tr('镜像仓库 / 新版本优先', 'Image library / newest first'), labels)]


def options_for(instance=None, variant='os4-official'):
    values = {}
    if instance:
        variant = instance['variant']
        values = properties(instance['root'] / 'avd' / (instance['runtime']['name'] + '.avd') / 'config.ini')
    default_ram = int(values.get('hw.ramSize', {'os4-official': 6144, 'os4-pad': 4096}.get(variant, 2560))) / 1024
    disk = values.get('disk.dataPartition.size', '32G')
    match = re.fullmatch(r'(\d+)(G|GB)', disk)
    storage = int(match[1]) if match else 32
    if variant == 'os4-pad':
        rows = [tr('OS4 Pad 默认 4 GiB / 4 核。',
                   'OS4 Pad: 4 GiB / 4 cores.'),
                tr('已有存储只支持扩容。', 'Existing storage only grows.')]
    else:
        rows = [tr('OS4 建议 6 GiB / 32 GiB / 4 核；OS3 默认 2.5 GiB / 2 核。',
                   'OS4: 6 GiB / 32 GiB / 4 cores. OS3: 2.5 GiB / 2 cores.'),
                tr('OS4 完整负一屏模糊建议 8 GiB；已有存储只支持扩容。',
                   'OS4 full App Vault blur: 8 GiB. Existing storage only grows.')]
    panel(tr('资源配置', 'Hardware settings'), rows)
    return hardware(float(ask('RAM (GiB)', 'RAM (GiB)', default_ram)),
        int(ask('存储 (GiB)', 'Storage (GiB)', storage)),
        int(ask('CPU 核心', 'CPU cores', values.get('hw.cpu.ncore', 4 if variant in ('os4-official', 'os4-pad') else 2))),
        variant=variant)


def variant_label(variant):
    return {'os4-official': 'OS4', 'os4-pad': 'OS4 Pad'}.get(variant, 'OS3')


def dashboard(entries):
    if sys.stdout.isatty():
        print('\033[2J\033[H', end='')
    panel('H Y P E R O S - A V D   /   INSTALLER ' + VERSION, [
        'Apple Silicon / ARM64 / Android Studio',
        tr('镜像：OS4 手机 / Pad 官方 OTA  |  OS3 GSI', 'Images: OS4 phone / Pad official OTA  |  OS3 GSI'),
        tr('安装器：正式 Release  |  镜像：包含 Pre-release',
           'Installer: stable releases  |  Images: prereleases included')])
    panel(tr('主菜单', 'Dashboard'), [
        tr('[1] 安装新 AVD             [2] 保数据升级', '[1] Install a new AVD      [2] Upgrade / keep data'),
        tr('[3] 启动已有实例           [4] RAM / 存储 / CPU', '[3] Start an instance      [4] RAM / storage / CPU'),
        tr('[5] 镜像浏览 / 检查更新    [6] 恢复 / 回滚', '[5] Browse images / updates [6] Recover / rollback'),
        tr('[7] 安装器检查更新         [0] 退出', '[7] Installer updates      [0] Exit')])
    rows = [f"[{variant_label(e['variant'])}] {e['runtime']['name']} | "
            + (tr('源码旧实例', 'Source workspace') if e['version'] == 'legacy' else e['version'])
            for e in entries]
    panel(tr(f'已安装实例 ({len(entries)})', f'Installed instances ({len(entries)})'),
          rows or [tr('尚未安装，选择 [1] 浏览 OS3 / OS4 / OS4 Pad。', 'No instances yet. Choose [1] for OS3 / OS4 / OS4 Pad.')])


def image_updates(entries):
    rows = catalog('all')
    details = []
    for kind, label in (('os4-official', 'OS4'), ('os4-pad', 'OS4 Pad'), ('os3', 'OS3')):
        matches = [r for r in rows if release_variant(r) == kind]
        installed = [e['runtime']['name'] + ': ' + e['version'] for e in entries if e['variant'] == kind]
        details.append(label + ' | ' + tr('最新：', 'Latest: ') +
                       (matches[0]['tag_name'] if matches else tr('未发布', 'Unavailable')))
        details.extend('  ' + v for v in installed)
        if matches:
            details.append('  ' + matches[0].get('html_url', ''))
    panel(tr('OS3 / OS4 / OS4 Pad 镜像更新', 'OS3 / OS4 / OS4 Pad image updates'), details)


def installer_updates():
    rows = installer_catalog()
    details = [tr('当前：', 'Current: ') + 'installer-v' + VERSION]
    if rows:
        latest = rows[0]
        newer = version_key(latest['tag_name'].removeprefix('installer-')) > version_key(VERSION)
        details += [tr('最新：', 'Latest: ') + latest['tag_name'],
                    tr('有新安装器可下载。', 'A newer installer is available.') if newer else
                    tr('当前安装器已是最新。', 'The installer is up to date.'), latest.get('html_url', '')]
    else:
        details.append(tr('尚无已发布的正式安装器 Release。', 'No stable installer release is published yet.'))
    panel(tr('安装器更新 / 独立正式 Release', 'Installer updates / separate stable release'), details)


def tui(language=None):
    global LANG
    if language is None:
        panel('HyperOS-AVD / Installer ' + VERSION, ['[1] 中文', '[2] English'])
        LANG = 'en' if ask('语言 / Language: 1 中文, 2 English', 'Language', 1) == '2' else 'zh'
    else:
        LANG = language
    while True:
        entries = instances()
        dashboard(entries)
        try:
            action = ask('选择操作', 'Choose action', 0)
            if action == '0':
                return
            if action in ('1', '2'):
                item = pick_instance() if action == '2' else None
                if item and not (item['root'] / 'local/installed-release.json').is_file():
                    raise RuntimeError(tr('源码旧实例没有发布清单；可启动或调整硬件，不能自动迁移固件。',
                        'This source workspace has no release manifest; start/hardware work, automatic firmware migration is refused.'))
                release = pick_release(item['variant'] if item else 'all')
                variant = release_variant(release)
                default_name = {'os4-official': 'HyperOS_4', 'os4-pad': 'HyperOS_4_Pad'}.get(variant, 'HyperOS_3')
                name = item['runtime']['name'] if item else ask('AVD 名称', 'AVD name', default_name)
                root = item['root'] if item else Path(ask('安装目录', 'Installation folder', str(HOME / 'instances' / name))).expanduser().resolve()
                port = item['runtime']['port'] if item else choose_port()
                settings = options_for(item, variant)
                validate_name(name)
                panel(tr('安装计划 / 下载后备份并切换', 'Install plan / verify, back up, then switch'), [
                    'AVD: ' + name, 'Image: ' + release['tag_name'],
                    f"RAM: {int(settings['hw.ramSize']) / 1024:g} GiB | Storage: {settings['disk.dataPartition.size']} | CPU: {settings['hw.cpu.ncore']}",
                    'Port: ' + str(port), str(root)])
                idle(root, name, port)
                path = fetch_release(release, HOME / 'downloads', root=root)
                install(root, path, name, port, sdk_path(), settings, camera=
                    variant == 'os4-official' and ask('启用实验性小米相机？1 是，0 否（后摄录像仍掉帧）',
                    'Enable experimental Xiaomi camera? 1 yes, 0 no (rear video drops frames)', 0) == '1')
                if ask('现在启动？1 是，0 否', 'Start now? 1 yes, 0 no', 1) == '1':
                    start({'root': root})
            elif action == '3':
                start(pick_instance())
            elif action == '4':
                item = pick_instance()
                root, run = item['root'], item['runtime']
                settings = options_for(item, item['variant'])
                idle(root, run['name'], run['port'])
                with lock(root):
                    folder = backup(root, run['name'])
                    paths = {key: str((root / key).resolve()) for key in ('images', 'tools', 'config')}
                    json_write(folder / 'transaction.json', {'name': run['name'], 'port': run['port'], 'paths': paths, 'real': dict.fromkeys(paths, False)})
                    try:
                        prepare_storage(root, run['name'], run['port'], Path(run['sdk']),
                                        int(settings['disk.dataPartition.size'][:-1]), folder)
                        json_write(root / 'local/runtime.json', {**run, 'hardware': settings})
                        with scope(root):
                            setup.configure(Path(run['sdk']), run['name'], run['port'])
                    except BaseException:
                        idle(root, run['name'], run['port'])
                        restore(root, folder)
                        raise
                say('硬件配置已保存，下次冷启动生效。', 'Hardware saved; changes apply on the next cold boot.')
            elif action == '5':
                image_updates(entries)
            elif action == '6':
                item = pick_instance()
                root, run = item['root'], item['runtime']
                pending = root / 'local/upgrade-pending.json'
                folder = Path(json.loads(pending.read_text())['backup']) if pending.exists() else Path(ask('备份目录', 'Backup directory', json.loads((root / 'local/manager.json').read_text()).get('backup', '')))
                idle(root, run['name'], run['port'])
                with lock(root):
                    restore(root, folder)
            elif action == '7':
                installer_updates()
            else:
                say('请输入菜单编号。', 'Enter a menu number.')
        except Back:
            continue
        except (RuntimeError, OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
            panel(tr('操作失败 / 原数据保留', 'Operation failed / userdata retained'), [str(error)])
        if sys.stdin.isatty():
            input(tr('按 Enter 返回主菜单...', 'Press Enter to return to the dashboard...'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', choices=('zh', 'en'))
    commands = parser.add_subparsers(dest='command')
    listing = commands.add_parser('releases')
    listing.add_argument('--variant', choices=('all', 'os3', 'os4-official', 'os4-pad'), default='all')
    listing.add_argument('--stable-only', action='store_true')
    commands.add_parser('list')
    commands.add_parser('installer-updates')
    installing = commands.add_parser('install')
    installing.add_argument('--bundle', type=Path)
    installing.add_argument('--release', default='latest')
    installing.add_argument('--variant', choices=('os3', 'os4-official', 'os4-pad'), default='os4-official')
    installing.add_argument('--root', type=Path, required=True)
    installing.add_argument('--name', required=True)
    installing.add_argument('--port', type=int)
    installing.add_argument('--sdk', type=Path)
    installing.add_argument('--ram', type=float)
    installing.add_argument('--storage', type=int, default=32)
    installing.add_argument('--cores', type=int, default=4)
    installing.add_argument('--start', action='store_true')
    installing.add_argument('--camera', action='store_true', help='Enable experimental Xiaomi camera bridge on boot')
    starting = commands.add_parser('start')
    starting.add_argument('--root', type=Path, required=True)
    starting.add_argument('--headless', action='store_true')
    starting.add_argument('--skip-oobe', action='store_true')
    args = parser.parse_args()
    global LANG
    LANG = args.language or 'zh'
    host_check()
    if args.command == 'releases':
        print(json.dumps([{key: item[key] for key in ('tag_name', 'html_url', 'prerelease')}
                          for item in catalog(args.variant, args.stable_only)], indent=2))
    elif args.command == 'list':
        print(json.dumps(instances(), indent=2, default=str))
    elif args.command == 'installer-updates':
        installer_updates()
    elif args.command == 'start':
        start({'root': args.root.expanduser().resolve()}, args.headless, args.skip_oobe)
    elif args.command == 'install':
        root = args.root.expanduser().resolve()
        variant = (setup.read_install_manifest(str(args.bundle.expanduser().resolve()))[0].get('variant', 'os3')
                   if args.bundle else args.variant)
        ram = args.ram if args.ram is not None else {'os4-pad': 4, 'os4-official': 6}.get(variant, 2.5)
        settings = hardware(ram, args.storage, args.cores, variant=variant)
        previous = root / 'local/runtime.json'
        port = args.port or (json.loads(previous.read_text())['port'] if previous.exists() else choose_port())
        if port % 2 or not 5556 <= port <= 5682:
            parser.error('Use an even console port between 5556 and 5682.')
        if args.bundle:
            path = args.bundle.expanduser().resolve()
        else:
            idle(root, args.name, port)
            rows = catalog(args.variant)
            if args.release == 'latest':
                choices = rows
            elif release_variant({'tag_name': args.release}) is not None:
                choices = [r for r in rows if r['tag_name'] == args.release]
            else:
                choices = [r for r in rows if version_key(r['tag_name']) == version_key(args.release)]
            if not choices:
                raise RuntimeError('Requested release is not published.')
            path = fetch_release(choices[0], HOME / 'downloads', root=root)
        install(root, path, args.name, port, sdk_path(args.sdk), settings, args.camera)
        if args.start:
            start({'root': root})
    else:
        tui(args.language)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError, http.client.HTTPException) as error:
        raise SystemExit(tr('操作失败：', 'Operation failed: ') + str(error))
    except (KeyboardInterrupt, EOFError):
        print('\n' + tr('已退出；下载缓存和备份保留。', 'Exited; download cache and backups retained.'))
