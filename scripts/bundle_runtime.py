#!/usr/bin/env python3
"""Versioned handoff from a stable installer to a fully verified bundle runtime."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat

from common import sha256

INSTALL_PROTOCOL = 'verified-bundle-runtime-v1'
PROTOCOL_MINIMUM = '1.2.3'
ENTRYPOINT = 'runtime/scripts/bundle_runtime.py'
FAMILIES = {
    'os4-official': ('official-hongkong-ota', 'hongkong', 'os4-hongkong-api37-ranchu-4k'),
    'os4-pad': ('official-yingtian-ota', 'yingtian', 'os4-yingtian-api37-ranchu-4k'),
}


def has_protocol(manifest):
    compatibility = manifest.get('compatibility', {})
    if not isinstance(compatibility, dict):
        raise RuntimeError('Invalid release compatibility metadata.')
    value = compatibility.get('install_protocol')
    if value is None:
        return False
    if value != INSTALL_PROTOCOL:
        raise RuntimeError('Unsupported bundle installation protocol; update the installer.')
    return True


def manifest_digest(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def file_entries(manifest):
    """Reject aliases, links, invalid types and ambiguous archive paths."""
    files = manifest.get('files')
    if not isinstance(files, dict) or not files:
        raise RuntimeError('Missing release file integrity metadata.')
    for name, info in files.items():
        if not isinstance(name, str):
            raise RuntimeError('Invalid release path.')
        path = PurePosixPath(name)
        if (not name or '\\' in name or path.is_absolute() or '..' in path.parts
                or path.as_posix() != name or len(path.parts) < 2
                or path.parts[0] not in ('images', 'tools', 'runtime', 'config')
                or path.parts[0] == 'config' and name != 'config/avd.ini'
                or not isinstance(info, dict) or set(info) != {'size', 'sha256'}
                or type(info['size']) is not int or info['size'] < 0
                or not isinstance(info['sha256'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', info['sha256'])):
            raise RuntimeError('Invalid release file integrity metadata: ' + name)
    return files


def validate_envelope(manifest):
    """Validate the stable transport contract without a firmware source registry."""
    if not isinstance(manifest, dict) or not has_protocol(manifest):
        raise RuntimeError('Missing verified bundle installation protocol.')
    compat, build = manifest.get('compatibility'), manifest.get('build')
    variant = manifest.get('variant')
    if variant not in FAMILIES or not isinstance(build, dict):
        raise RuntimeError('Unsupported verified bundle firmware family.')
    source, device, family = FAMILIES[variant]
    tag = ((r'v\d+\.\d+\.\d+-a17-hyperos4-hongkong-r\d+') if variant == 'os4-official'
           else r'pad-v\d+\.\d+\.\d+-a17-hyperos4-yingtian-r\d+')
    minimum = compat.get('minimum_installer')
    if (manifest.get('project') != 'HyperOS-AVD' or type(manifest.get('format')) is not int
            or manifest['format'] != 3 or manifest.get('platform') != 'macos-arm64'
            or not isinstance(manifest.get('version'), str)
            or not re.fullmatch(tag, manifest['version'])
            or manifest.get('source') != source or manifest.get('source_device') != device
            or type(manifest.get('android_api')) is not int or manifest['android_api'] != 37
            or build.get('source') != source or type(build.get('android_api')) is not int
            or build['android_api'] != 37 or build.get('hyperos') != manifest.get('hyperos')
            or not isinstance(manifest.get('hyperos'), str)
            or not re.fullmatch((r'OS4\.\d+\.\d+\.\d+\.[A-Z]{7}' if variant == 'os4-pad'
                                 else r'4\.\d+\.\d+\.\d+\.[A-Z]{7}'), manifest['hyperos'])
            or build.get('adb_authentication') is not True
            or compat.get('userdata_family') != family or compat.get('runtime_in_bundle') is not True
            or not isinstance(minimum, str) or not re.fullmatch(r'\d+\.\d+\.\d+', minimum)
            or tuple(map(int, minimum.split('.'))) < tuple(map(int, PROTOCOL_MINIMUM.split('.')))):
        raise RuntimeError('Invalid verified bundle installation envelope.')
    files = file_entries(manifest)
    required = {'config/avd.ini', 'images/encryptionkey.img', 'images/system.img',
                ENTRYPOINT, 'runtime/scripts/manage.py', 'runtime/scripts/setup.py',
                'runtime/scripts/common.py', 'tools/os4-core/context.json',
                'tools/os4-core/receipt.json', 'tools/os4-app-compat/app-compat.zip',
                'tools/os4-app-compat/receipt.json'}
    if not required <= set(files):
        raise RuntimeError('Verified bundle is missing its runtime or encryption template.')
    parts = manifest.get('parts')
    if not isinstance(parts, list) or not parts:
        raise RuntimeError('Missing release archive parts.')
    seen = set()
    for item in parts:
        if (not isinstance(item, dict) or set(item) != {'name', 'size', 'sha256'}
                or not isinstance(item['name'], str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', item['name'])
                or item['name'] in seen or type(item['size']) is not int or item['size'] <= 0
                or not isinstance(item['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', item['sha256'])):
            raise RuntimeError('Invalid release archive integrity metadata.')
        seen.add(item['name'])
    return manifest


def regular(path, root):
    root = Path(root)
    current = root
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError('Invalid bundle staging directory.')
    for part in path.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise RuntimeError('Release staging contains a symlink: ' + str(current))
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RuntimeError('Release staging contains a nonregular file: ' + str(path))


def verify_staged(target, manifest):
    """Authenticate cached content and manifest again immediately before handoff."""
    target = Path(target)
    saved = target / 'local/installed-release.json'
    regular(saved, target)
    if json.loads(saved.read_text()) != manifest:
        raise RuntimeError('Cached firmware manifest differs from the release manifest.')
    files = file_entries(manifest)
    for name, info in files.items():
        path = target / name
        regular(path, target)
        if path.stat().st_size != info['size'] or sha256(path) != info['sha256']:
            raise RuntimeError('Cached firmware differs from the release manifest: ' + name)
    # Python imports must not find an injected unlisted module or bytecode cache.
    runtime = target / 'runtime'
    if runtime.exists():
        for path in runtime.rglob('*'):
            relative = path.relative_to(target)
            if path.is_symlink() or not path.is_dir() and relative.as_posix() not in files:
                raise RuntimeError('Unlisted bundle runtime content: ' + str(path))


def execute_request(request_path, report_path):
    """Exact entrypoint; call the transaction directly rather than hand off twice."""
    import manage
    import setup
    request = json.loads(Path(request_path).read_text())
    required = {'schema', 'protocol', 'root', 'target', 'name', 'port', 'sdk', 'options', 'camera',
                'manifest_sha256'}
    if (not isinstance(request, dict) or set(request) != required or type(request['schema']) is not int
            or request['schema'] != 1 or request['protocol'] != INSTALL_PROTOCOL
            or any(not isinstance(request[key], str) for key in ('root', 'target', 'name', 'sdk'))
            or not isinstance(request['manifest_sha256'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', request['manifest_sha256'])
            or type(request['port']) is not int or request['port'] % 2 or not 5556 <= request['port'] <= 5682
            or not isinstance(request['options'], dict) or type(request['camera']) is not bool):
        raise RuntimeError('Invalid bundle installation request.')
    root, target = Path(request['root']).resolve(), Path(request['target']).resolve()
    manifest_path = target / 'local/installed-release.json'
    manifest, _ = setup.read_manifest(str(manifest_path))
    if manifest_digest(manifest) != request['manifest_sha256']:
        raise RuntimeError('Bundle manifest changed after bootstrap verification.')
    validate_envelope(manifest)
    if target != root / 'versions' / manifest['version']:
        raise RuntimeError('Bundle installation target is outside its instance.')
    verify_staged(target, manifest)
    validate_runtime_assets(target)
    folder = manage.install_transaction(root, manifest_path, request['name'], request['port'],
                                        Path(request['sdk']), request['options'], request['camera'])
    manage.json_write(Path(report_path), {'schema': 1, 'protocol': INSTALL_PROTOCOL, 'backup': str(folder)})


def validate_runtime_assets(target):
    """Authenticate the image context and Apps catalog using the bundled rules."""
    from core_context import load
    from apply_app_compat import recipes
    from app_compat_catalog import verify_prebuilt
    load(target)
    verify_prebuilt(Path(target) / 'tools/os4-app-compat', recipes())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    execute_request(args.request, args.report)
