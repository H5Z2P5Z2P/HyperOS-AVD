"""Verify source-independent handoff and rejection before userdata changes."""
import copy
import hashlib
import io
import importlib.util
import json
import marshal
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import bundle_runtime as protocol
import common
import delta_install
import incremental
import manage
import setup


class BundleRuntimeTests(unittest.TestCase):
    def poison_cache(self, source, marker):
        """Create a valid timestamp cache which normal Python would execute."""
        code = compile(f"from pathlib import Path\nPath({str(marker)!r}).write_text('unverified bytecode')\n"
                       "VALUE = 'unverified bytecode'\n", str(source), 'exec')
        metadata = source.stat()
        data = (importlib.util.MAGIC_NUMBER
                + struct.pack('<III', 0, int(metadata.st_mtime), metadata.st_size)
                + marshal.dumps(code))
        cache = Path(importlib.util.cache_from_source(str(source)))
        cache.parent.mkdir(exist_ok=True)
        cache.write_bytes(data)
        return cache

    def bundle(self, directory, variant='os4-official'):
        directory.mkdir()
        source, device, family = protocol.FAMILIES[variant]
        entry = b'''import argparse, json
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument('--request'); p.add_argument('--report')
a = p.parse_args(); r = json.loads(Path(a.request).read_text())
folder = Path(r['root']) / 'backups' / 'verified-test'; folder.mkdir(parents=True)
(Path(r['root']) / 'executed').write_text('verified bundle entrypoint')
Path(a.report).write_text(json.dumps({'schema': 1, 'protocol': r['protocol'], 'backup': str(folder)}))
'''
        payloads = {'images/system.img': b'new', 'images/encryptionkey.img': b'stable-key',
                    'config/avd.ini': b'target=android-37.0\nhw.cpu.arch=arm64\nhw.ramSize=6144\n',
                    protocol.ENTRYPOINT: entry, 'runtime/scripts/manage.py': b'# new source recipes',
                    'runtime/scripts/setup.py': b'# strict source authentication',
                    'runtime/scripts/common.py': b'# portable common',
                    'tools/os4-core/context.json': b'{}', 'tools/os4-core/receipt.json': b'{}',
                    'tools/os4-app-compat/app-compat.zip': b'catalog fixture',
                    'tools/os4-app-compat/receipt.json': b'{}'}
        archive = directory / 'bundle.part001'
        with tarfile.open(archive, 'w:gz') as output:
            for name, data in payloads.items():
                item = tarfile.TarInfo(name)
                item.size = len(data)
                output.addfile(item, io.BytesIO(data))
        firmware = '4.0.999.0.XFRCNXM' if variant == 'os4-official' else setup.PAD_HYPEROS
        version = ('v9.0.0-a17-hyperos4-hongkong-r999' if variant == 'os4-official'
                   else 'pad-v9.0.0-a17-hyperos4-yingtian-r999')
        manifest = {'project': 'HyperOS-AVD', 'format': 3, 'platform': 'macos-arm64',
                    'version': version, 'variant': variant, 'source': source, 'source_device': device,
                    'android_api': 37, 'hyperos': firmware,
                    'build': {'source': source, 'device': device, 'android_api': 37, 'hyperos': firmware,
                              'adb_authentication': True},
                    'compatibility': {'install_protocol': protocol.INSTALL_PROTOCOL,
                                      'minimum_installer': protocol.PROTOCOL_MINIMUM,
                                      'userdata_family': family, 'runtime_in_bundle': True},
                    'files': {name: {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                              for name, data in payloads.items()},
                    'parts': [{'name': archive.name, 'size': archive.stat().st_size,
                               'sha256': common.sha256(archive)}]}
        path = directory / 'manifest.json'
        path.write_text(json.dumps(manifest))
        return path, manifest

    def delta_bundle(self, directory):
        """Keep immutable source bytes separate from mutable instance images."""
        path, manifest = self.bundle(directory / 'bundle')
        manifest['build']['archive_sha256'] = 'a' * 64
        with tarfile.open(path.parent / manifest['parts'][0]['name']) as archive:
            payloads = {item.name: archive.extractfile(item).read() for item in archive}
        payloads['tools/new.txt'] = b'new release helper'
        manifest['files']['tools/new.txt'] = {'size': len(payloads['tools/new.txt']),
            'sha256': hashlib.sha256(payloads['tools/new.txt']).hexdigest()}
        archive_path = path.parent / manifest['parts'][0]['name']
        with tarfile.open(archive_path, 'w:gz') as archive:
            for name, data in payloads.items():
                item = tarfile.TarInfo(name); item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
        manifest['parts'][0].update(size=archive_path.stat().st_size, sha256=common.sha256(archive_path))
        old = copy.deepcopy(manifest)
        old['version'] = 'v8.0.0-a17-hyperos4-hongkong-r998'
        old_payloads = dict(payloads)
        old_payloads['images/system.img'] = b'old immutable firmware'
        old_payloads['tools/obsolete.txt'] = b'removed release helper'
        old_payloads.pop('tools/new.txt')
        old['files'] = {name: {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                        for name, data in old_payloads.items()}
        root = (directory / 'instance').resolve(); source = root / 'versions' / old['version']
        for name, data in old_payloads.items():
            current = source / name; current.parent.mkdir(parents=True, exist_ok=True)
            current.write_bytes(data)
        for base in (root, source):
            (base / 'local').mkdir(exist_ok=True)
            (base / 'local/installed-release.json').write_text(json.dumps(old))
            (base / 'local/build.json').write_text(json.dumps(old['build']))
        (root / 'images').mkdir(); (root / 'images/system.img').write_bytes(b'mutable instance firmware')
        (root / 'avd').mkdir(); (root / 'avd/userdata-qemu.img').write_bytes(b'personal userdata')
        patches = {}
        for name, data in payloads.items():
            if old['files'].get(name) == manifest['files'][name]:
                continue
            target = directory / 'target-files' / name
            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
            stream = io.BytesIO()
            incremental.write_patch(source / name if name in old['files'] else None, target, stream)
            patches[name] = stream.getvalue()
        delta_path = path.parent / 'delta.part001'
        self.write_delta_archive(delta_path, patches.items())
        descriptor = {'protocol': incremental.PROTOCOL, 'from_version': old['version'],
            'from_manifest_sha256': protocol.manifest_digest(old), 'parts': [
                {'name': delta_path.name, 'size': delta_path.stat().st_size, 'sha256': common.sha256(delta_path)}]}
        manifest['deltas'] = [descriptor]
        path.write_text(json.dumps(manifest))
        return root, path, manifest, descriptor, source, old, patches

    def write_delta_archive(self, path, members):
        with tarfile.open(path, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
            for name, data in members:
                item = tarfile.TarInfo(name); item.size = len(data)
                archive.addfile(item, io.BytesIO(data))

    def refresh_delta_part(self, path, manifest, descriptor):
        part = path.parent / descriptor['parts'][0]['name']
        descriptor['parts'][0].update(size=part.stat().st_size, sha256=common.sha256(part))
        path.write_text(json.dumps(manifest))

    def delta_only_bundle(self, directory):
        root, path, manifest, descriptor, source, old, patches = self.delta_bundle(directory)
        base_directory = directory / 'complete-base'; base_directory.mkdir()
        archive_path = base_directory / 'base.part001'
        with tarfile.open(archive_path, 'w:gz') as archive:
            for name in old['files']:
                data = (source / name).read_bytes()
                item = tarfile.TarInfo(name); item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
        old['parts'] = [{'name': archive_path.name, 'size': archive_path.stat().st_size,
                         'sha256': common.sha256(archive_path)}]
        base_path = base_directory / 'manifest.json'
        base_path.write_text(json.dumps(old))
        (source / 'local/installed-release.json').write_text(json.dumps(old))
        descriptor['from_manifest_sha256'] = protocol.manifest_digest(old)
        manifest['version'] = old['version'] + '.1'
        manifest['distribution'] = protocol.DELTA_DISTRIBUTION
        manifest['compatibility']['minimum_installer'] = protocol.DELTA_MINIMUM
        manifest['base_release'] = {'manifest': copy.deepcopy(old),
                                    'manifest_sha256': protocol.manifest_digest(old)}
        manifest['parts'] = []
        path.write_text(json.dumps(manifest))
        return root, path, manifest, descriptor, source, old, base_path

    def history_bundle(self, directory, variant='os4-official'):
        """Build real base, repair and direct history archives for both families."""
        import package_release
        base_path, base = self.bundle(directory / 'base', variant)
        base['version'] = base['version'].replace('-r999', '-r6' if variant == 'os4-official' else '-r3')
        base['build']['archive_sha256'] = 'a' * 64
        base_path.write_text(json.dumps(base))
        root = (directory / 'instance').resolve()
        source = root / 'versions' / base['version']; source.mkdir(parents=True)
        with manage.scope(source):
            setup.stage_bundle(str(base_path))
        paths = {name: source / name for name in base['files']}
        changed = directory / 'first-system.img'; changed.write_bytes(b'first repaired system')
        paths['images/system.img'] = changed
        repair_path = directory / 'repair/manifest.json'
        with patch('sys.stdout', new_callable=io.StringIO):
            repair = package_release.write_bundle(repair_path.parent, base['version'] + '.1', base, paths, 1,
                delta_from=[source / 'local/installed-release.json'], delta_only=True)
        repair_source = root / 'versions' / repair['version']
        selection = delta_install.select_delta(root, repair)
        delta_install.stage_delta(root, repair_source, repair_path, repair, *selection)
        (root / 'local').mkdir()
        (root / 'local/installed-release.json').write_text(json.dumps(repair))
        personal = root / 'avd/Custom_Name.avd/userdata-qemu.img'
        personal.parent.mkdir(parents=True); personal.write_bytes(b'personal data remains untouched')
        paths = {name: repair_source / name for name in repair['files']}
        changed = directory / 'second-system.img'; changed.write_bytes(b'second repaired system')
        paths['images/system.img'] = changed
        target_path = directory / 'history/manifest.json'
        with patch('sys.stdout', new_callable=io.StringIO):
            target = package_release.write_bundle(target_path.parent, base['version'] + '.2', repair, paths, 1,
                delta_from=[repair_source / 'local/installed-release.json', source / 'local/installed-release.json'],
                delta_only=True)
        return root, target_path, target, base, repair, base_path

    def test_history_direct_reconstruction_for_phone_and_pad_from_both_installed_versions(self):
        for variant in protocol.FAMILIES:
            for revision in (0, 1):
                with self.subTest(variant=variant, revision=revision), tempfile.TemporaryDirectory() as directory:
                    root, path, manifest, base, repair, _ = self.history_bundle(Path(directory), variant)
                    active = repair if revision else base
                    (root / 'local/installed-release.json').write_text(json.dumps(active))
                    if revision:
                        shutil.rmtree(root / 'versions' / base['version'])
                    else:
                        shutil.rmtree(root / 'versions' / repair['version'])
                    selected = delta_install.select_delta(root, manifest)
                    self.assertEqual(selected[0]['from_version'], active['version'])
                    target = root / 'versions' / manifest['version']
                    delta_install.stage_delta(root, target, path, manifest, *selected)
                    protocol.verify_staged(target, manifest)
                    self.assertEqual((target / 'images/system.img').read_bytes(), b'second repaired system')
                    self.assertEqual(json.loads((root / 'local/installed-release.json').read_text()), active)
                    self.assertEqual((root / 'avd/Custom_Name.avd/userdata-qemu.img').read_bytes(),
                                     b'personal data remains untouched')

    def test_history_envelope_and_source_corruption_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, path, manifest, base, repair, _ = self.history_bundle(Path(directory))
            for failure in ('gap', 'duplicate-version', 'duplicate-digest', 'duplicate-part', 'old-installer',
                            'wrong-base', 'legacy-multiple', 'wrong-series'):
                changed = copy.deepcopy(manifest)
                if failure == 'gap':
                    changed['deltas'].pop(0)
                elif failure == 'duplicate-version':
                    changed['deltas'].append(copy.deepcopy(changed['deltas'][0]))
                elif failure == 'duplicate-digest':
                    changed['deltas'][0]['from_manifest_sha256'] = changed['deltas'][1]['from_manifest_sha256']
                elif failure == 'duplicate-part':
                    changed['deltas'][0]['parts'][0]['name'] = changed['deltas'][1]['parts'][0]['name']
                elif failure == 'old-installer':
                    changed['compatibility']['minimum_installer'] = protocol.DELTA_MINIMUM
                elif failure == 'wrong-base':
                    changed['deltas'][1]['from_manifest_sha256'] = 'c' * 64
                elif failure == 'legacy-multiple':
                    changed['distribution'] = protocol.DELTA_DISTRIBUTION
                else:
                    changed['deltas'][0]['from_version'] = repair['version'].replace('-r6', '-r7')
                with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                    protocol.validate_envelope(changed)
            selected = delta_install.select_delta(root, manifest)
            self.assertEqual(selected[0]['from_version'], repair['version'])
            # A source altered after selection cannot promote any target.
            (selected[1] / 'images/system.img').write_bytes(b'corrupt immutable repair')
            target = root / 'versions' / manifest['version']
            with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
                delta_install.stage_delta(root, target, path, manifest, *selected)
            self.assertFalse(target.exists())
            self.assertEqual((root / 'avd/Custom_Name.avd/userdata-qemu.img').read_bytes(),
                             b'personal data remains untouched')

    def test_delta_only_stages_full_base_then_patch_without_activating_base(self):
        for active in (False, True):
            with self.subTest(active=active), tempfile.TemporaryDirectory() as directory:
                root, path, manifest, descriptor, source, old, base_path = self.delta_only_bundle(Path(directory))
                direct = Path(directory) / 'direct-extraction'
                with manage.scope(direct), self.assertRaisesRegex(RuntimeError, 'reconstruct this delta-only release'):
                    setup.stage_bundle(str(path))
                self.assertFalse(direct.exists())
                shutil.rmtree(source)
                if active:
                    previous = copy.deepcopy(old); previous['version'] = old['version'].replace('-r998', '-r997')
                    (root / 'local/installed-release.json').write_text(json.dumps(previous))
                    active_bytes = (root / 'local/installed-release.json').read_bytes()
                else:
                    for name in ('local', 'images', 'avd'):
                        shutil.rmtree(root / name)
                self.assertIsNone(delta_install.select_delta(root, manifest))
                self.assertEqual(delta_install.stage_base(root, base_path, old), source)
                protocol.verify_staged(source, old)
                self.assertEqual(delta_install.stage_base(root, base_path, old), source)
                selected = delta_install.select_delta(root, manifest)
                self.assertEqual(selected, (descriptor, source, old))
                target = root / 'versions' / manifest['version']
                delta_install.stage_delta(root, target, path, manifest, *selected)
                protocol.verify_staged(target, manifest)
                self.assertEqual((target / 'images/system.img').read_bytes(), b'new')
                if active:
                    self.assertEqual((root / 'local/installed-release.json').read_bytes(), active_bytes)
                    self.assertEqual((root / 'avd/userdata-qemu.img').read_bytes(), b'personal userdata')
                    self.assertEqual((root / 'images/system.img').read_bytes(), b'mutable instance firmware')
                else:
                    self.assertFalse((root / 'local').exists())
                    self.assertFalse((root / 'avd').exists())
                    self.assertFalse((root / 'images').exists())
                self.assertFalse((source / 'downloads').exists())
                self.assertFalse(list((root / 'versions').glob('.delta-*')))

    def test_delta_only_missing_or_corrupt_base_never_overwrites_existing_state(self):
        for failure in ('missing-part', 'cached-bytes', 'cached-manifest', 'wrong-pin', 'low-disk', 'symlink'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root, path, manifest, descriptor, source, old, base_path = self.delta_only_bundle(Path(directory))
                active = (root / 'local/installed-release.json').read_bytes()
                if failure in ('missing-part', 'low-disk'):
                    shutil.rmtree(source)
                    if failure == 'missing-part':
                        (base_path.parent / old['parts'][0]['name']).unlink()
                        with self.assertRaisesRegex(RuntimeError, 'manifest and all archive parts'):
                            delta_install.stage_base(root, base_path, old)
                    else:
                        with patch.object(delta_install.shutil, 'disk_usage',
                                          return_value=type('Disk', (), {'free': 0})()), \
                                self.assertRaisesRegex(RuntimeError, 'free disk space'):
                            delta_install.stage_base(root, base_path, old)
                    self.assertFalse(source.exists())
                elif failure == 'wrong-pin':
                    manifest['base_release']['manifest_sha256'] = '0' * 64
                    with self.assertRaises(RuntimeError):
                        delta_install.select_delta(root, manifest)
                else:
                    marker = source / 'custom-file'; marker.write_bytes(b'preserved custom data')
                    if failure == 'cached-bytes':
                        (source / 'images/system.img').write_bytes(b'corrupt cached source')
                    elif failure == 'cached-manifest':
                        (source / 'local/installed-release.json').write_text('{}')
                    else:
                        actual = source.with_name(source.name + '-actual'); source.rename(actual)
                        source.symlink_to(actual, target_is_directory=True)
                    with self.assertRaisesRegex(RuntimeError, 'base|cache'):
                        delta_install.stage_base(root, base_path, old)
                    with self.assertRaisesRegex(RuntimeError, 'base|cache'):
                        delta_install.select_delta(root, manifest)
                    self.assertEqual((source / 'custom-file').read_bytes(), b'preserved custom data')
                self.assertEqual((root / 'local/installed-release.json').read_bytes(), active)
                self.assertEqual((root / 'avd/userdata-qemu.img').read_bytes(), b'personal userdata')
                self.assertFalse((root / 'versions' / manifest['version']).exists())
                self.assertFalse(list((root / 'versions').glob('.delta-*')))

    def test_delta_stages_exact_target_with_new_removed_and_unchanged_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root, path, manifest, descriptor, source, old, patches = self.delta_bundle(Path(directory))
            compressed = (path.parent / descriptor['parts'][0]['name']).read_bytes()
            descriptor['parts'] = []
            split = len(compressed) // 2
            for index, data in enumerate((compressed[:split], compressed[split:]), 1):
                part = path.parent / ('delta.part%03d' % index); part.write_bytes(data)
                descriptor['parts'].append({'name': part.name, 'size': len(data), 'sha256': common.sha256(part)})
            path.write_text(json.dumps(manifest))
            selected = delta_install.select_delta(root, manifest)
            self.assertEqual(selected, (descriptor, source, old))
            target = root / 'versions' / manifest['version']
            delta_install.stage_delta(root, target, path, manifest, *selected)
            protocol.verify_staged(target, manifest)
            self.assertEqual((target / 'images/system.img').read_bytes(), b'new')
            self.assertEqual((target / 'tools/new.txt').read_bytes(), b'new release helper')
            self.assertFalse((target / 'tools/obsolete.txt').exists())
            self.assertEqual(json.loads((target / 'local/build.json').read_text()), manifest['build'])
            self.assertEqual((source / 'images/system.img').read_bytes(), b'old immutable firmware')
            self.assertEqual((root / 'images/system.img').read_bytes(), b'mutable instance firmware')
            self.assertEqual((root / 'avd/userdata-qemu.img').read_bytes(), b'personal userdata')
            self.assertFalse(list((root / 'versions').glob('.delta-*')))

    def test_delta_selection_falls_back_for_unusable_or_non_saving_source(self):
        for case in ('changed-bytes', 'unchanged-bytes', 'missing-version', 'source-manifest',
                     'source-symlink', 'source-hardlink', 'different-base', 'non-saving', 'future-protocol'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root, path, manifest, descriptor, source, old, patches = self.delta_bundle(Path(directory))
                if case == 'changed-bytes':
                    (source / 'images/system.img').write_bytes(b'corrupt patch base')
                elif case == 'unchanged-bytes':
                    (source / 'images/encryptionkey.img').write_bytes(b'corrupt copied file')
                elif case == 'missing-version':
                    (source / 'local/installed-release.json').unlink()
                elif case == 'source-manifest':
                    (source / 'local/installed-release.json').write_text('{}')
                elif case == 'source-symlink':
                    current = source / 'images/system.img'; current.unlink()
                    current.symlink_to(root / 'images/system.img')
                elif case == 'source-hardlink':
                    os.link(source / 'images/system.img', root / 'aliased.img')
                elif case == 'different-base':
                    manifest['build']['archive_sha256'] = 'b' * 64
                elif case == 'non-saving':
                    descriptor['parts'][0]['size'] = manifest['parts'][0]['size']
                else:
                    descriptor['protocol'] = 'future-delta-v2'
                self.assertIsNone(delta_install.select_delta(root, manifest))
                self.assertEqual((root / 'avd/userdata-qemu.img').read_bytes(), b'personal userdata')
                self.assertFalse((root / 'versions' / manifest['version']).exists())
                self.assertFalse(list((root / 'versions').glob('.delta-*')))

    def test_delta_descriptor_rejects_ambiguous_parts_and_types(self):
        for case in ('extra', 'path', 'full-collision', 'duplicate', 'bool-size', 'hash'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root, path, manifest, descriptor, source, old, patches = self.delta_bundle(Path(directory))
                if case == 'extra':
                    descriptor['unrecognized'] = True
                elif case == 'path':
                    descriptor['parts'][0]['name'] = '../delta.part001'
                elif case == 'full-collision':
                    descriptor['parts'][0]['name'] = manifest['parts'][0]['name']
                elif case == 'duplicate':
                    descriptor['parts'].append(copy.deepcopy(descriptor['parts'][0]))
                elif case == 'bool-size':
                    descriptor['parts'][0]['size'] = True
                else:
                    descriptor['from_manifest_sha256'] = 'invalid'
                with self.assertRaises(RuntimeError):
                    delta_install.validate_descriptor(descriptor, manifest)

    def test_delta_archive_rejections_leave_source_userdata_and_target_untouched(self):
        for case in ('duplicate', 'traversal', 'alias', 'symlink', 'hardlink', 'pax', 'directory', 'missing',
                     'unlisted', 'oversized', 'invalid-patch', 'part-checksum'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root, path, manifest, descriptor, source, old, patches = self.delta_bundle(Path(directory))
                part = path.parent / descriptor['parts'][0]['name']
                members = list(patches.items())
                if case == 'duplicate':
                    members.append(members[0])
                elif case == 'traversal':
                    members[0] = ('images/../outside.img', members[0][1])
                elif case == 'alias':
                    members[0] = ('images//system.img', members[0][1])
                elif case == 'missing':
                    members.pop()
                elif case == 'unlisted':
                    members.append(('tools/unlisted.txt', b'unlisted'))
                elif case == 'oversized':
                    members[0] = (members[0][0], b'x' * (incremental.patch_limit(3) + 1))
                elif case == 'invalid-patch':
                    members[0] = (members[0][0], b'corrupt')
                if case in ('symlink', 'hardlink', 'pax', 'directory'):
                    with tarfile.open(part, 'w:gz') as archive:
                        item = tarfile.TarInfo(members[0][0]); item.linkname = 'outside'
                        item.type = {'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE,
                                     'pax': tarfile.XHDTYPE, 'directory': tarfile.DIRTYPE}[case]
                        archive.addfile(item)
                else:
                    self.write_delta_archive(part, members)
                if case == 'part-checksum':
                    part.write_bytes(part.read_bytes() + b'corrupt')
                else:
                    self.refresh_delta_part(path, manifest, descriptor)
                selected = delta_install.select_delta(root, manifest)
                self.assertIsNotNone(selected)
                target = root / 'versions' / manifest['version']
                with self.assertRaises(RuntimeError):
                    delta_install.stage_delta(root, target, path, manifest, *selected)
                self.assertFalse(target.exists())
                self.assertFalse((root / 'outside.img').exists())
                self.assertEqual((source / 'images/system.img').read_bytes(), b'old immutable firmware')
                self.assertEqual((root / 'avd/userdata-qemu.img').read_bytes(), b'personal userdata')
                self.assertFalse(list((root / 'versions').glob('.delta-*')))

    def test_delta_rechecks_source_and_available_disk_before_staging(self):
        for case in ('source-changed', 'low-disk'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root, path, manifest, descriptor, source, old, patches = self.delta_bundle(Path(directory))
                selected = delta_install.select_delta(root, manifest)
                target = root / 'versions' / manifest['version']
                if case == 'source-changed':
                    (source / 'images/system.img').write_bytes(b'changed after selection')
                    with self.assertRaises(RuntimeError):
                        delta_install.stage_delta(root, target, path, manifest, *selected)
                else:
                    with patch.object(delta_install.shutil, 'disk_usage', return_value=type('Disk', (), {'free': 0})()), \
                            self.assertRaisesRegex(RuntimeError, 'free disk space'):
                        delta_install.stage_delta(root, target, path, manifest, *selected)
                self.assertFalse(target.exists())
                self.assertFalse(list((root / 'versions').glob('.delta-*')))

    def install(self, root, path):
        with patch('userdata_resize.check_dependencies'), patch.object(manage, 'idle'), \
                patch.object(manage, 'avd_home', return_value=root.parent / 'registry'):
            return manage.install(root, path, 'Custom_Name', 5584, Path('/sdk'), manage.hardware(6, 32, 4))

    def test_unknown_source_reaches_only_verified_runtime_without_bootstrap_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path, manifest = self.bundle(folder / 'bundle')
            with self.assertRaises(RuntimeError):
                setup.read_manifest(str(path))
            with patch('phone_profile.profile_from_build', side_effect=AssertionError('old registry used')):
                self.assertEqual(setup.read_install_manifest(str(path))[0], manifest)
                backup = self.install(folder / 'instance', path)
            self.assertEqual(backup, (folder / 'instance/backups/verified-test').resolve())
            self.assertEqual((folder / 'instance/executed').read_text(), 'verified bundle entrypoint')
            self.assertFalse((folder / 'instance/avd').exists())

    def test_pad_envelope_uses_actual_prefixed_firmware_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path, manifest = self.bundle(Path(directory) / 'bundle', 'os4-pad')
            self.assertEqual(setup.read_install_manifest(str(path))[0], manifest)
            self.assertEqual(setup.read_manifest(str(path))[0], manifest)

    def test_future_installer_version_does_not_raise_protocol_baseline(self):
        import package_release
        from test_os4_pad import build_info
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'local').mkdir()
            (root / 'local/build.json').write_text(json.dumps(build_info()))
            with patch.object(manage, 'VERSION', '99.0.0'):
                value = package_release.release_metadata(root, 'os4-pad')
            self.assertEqual(value['compatibility']['minimum_installer'], protocol.PROTOCOL_MINIMUM)
            self.assertEqual(value['compatibility']['install_protocol'], protocol.INSTALL_PROTOCOL)

    def test_retained_data_checks_family_key_order_and_ignores_old_source_registry(self):
        for failure in (None, 'family', 'key', 'downgrade'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory); path, manifest = self.bundle(folder / 'bundle')
                manifest['compatibility'].update(upgrade_policy=manage.FORWARD_UPGRADE_POLICY,
                    module_upgrade_preflight=manage.MODULE_UPGRADE_PREFLIGHT)
                path.write_text(json.dumps(manifest))
                root = folder / 'instance'; (root / 'local').mkdir(parents=True)
                data = root / 'avd/Custom_Name.avd'; data.mkdir(parents=True)
                userdata = data / 'userdata-qemu.img'; userdata.write_bytes(b'original personal userdata')
                old = copy.deepcopy(manifest)
                old['version'] = 'v1.0.0-a17-hyperos4-hongkong-r1'
                old['build']['hyperos'] = old['hyperos'] = '4.0.888.0.XFRCNXM'
                if failure == 'family':
                    old['compatibility']['userdata_family'] = setup.PAD_FAMILY
                elif failure == 'key':
                    old['files']['images/encryptionkey.img']['sha256'] = 'f' * 64
                elif failure == 'downgrade':
                    old['version'] = 'v99.0.0-a17-hyperos4-hongkong-r999'
                (root / 'local/installed-release.json').write_text(json.dumps(old))
                with patch.object(manage, 'validate_userdata'), \
                        patch.object(manage, 'data_size', return_value={'virtual-size': 32 * 1024**3}), \
                        patch('phone_profile.profile_from_build', side_effect=AssertionError('bootstrap registry used')):
                    if failure:
                        with self.assertRaises(RuntimeError), patch.object(manage.subprocess, 'run') as execute:
                            self.install(root, path)
                        execute.assert_not_called()
                    else:
                        self.install(root, path)
                self.assertEqual(userdata.read_bytes(), b'original personal userdata')
                self.assertEqual((root / 'executed').exists(), failure is None)

    def test_unknown_protocol_invalid_family_paths_types_and_minimum_refuse_before_execution(self):
        for case in ('protocol', 'family', 'runtime', 'entrypoint', 'traversal', 'alias', 'bool-size',
                     'part-path', 'part-duplicate', 'minimum'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                path, manifest = self.bundle(folder / 'bundle')
                if case == 'protocol':
                    manifest['compatibility']['install_protocol'] = 'future-unknown-v2'
                elif case == 'family':
                    manifest['compatibility']['userdata_family'] = setup.PAD_FAMILY
                elif case == 'runtime':
                    manifest['compatibility']['runtime_in_bundle'] = False
                elif case == 'entrypoint':
                    manifest['files']['runtime/execute.py'] = manifest['files'].pop(protocol.ENTRYPOINT)
                elif case == 'traversal':
                    manifest['files']['runtime/../untrusted.py'] = manifest['files'][protocol.ENTRYPOINT]
                elif case == 'alias':
                    manifest['files']['runtime//execute.py'] = manifest['files'][protocol.ENTRYPOINT]
                elif case == 'bool-size':
                    manifest['files'][protocol.ENTRYPOINT]['size'] = True
                elif case == 'part-path':
                    manifest['parts'][0]['name'] = '../bundle.part001'
                elif case == 'part-duplicate':
                    manifest['parts'].append(copy.deepcopy(manifest['parts'][0]))
                else:
                    manifest['compatibility']['minimum_installer'] = '1.2.2'
                path.write_text(json.dumps(manifest))
                with patch.object(manage.subprocess, 'run') as execute, self.assertRaises(RuntimeError):
                    self.install(folder / 'instance', path)
                execute.assert_not_called()
                self.assertFalse((folder / 'instance').exists())

    def test_archive_hash_failure_never_executes_release_code_or_changes_userdata(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path, manifest = self.bundle(folder / 'bundle')
            (folder / 'bundle' / manifest['parts'][0]['name']).write_bytes(b'corrupt archive')
            with patch.object(manage.subprocess, 'run') as execute, self.assertRaisesRegex(RuntimeError, 'checksum'):
                self.install(folder / 'instance', path)
            execute.assert_not_called()
            self.assertFalse((folder / 'instance/avd').exists())

    def test_cached_manifest_size_link_and_unlisted_source_tampering_block_handoff(self):
        for case in ('manifest', 'bytes', 'size', 'link', 'hardlink', 'source', 'bytecode-link', 'bytecode-fifo'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                path, manifest = self.bundle(folder / 'bundle')
                root = folder / 'instance'
                target = root / 'versions' / manifest['version']
                target.mkdir(parents=True)
                with manage.scope(target):
                    setup.stage_bundle(str(path))
                entry = target / protocol.ENTRYPOINT
                if case == 'manifest':
                    saved = target / 'local/installed-release.json'
                    value = json.loads(saved.read_text()); value['hyperos'] = '4.0.998.0.XFRCNXM'
                    saved.write_text(json.dumps(value))
                elif case == 'bytes':
                    entry.write_bytes(b'x' * entry.stat().st_size)
                elif case == 'size':
                    entry.write_bytes(entry.read_bytes() + b'\n')
                elif case == 'link':
                    copied = folder / 'copied.py'; copied.write_bytes(entry.read_bytes())
                    entry.unlink(); entry.symlink_to(copied)
                elif case == 'hardlink':
                    import os
                    os.link(entry, folder / 'aliased.py')
                elif case == 'source':
                    (target / 'runtime/scripts/injected.py').write_text('raise AssertionError()')
                elif case == 'bytecode-link':
                    cache = target / 'runtime/scripts/__pycache__'; cache.mkdir()
                    (cache / 'common.pyc').symlink_to(folder / 'untrusted')
                else:
                    import os
                    cache = target / 'runtime/scripts/__pycache__'; cache.mkdir()
                    os.mkfifo(cache / 'common.pyc')
                with patch.object(manage.subprocess, 'run') as execute, self.assertRaises(RuntimeError):
                    self.install(root, path)
                execute.assert_not_called()
                self.assertFalse((root / 'executed').exists())

    def test_timestamp_valid_unlisted_bytecode_blocks_handoff_before_userdata_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path, manifest = self.bundle(folder / 'bundle')
            root = folder / 'instance'; target = root / 'versions' / manifest['version']
            target.mkdir(parents=True)
            with manage.scope(target):
                setup.stage_bundle(str(path))
            marker = folder / 'bytecode-executed'
            self.poison_cache(target / 'runtime/scripts/common.py', marker)
            private = root / 'private-userdata'; private.write_bytes(b'personal userdata')
            with patch.object(manage.subprocess, 'run') as execute, \
                    self.assertRaisesRegex(RuntimeError, 'Unlisted bundle runtime'):
                self.install(root, path)
            execute.assert_not_called()
            self.assertEqual(private.read_bytes(), b'personal userdata')
            self.assertFalse(marker.exists())
            self.assertFalse((root / 'executed').exists())

    def test_cached_verified_handoff_stays_reusable_without_runtime_caches(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); path, manifest = self.bundle(folder / 'bundle')
            root = folder / 'instance'
            self.install(root, path)
            target = root / 'versions' / manifest['version']
            self.assertFalse(list((target / 'runtime').rglob('__pycache__')))
            (root / 'backups/verified-test').rmdir()
            self.install(root, path)
            protocol.verify_staged(target, manifest)
            self.assertFalse(list((target / 'runtime').rglob('*.pyc')))

    def test_normal_start_and_wrapper_ignore_poisoned_cache_and_write_no_runtime_bytecode(self):
        for wrapper in (False, True):
            with self.subTest(wrapper=wrapper), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); scripts = root / 'versions/test/runtime/scripts'
                scripts.mkdir(parents=True); (root / 'local').mkdir()
                (root / 'local/manager.json').write_text(json.dumps({'runtime': 'versions/test/runtime'}))
                source = scripts / 'common.py'; source.write_text("VALUE = 'verified source'\n")
                marker, observed = root / 'poison-executed', root / 'observed'
                cache = self.poison_cache(source, marker)
                # Prove this fixture is a usable timestamp-valid Python cache.
                env = os.environ.copy()
                for key in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONPYCACHEPREFIX'):
                    env.pop(key, None)
                subprocess.run([sys.executable, '-c', 'import common'], cwd=scripts,
                               env=env, check=True)
                self.assertTrue(marker.is_file()); marker.unlink()
                (scripts / 'launch.py').write_text("import common\nfrom pathlib import Path\n"
                    f"Path({str(observed)!r}).write_text(common.VALUE)\n")
                if wrapper:
                    manage.wrapper(root)
                    subprocess.run(['zsh', str(root / 'Start.command')], env=env, check=True)
                else:
                    manage.start({'root': root}, headless=True, skip_oobe=True)
                self.assertEqual(observed.read_text(), 'verified source')
                self.assertFalse(marker.exists())
                self.assertEqual(list(scripts.rglob('*.pyc')), [cache])
                self.assertFalse(list((root / 'local').glob('python-launch-*')))

    def test_setup_preserves_phone_and_pad_existing_hardware_and_camera_choices(self):
        for variant in ('os4-official', 'os4-pad'):
            for camera in (False, True):
                with self.subTest(variant=variant, camera=camera), tempfile.TemporaryDirectory() as directory:
                    folder = Path(directory); path, manifest = self.bundle(folder / 'bundle', variant)
                    root = folder / 'instance'; (root / 'local').mkdir(parents=True)
                    options = manage.hardware(8, 48, 2, variant=variant)
                    (root / 'local/build.json').write_text(json.dumps(manifest['build']))
                    (root / 'local/runtime.json').write_text(json.dumps({'name': 'Preserved_Name',
                        'port': 5590, 'hardware': options, 'camera_bridge': camera}))
                    with manage.scope(root), patch.dict(os.environ, {'HYPEROS_AVD_WORKSPACE': str(root)}), \
                            patch('sys.argv', ['setup.py', '--bundle', str(path)]), \
                            patch.object(setup, 'host_check'), patch.object(setup, 'port_free'), \
                            patch.object(setup, 'avd_home', return_value=folder / 'registry'), \
                            patch.object(setup, 'sdk_path', return_value=Path('/sdk')), \
                            patch('userdata_resize.check_dependencies'), \
                            patch.object(manage, 'install') as install, patch('sys.stdout', new_callable=io.StringIO):
                        setup.main()
                    self.assertEqual(install.call_args.args, (root.resolve(), str(path), 'Preserved_Name',
                                                             5590, Path('/sdk'), options))
                    self.assertEqual(install.call_args.kwargs, {'camera': camera})

    def test_child_validates_then_calls_transaction_directly_without_recursion(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path, manifest = self.bundle(folder / 'bundle')
            root = folder / 'instance'; target = root / 'versions' / manifest['version']
            target.mkdir(parents=True)
            with manage.scope(target):
                setup.stage_bundle(str(path))
            request, report = folder / 'request.json', folder / 'report.json'
            request.write_text(json.dumps({'schema': 1, 'protocol': protocol.INSTALL_PROTOCOL,
                'root': str(root), 'target': str(target), 'name': 'Custom_Name', 'port': 5584,
                'sdk': '/sdk', 'options': manage.hardware(6, 32, 4), 'camera': False,
                'manifest_sha256': protocol.manifest_digest(manifest)}))
            backup = root / 'backups/verified-test'
            with patch.object(setup, 'read_manifest', return_value=(manifest, target)), \
                    patch.object(protocol, 'validate_runtime_assets') as assets, \
                    patch.object(manage, 'install_transaction', return_value=backup) as transaction, \
                    patch.object(manage, 'install') as recursive:
                protocol.execute_request(request, report)
            transaction.assert_called_once()
            assets.assert_called_once_with(target.resolve())
            recursive.assert_not_called()
            self.assertEqual(json.loads(report.read_text())['backup'], str(backup))
            with self.assertRaises(RuntimeError), patch.object(manage, 'install_transaction') as transaction:
                protocol.execute_request(request, report)
            transaction.assert_not_called()
            with patch.object(setup, 'read_manifest', return_value=(manifest, target)), \
                    patch.object(protocol, 'validate_runtime_assets', side_effect=RuntimeError('catalog changed')), \
                    patch.object(manage, 'install_transaction') as transaction, \
                    self.assertRaisesRegex(RuntimeError, 'catalog changed'):
                protocol.execute_request(request, report)
            transaction.assert_not_called()

    def test_legacy_manifest_uses_unchanged_strict_reader_and_transaction(self):
        import test_manager
        with tempfile.TemporaryDirectory() as directory:
            path, manifest = test_manager.ManagerTests().bundle(Path(directory) / 'bundle')
            self.assertEqual(setup.read_install_manifest(str(path)), setup.read_manifest(str(path)))
            with patch.object(manage, 'install_transaction', return_value='legacy') as transaction, \
                    patch.object(manage, 'install_via_runtime') as handoff:
                self.assertEqual(manage.install(Path('/unused'), path, 'Custom_Name', 5584, Path('/sdk'), {}), 'legacy')
            transaction.assert_called_once()
            handoff.assert_not_called()

    def test_download_and_cli_accept_future_source_before_firmware_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); path, manifest = self.bundle(folder / 'bundle')
            part = manifest['parts'][0]
            assets = {'manifest.json': {'browser_download_url': path.as_uri(),
                'size': path.stat().st_size, 'digest': 'sha256:' + common.sha256(path)},
                part['name']: {'browser_download_url': (path.parent / part['name']).as_uri(),
                               'size': part['size']}}
            with patch('phone_profile.profile_from_build', side_effect=AssertionError('old registry used')), \
                    patch('sys.stdout', new_callable=io.StringIO):
                downloaded = manage.fetch_release({'tag_name': manifest['version'], 'asset_map': assets},
                                                  folder / 'cache')
            self.assertEqual(json.loads(downloaded.read_text()), manifest)
            arguments = ['manage.py', 'install', '--bundle', str(path), '--root', str(folder / 'instance'),
                         '--name', 'Custom_Name', '--port', '5584']
            with patch('sys.argv', arguments), patch.object(manage, 'host_check'), \
                    patch.object(manage, 'sdk_path', return_value=Path('/sdk')), \
                    patch('phone_profile.profile_from_build', side_effect=AssertionError('old registry used')), \
                    patch.object(manage, 'install') as install:
                manage.main()
            self.assertEqual(install.call_args.args[1], path.resolve())


if __name__ == '__main__':
    unittest.main()
