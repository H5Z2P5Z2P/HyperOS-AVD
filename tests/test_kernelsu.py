"""Consolidated unit tests for KernelSU subsystem:
ramdisk codec, LKM patch receipts, update applicator, and bootstrap integration.
"""
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from unittest.mock import patch
import zipfile

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import apply_flutter_fix
import apply_kernelsu_update as update
import build_os4_official as phone_builder
from common import KSU_ASSETS, KSU_VERSION
import kernelsu_release
import kernelsu_release as release
import ksu_ramdisk
import ksu_ramdisk as fixes
import launch
import package_release
from patch_boot_services import signing_block
import patch_kernelsu
import patch_kernelsu as ksu_fixes
from test_os4_pad import build_info



# --- tests/test_ksu_ramdisk.py ---

'Verify bounded offline ramdisk derivation and immutable local cache ownership.'

def cpio(items):
    output = bytearray()
    for index, (name, data, metadata) in enumerate([*items, (b'TRAILER!!!', b'', {})]):
        fields = [index + 100, 33261, 0, 0, 1, 1700000000, len(data), 0, 0, 0, 0, len(name) + 1, 0]
        for key, value in metadata.items():
            fields[key] = value
        output.extend(b'070701' + b''.join((f'{value:08x}'.encode() for value in fields)))
        output.extend(name + b'\x00')
        output.extend(b'\x00' * (-len(output) % 4))
        output.extend(data)
        output.extend(b'\x00' * (-len(output) % 4))
    return bytes(output)

class RamdiskCodecTests(unittest.TestCase):

    def test_literal_lz4_cross_block_boundary_and_simple_gzip_are_deterministic(self):
        data = b'x' * (fixes.MAX_LZ4_BLOCK + 7)
        for kind in ('cpio', 'lz4-legacy', 'gzip'):
            with self.subTest(kind=kind):
                output = fixes.pack(kind, data)
                if kind == 'cpio':
                    self.assertEqual(output, data)
                    continue
                self.assertEqual(fixes.unpack(output), (kind, data))
                self.assertEqual(output, fixes.pack(kind, data))
        encoded = fixes.pack('lz4-legacy', data)
        first = struct.unpack_from('<I', encoded, 4)[0]
        self.assertLessEqual(first, fixes.MAX_LZ4_BLOCK + fixes.MAX_LZ4_BLOCK // 255 + 16)
        self.assertGreater(len(encoded), 8 + first)

    def test_lz4_overlapping_match_expansion_has_normal_decoder_semantics(self):
        block = b'\x10A\x01\x00\x10Z'
        packed = fixes.LZ4_MAGIC + struct.pack('<I', len(block)) + block
        self.assertEqual(fixes.unpack(packed), ('lz4-legacy', b'AAAAAZ'))

    def test_lz4_corruption_and_expansion_bounds_are_rejected(self):
        malformed = [b'', b'\x10', b'\x10A\x00\x00\x00', b'\x10A\x02\x00\x00', b'\xf0\xff', b'\x10A\x01', b'\x11A']
        for block in malformed:
            packed = fixes.LZ4_MAGIC + struct.pack('<I', len(block)) + block
            with self.subTest(block=block), self.assertRaises(RuntimeError):
                fixes.unpack(packed)
        valid = fixes.pack('lz4-legacy', b'12345')
        for value in (valid[:-1], valid + b'x', fixes.LZ4_MAGIC, fixes.LZ4_MAGIC + b'\xff' * 4):
            with self.subTest(size=len(value)), self.assertRaises(RuntimeError):
                fixes.unpack(value)
        with patch.object(fixes, 'MAX_LZ4_BLOCK', 4):
            with self.assertRaisesRegex(RuntimeError, 'oversized'):
                fixes.unpack(valid)

    def test_gzip_trailer_optional_headers_multiple_members_and_size_bound_fail_closed(self):
        value = fixes.pack('gzip', b'0123456789')
        for bad in (value[:-1], value + value, value[:3] + b'\x08' + value[4:], value[:-8] + b'\x00' * 8):
            with self.subTest(size=len(bad)), self.assertRaises(RuntimeError):
                fixes.unpack(bad)
        with patch.object(fixes, 'MAX_RAMDISK', len(value)):
            compressed = __import__('gzip').compress(b'x' * 1024, mtime=0)
            with self.assertRaisesRegex(RuntimeError, 'Oversized'):
                fixes.unpack(compressed)

    def test_cpio_malformed_names_duplicate_entries_crc_and_trailing_archives_are_rejected(self):
        good = cpio([(b'other', b'data', {})])
        self.assertEqual(len(fixes.parse_cpio(good)), 2)
        variants = [good[:-1], good + good, good.replace(b'070701', b'070702', 1), cpio([(b'../escape', b'', {})]), cpio([(b'/absolute', b'', {})]), cpio([(b'dup', b'1', {}), (b'dup', b'2', {})]), cpio([(b'dup', b'1', {}), (b'./dup', b'2', {})]), cpio([(b'bad\x00name', b'', {})])]
        for bad in variants:
            with self.subTest(size=len(bad)), self.assertRaises(RuntimeError):
                fixes.parse_cpio(bad)
        self.assertEqual(fixes.parse_cpio(good + b'\x00' * 512), fixes.parse_cpio(good))

class RamdiskArtifactFixture:

    @classmethod
    def setUpClass(cls):
        path = REPO / 'tools' / patch_kernelsu.ASSET
        if not path.is_file():
            raise unittest.SkipTest('Official KernelSU asset is not cached.')
        cls.module = path.read_bytes()
        patch_kernelsu.audit(cls.module)

    def archive(self, member=None, metadata=None, extra=None):
        items = [(b'init', b'original init bytes', {5: 123, 0: 700}), (b'symlink', b'init', {1: 41471, 0: 701}), (fixes.MEMBER, self.module if member is None else member, metadata or {})]
        if extra:
            items.extend(extra)
        return cpio(items)

class RamdiskArtifactTests(RamdiskArtifactFixture, unittest.TestCase):

    def test_only_four_member_bytes_change_all_archive_metadata_and_other_entries_stay_exact(self):
        archive = self.archive()
        for kind in ('cpio', 'lz4-legacy', 'gzip'):
            with self.subTest(kind=kind):
                output, marker = fixes.patch_ramdisk(fixes.pack(kind, archive))
                _, after = fixes.unpack(output)
                self.assertEqual(fixes.parse_cpio(after), fixes.parse_cpio(archive))
                start = marker['member_offset'] + patch_kernelsu.audit(self.module)['offset']
                self.assertEqual(archive[:start], after[:start])
                self.assertEqual(archive[start + 4:], after[start + 4:])
                self.assertEqual(after[start:start + 4], patch_kernelsu.BRANCH)
                self.assertEqual(marker['recipe'], patch_kernelsu.receipt())
                self.assertEqual(fixes.patch_ramdisk(output)[0], None)

    def test_unknown_owned_module_links_permissions_aliases_and_absence_are_preserved(self):
        variants = [self.archive(member=b'unknown module'), self.archive(metadata={4: 2}), self.archive(metadata={2: 2000}), self.archive(metadata={1: 41471}), self.archive(extra=[(b'alias.ko', self.module, {})]), self.archive(extra=[(b'inode-alias', b'', {0: 102, 4: 2})]), cpio([(b'init', b'init', {})])]
        for bad in variants:
            with self.subTest(size=len(bad)), self.assertRaises(RuntimeError):
                fixes.patch_ramdisk(bad)

    def test_real_daily_frozen_input_and_complete_cpio_diff(self):
        path = REPO / 'work/os4-official/images/ramdisk.img'
        if not path.is_file():
            self.skipTest('Daily frozen OS4 ramdisk is not present.')
        original = path.read_bytes()
        expected = 'a87375eff541d658c1b27562a23c785c6d241ba5788eab6a1ceaaa25c748585e'
        if hashlib.sha256(original).hexdigest() != expected:
            self.skipTest('Daily ramdisk changed; the historical real-input fixture is unavailable.')
        output, marker = fixes.patch_ramdisk(original)
        self.assertEqual(marker['output_sha256'], '73eb1206806a2b282328195c1a53bd0d2567dad3c5924181e31b87f0c96c7e00')
        self.assertEqual(marker['output_size'], 4481427)
        _, before = fixes.unpack(original)
        _, after = fixes.unpack(output)
        self.assertEqual(len(before), 4463912)
        self.assertEqual(fixes.parse_cpio(before), fixes.parse_cpio(after))
        entries = fixes.parse_cpio(before)
        self.assertEqual(len(entries), 32)
        for entry in entries:
            start, end = (entry['offset'], entry['end'])
            if entry['name'] == fixes.MEMBER:
                body = entry['body']
                self.assertEqual(before[start:body], after[start:body])
                self.assertEqual(patch_kernelsu.audit(after[body:body + entry['size']])['sha256'], patch_kernelsu.AFTER)
            else:
                self.assertEqual(before[start:end], after[start:end])
        self.assertEqual(path.read_bytes(), original)

class CurrentRamdiskArtifactTests(RamdiskArtifactFixture, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            cls.current_path = kernelsu_release.asset(REPO, kernelsu_release.LKM)
        except (RuntimeError, OSError) as error:
            raise unittest.SkipTest('Current official KernelSU asset is not cached: ' + str(error))
        cls.current = cls.current_path.read_bytes()
        cls.quiet_current = patch_kernelsu.patch_bytes(cls.current)

    def configured_archive(self, member=None, config=b'allow_shell=1'):
        return self.archive(member=member, extra=[(b'ksu_config', config, {1: 33188})])

    def test_current_replacement_updates_only_member_size_body_padding_and_keeps_config(self):
        before = self.configured_archive()
        for kind in ('cpio', 'lz4-legacy', 'gzip'):
            with self.subTest(kind=kind):
                output, marker = fixes.patch_ramdisk(fixes.pack(kind, before), target=self.current)
                _, after = fixes.unpack(output)
                old_entries, new_entries = (fixes.parse_cpio(before), fixes.parse_cpio(after))
                self.assertEqual([item['name'] for item in old_entries], [item['name'] for item in new_entries])
                for old, new in zip(old_entries, new_entries):
                    if old['name'] == fixes.MEMBER:
                        self.assertEqual(new['size'], 330664)
                        self.assertEqual(old['size'], 315176)
                        self.assertEqual(after[new['body']:new['body'] + new['size']], self.quiet_current)
                        self.assertEqual(old['fields'][:6] + old['fields'][7:], new['fields'][:6] + new['fields'][7:])
                    else:
                        self.assertEqual(before[old['offset']:old['end']], after[new['offset']:new['end']])
                self.assertEqual(marker['schema'], 2)
                self.assertEqual(marker['target_release'], kernelsu_release.VERSION)
                self.assertEqual(marker['target_official_sha256'], kernelsu_release.ASSETS[kernelsu_release.LKM])
                self.assertEqual(marker['target_quiet_sha256'], hashlib.sha256(self.quiet_current).hexdigest())
                self.assertEqual(marker['original_config'], {'sha256': hashlib.sha256(b'allow_shell=1').hexdigest(), 'parameters': ['allow_shell']})
                self.assertIsNone(fixes.patch_ramdisk(output, target=self.current)[0])

    def test_old_quiet_source_can_upgrade_and_new_official_source_can_be_quieted(self):
        for member in (patch_kernelsu.patch_bytes(self.module), self.current):
            with self.subTest(source=hashlib.sha256(member).hexdigest()):
                source = self.configured_archive(member=member)
                output, marker = fixes.patch_ramdisk(source, target=self.current)
                _, archive = fixes.unpack(output)
                entry = next((item for item in fixes.parse_cpio(archive) if item['name'] == fixes.MEMBER))
                self.assertEqual(archive[entry['body']:entry['body'] + entry['size']], self.quiet_current)
                self.assertEqual(marker['input_member_sha256'], hashlib.sha256(member).hexdigest())

    def test_custom_config_unknown_targets_and_current_lkm_aliases_refuse_upgrade(self):
        for config in (b'allow_shell=1 unknown=1', b'allow_shell=1 allow_shell=0', b'allow_shell=custom'):
            with self.subTest(config=config), self.assertRaisesRegex(RuntimeError, 'config'):
                fixes.patch_ramdisk(self.configured_archive(config=config), target=self.current)
        with self.assertRaises(RuntimeError):
            fixes.patch_ramdisk(self.configured_archive(), target=b'unknown replacement')
        with self.assertRaisesRegex(RuntimeError, 'extra KernelSU LKM alias'):
            fixes.patch_ramdisk(self.archive(extra=[(b'other-module', self.current, {})]), target=self.current)

    def test_real_phone_and_pad_sources_keep_all_non_lkm_entries_and_loaded_source_bytes(self):
        for name in ('os4-official', 'os4-pad'):
            path = REPO / 'work' / name / 'images/ramdisk.img'
            if not path.is_file():
                continue
            with self.subTest(workspace=name):
                source, stat = (path.read_bytes(), path.stat())
                output, marker = fixes.patch_ramdisk(source, target=self.current)
                self.assertIsNotNone(output)
                self.assertEqual(marker['original_config']['parameters'], ['allow_shell'])
                self.assertEqual(path.read_bytes(), source)
                self.assertEqual((path.stat().st_ino, path.stat().st_mtime_ns), (stat.st_ino, stat.st_mtime_ns))

class RamdiskRuntimeCacheTests(RamdiskArtifactFixture, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        kernel = REPO / 'work/os4-official/images/kernel-ranchu'
        if not kernel.is_file():
            raise unittest.SkipTest('Audited ranchu kernel is not cached.')
        cls.kernel = kernel.read_bytes()
        if hashlib.sha256(cls.kernel).hexdigest() != fixes.KERNEL_SHA256:
            raise unittest.SkipTest('Audited ranchu kernel fixture is unavailable.')

    def workspace(self, folder):
        workspace = Path(folder) / 'Renamed workspace'
        (workspace / 'local').mkdir(parents=True)
        (workspace / 'version/images').mkdir(parents=True)
        (workspace / 'images').symlink_to('version/images', target_is_directory=True)
        (workspace / 'local/build.json').write_text(json.dumps({'hyperos': 'OS4.0.999.0.XBMCNXM', 'android_api': 37, 'kernel_page_size': 4096, 'hardware_base_api': 36}))
        (workspace / 'images/source.properties').write_text('SystemImage.Abi=arm64-v8a\nAndroidVersion.ApiLevel=36\n')
        (workspace / 'images/kernel-ranchu').write_bytes(self.kernel)
        (workspace / 'images/ramdisk.img').write_bytes(fixes.pack('lz4-legacy', self.archive()))
        return workspace.resolve()

    def quiet_prepare(self, workspace):
        with redirect_stdout(io.StringIO()) as text:
            result = fixes.prepare_runtime(workspace)
        return (result, text.getvalue())

    def frozen_source(self, workspace, version='v0.2.2-a17-hyperos4-hongkong-r3'):
        source = workspace / 'versions' / version
        (source / 'local').mkdir(parents=True)
        (source / 'images').mkdir()
        (source / 'local/build.json').write_bytes((workspace / 'local/build.json').read_bytes())
        files = {}
        for name in ('kernel-ranchu', 'ramdisk.img', 'source.properties'):
            data = (workspace / 'images' / name).read_bytes()
            (source / 'images' / name).write_bytes(data)
            files['images/' + name] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        (source / 'local/installed-release.json').write_text(json.dumps({'project': 'HyperOS-AVD', 'version': version, 'files': files}))
        (workspace / 'local/manager.json').write_text(json.dumps({'schema': 1, 'version': version, 'runtime': 'versions/' + version + '/runtime'}))
        return source

    def current_stack(self):
        try:
            path = kernelsu_release.asset(REPO, kernelsu_release.LKM)
        except (RuntimeError, OSError) as error:
            self.skipTest('Current official KernelSU fixture is unavailable: ' + str(error))
        return (patch.object(kernelsu_release, 'available', return_value=True), patch.object(kernelsu_release, 'asset', return_value=path))

    def test_current_offline_stack_upgrades_legacy_cache_but_legacy_receipt_still_verifies(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            legacy, _ = self.quiet_prepare(workspace)
            before = {path: (path.read_bytes(), path.stat().st_ino) for path in (legacy, legacy.with_suffix('.json'), workspace / 'images/ramdisk.img')}
            available, asset = self.current_stack()
            with available, asset:
                current, message = self.quiet_prepare(workspace)
                self.assertIsNotNone(current, message)
                self.assertNotEqual(current, legacy)
                self.assertEqual(fixes.verify_cache(workspace, legacy), legacy)
                self.assertEqual(fixes.verify_cache(workspace, current), current)
                self.assertEqual(json.loads(current.with_suffix('.json').read_text())['target_release'], kernelsu_release.VERSION)
            self.assertEqual(fixes.verify_cache(workspace, current), current)
            self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_ino) for path in before})

    def test_saved_current_target_receipt_reproduces_frozen_source_and_refreshes_after_image_switch(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            available, asset = self.current_stack()
            with available, asset:
                old, _ = self.quiet_prepare(workspace)
                self.frozen_source(workspace)
                original = (old.read_bytes(), old.with_suffix('.json').read_bytes())
                (workspace / 'images/ramdisk.img').write_bytes(fixes.pack('gzip', self.archive()))
                self.assertEqual(fixes.verify_saved_cache(workspace, old), old)
                current = fixes.refresh_saved_cache(workspace, old)
                self.assertNotEqual(current, old)
                self.assertEqual(fixes.verify_cache(workspace, current), current)
                self.assertEqual(original, (old.read_bytes(), old.with_suffix('.json').read_bytes()))

    def test_current_cache_recipe_pin_config_proof_and_directory_alias_tampering_are_rejected(self):
        for change in ('pin', 'recipe', 'config'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                workspace = self.workspace(folder)
                available, asset = self.current_stack()
                with available, asset:
                    current, _ = self.quiet_prepare(workspace)
                receipt = current.with_suffix('.json')
                marker = json.loads(receipt.read_text())
                if change == 'pin':
                    marker['target_official_sha256'] = '0' * 64
                elif change == 'recipe':
                    marker['recipe']['version'] = 'v999'
                else:
                    marker['original_config'] = {'sha256': '0' * 64, 'parameters': ['unknown']}
                changed = fixes._marker_bytes(marker)
                receipt.write_bytes(changed)
                with self.assertRaises(RuntimeError):
                    fixes.verify_cache(workspace, current)
                self.assertEqual(receipt.read_bytes(), changed)

    def test_partial_current_offline_stack_never_downloads_or_rewrites_the_source(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            source = workspace / 'images/ramdisk.img'
            original = source.read_bytes()
            directory = workspace / 'tools' / kernelsu_release.DIRECTORY
            directory.mkdir(parents=True)
            (directory / kernelsu_release.LKM).write_bytes(b'partial current stack')
            with patch.object(kernelsu_release, 'fetch') as download:
                result, message = self.quiet_prepare(workspace)
            self.assertIsNone(result)
            self.assertIn('original image retained', message)
            download.assert_not_called()
            self.assertEqual(source.read_bytes(), original)
            self.assertFalse((workspace / 'local/boot-patches').exists())
            with self.assertRaisesRegex(RuntimeError, 'existing selection was retained'):
                fixes.prepare_runtime(workspace, strict=True)

    def test_new_current_target_cache_rebase_is_bound_to_absent_previous_workspace(self):
        with tempfile.TemporaryDirectory() as folder:
            previous = self.workspace(folder)
            available, asset = self.current_stack()
            with available, asset:
                current, _ = self.quiet_prepare(previous)
            old_images = str(previous / 'images') + '/'
            workspace = previous.with_name('Moved current workspace')
            previous.rename(workspace)
            relocated = workspace / current.relative_to(previous)
            original = (relocated.read_bytes(), relocated.with_suffix('.json').read_bytes())
            self.assertEqual(fixes.rebase_cache_selection(workspace, current, old_images), relocated)
            self.assertEqual(original, (relocated.read_bytes(), relocated.with_suffix('.json').read_bytes()))

    def test_stale_owned_cache_refresh_authenticates_one_saved_source_and_preserves_old_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            old_cache, _ = self.quiet_prepare(workspace)
            source = self.frozen_source(workspace)
            before = {path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns) for path in (*source.rglob('*'), old_cache, old_cache.with_suffix('.json')) if path.is_file()}
            current = workspace / 'images/ramdisk.img'
            current.write_bytes(fixes.pack('gzip', self.archive()))
            selected = fixes.refresh_saved_cache(workspace, old_cache)
            self.assertNotEqual(selected, old_cache)
            self.assertEqual(fixes.verify_cache(workspace, selected), selected)
            self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns) for path in before})
            self.assertEqual(current.read_bytes(), fixes.pack('gzip', self.archive()))

    def test_stale_cache_can_clear_override_only_for_an_authenticated_prepatched_current_source(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            old_cache, _ = self.quiet_prepare(workspace)
            self.frozen_source(workspace, version='pad-v0.1.1-a17-hyperos4-yingtian-r2')
            (workspace / 'images/ramdisk.img').write_bytes(self.archive(member=patch_kernelsu.patch_bytes(self.module)))
            self.assertIsNone(fixes.refresh_saved_cache(workspace, old_cache))
            self.assertTrue(old_cache.is_file())
            self.assertTrue(old_cache.with_suffix('.json').is_file())

    def test_stale_cache_missing_modified_and_aliased_provenance_is_refused_without_writes(self):
        for change in ('missing-manager', 'version-traversal', 'manifest-hash', 'old-source', 'kernel', 'receipt', 'cache', 'source-directory-alias'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                workspace = self.workspace(folder)
                old_cache, _ = self.quiet_prepare(workspace)
                source = self.frozen_source(workspace)
                (workspace / 'images/ramdisk.img').write_bytes(fixes.pack('gzip', self.archive()))
                if change == 'missing-manager':
                    (workspace / 'local/manager.json').unlink()
                elif change == 'version-traversal':
                    (workspace / 'local/manager.json').write_text(json.dumps({'schema': 1, 'version': '../escape'}))
                elif change == 'manifest-hash':
                    manifest_path = source / 'local/installed-release.json'
                    manifest = json.loads(manifest_path.read_text())
                    manifest['files']['images/ramdisk.img']['sha256'] = '0' * 64
                    manifest_path.write_text(json.dumps(manifest))
                elif change == 'old-source':
                    (source / 'images/ramdisk.img').write_bytes(b'unknown previous source')
                elif change == 'kernel':
                    (workspace / 'images/kernel-ranchu').write_bytes(b'unknown current kernel')
                elif change == 'receipt':
                    old_cache.with_suffix('.json').write_bytes(b'unknown receipt')
                elif change == 'cache':
                    old_cache.write_bytes(b'unknown cache')
                else:
                    original = source / 'images'
                    original.rename(source / 'saved-images')
                    original.symlink_to('saved-images', target_is_directory=True)
                before = {path.name: path.read_bytes() for path in old_cache.parent.iterdir()}
                with self.assertRaises((RuntimeError, OSError)):
                    fixes.refresh_saved_cache(workspace, old_cache)
                self.assertEqual(before, {path.name: path.read_bytes() for path in old_cache.parent.iterdir()})

    def test_stale_refresh_does_not_fallback_when_current_destination_is_unknown_or_preparation_skips(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            old_cache, _ = self.quiet_prepare(workspace)
            self.frozen_source(workspace)
            (workspace / 'images/ramdisk.img').write_bytes(fixes.pack('gzip', self.archive()))
            target, _ = self.quiet_prepare(workspace)
            target.write_bytes(b'unknown target cache')
            with self.assertRaisesRegex(RuntimeError, 'refresh failed'):
                fixes.refresh_saved_cache(workspace, old_cache)
            self.assertEqual(target.read_bytes(), b'unknown target cache')
            with patch.object(fixes, 'prepare_runtime', return_value=None), self.assertRaisesRegex(RuntimeError, 'existing selection was retained'):
                fixes.refresh_saved_cache(workspace, old_cache)

    def test_reserved_cache_locator_is_generic_and_does_not_follow_foreign_custom_selections(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            self.assertTrue(fixes.is_owned_cache_selection(workspace, workspace / 'local/boot-patches' / ('ramdisk-' + 'a' * 64 + '.img')))
            for path in (workspace / 'user/custom.img', workspace / 'local/boot-patches/custom.img', workspace / 'local/boot-patches' / ('ramdisk-' + 'a' * 64 + '.img/extra')):
                self.assertFalse(fixes.is_owned_cache_selection(workspace, path))

    def test_moved_workspace_cache_rebase_uses_previous_image_binding_and_exact_current_proof(self):
        with tempfile.TemporaryDirectory() as folder:
            previous = self.workspace(folder)
            old_cache, _ = self.quiet_prepare(previous)
            old_images = str(previous / 'images') + '/'
            workspace = previous.with_name('Moved workspace')
            previous.rename(workspace)
            relocated = workspace / old_cache.relative_to(previous)
            before = (relocated.read_bytes(), relocated.stat().st_ino, relocated.stat().st_mtime_ns)
            self.assertEqual(fixes.rebase_cache_selection(workspace, old_cache, old_images), relocated)
            self.assertEqual(before, (relocated.read_bytes(), relocated.stat().st_ino, relocated.stat().st_mtime_ns))

    def test_moved_stale_cache_rebase_requires_saved_frozen_source_before_refresh(self):
        with tempfile.TemporaryDirectory() as folder:
            previous = self.workspace(folder)
            old_cache, _ = self.quiet_prepare(previous)
            self.frozen_source(previous)
            (previous / 'images/ramdisk.img').write_bytes(fixes.pack('gzip', self.archive()))
            workspace = previous.with_name('Moved workspace')
            previous.rename(workspace)
            selected = fixes.rebase_cache_selection(workspace, old_cache, str(previous / 'images'))
            self.assertEqual(selected, workspace / old_cache.relative_to(previous))
            current = fixes.refresh_saved_cache(workspace, selected)
            self.assertNotEqual(current, selected)
            self.assertEqual(fixes.verify_cache(workspace, current), current)

    def test_rebase_refuses_copy_foreign_binding_arbitrary_basename_and_modified_receipt(self):
        for change in ('old-still-exists', 'foreign-binding', 'custom-name', 'traversal-binding', 'tampered-cache', 'tampered-receipt', 'dangling-old-alias'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                previous = self.workspace(folder)
                old_cache, _ = self.quiet_prepare(previous)
                workspace = previous.with_name('Moved workspace')
                previous.rename(workspace)
                selected, binding = (old_cache, str(previous / 'images'))
                relocated = workspace / old_cache.relative_to(previous)
                if change == 'old-still-exists':
                    previous.mkdir()
                elif change == 'foreign-binding':
                    binding = str(Path(folder) / 'foreign/images')
                elif change == 'custom-name':
                    selected = old_cache.with_name('custom.img')
                elif change == 'traversal-binding':
                    binding = str(previous) + '/sub/../images'
                elif change == 'tampered-cache':
                    relocated.write_bytes(b'unknown current cache')
                elif change == 'tampered-receipt':
                    relocated.with_suffix('.json').write_bytes(b'unknown current receipt')
                else:
                    previous.symlink_to(Path(folder) / 'missing-workspace')
                before = {path.name: path.read_bytes() for path in relocated.parent.iterdir()}
                with self.assertRaises((RuntimeError, OSError)):
                    fixes.rebase_cache_selection(workspace, selected, binding)
                self.assertEqual(before, {path.name: path.read_bytes() for path in relocated.parent.iterdir()})

    def test_runtime_cache_preserves_frozen_leaf_and_authenticates_repeat_read_only(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            source = workspace / 'images/ramdisk.img'
            before, info = (source.read_bytes(), source.stat())
            result, message = self.quiet_prepare(workspace)
            self.assertIsNotNone(result, message)
            self.assertIn('separate local ramdisk', message)
            self.assertEqual(result.parent, workspace / 'local/boot-patches')
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual((source.stat().st_ino, source.stat().st_mtime_ns), (info.st_ino, info.st_mtime_ns))
            all_before = {p.name: (p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes()) for p in result.parent.iterdir()}
            self.assertEqual(fixes.verify_cache(workspace, result), result)
            self.assertEqual(self.quiet_prepare(workspace)[0], result)
            all_after = {p.name: (p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes()) for p in result.parent.iterdir()}
            self.assertEqual(all_before, all_after)

    def test_unknown_kernel_abi_page_size_build_and_ramdisk_skip_without_writes(self):
        for change in ('kernel', 'abi', 'page-size', 'build', 'module'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                workspace = self.workspace(folder)
                if change == 'kernel':
                    (workspace / 'images/kernel-ranchu').write_bytes(b'unknown kernel')
                elif change == 'abi':
                    (workspace / 'images/source.properties').write_text('SystemImage.Abi=x86_64\nAndroidVersion.ApiLevel=36\n')
                elif change in ('page-size', 'build'):
                    path = workspace / 'local/build.json'
                    data = json.loads(path.read_text())
                    data['kernel_page_size' if change == 'page-size' else 'hyperos'] = 16384 if change == 'page-size' else '3.0.0.0.UNKNOWN'
                    path.write_text(json.dumps(data))
                else:
                    (workspace / 'images/ramdisk.img').write_bytes(self.archive(member=b'custom'))
                before = (workspace / 'images/ramdisk.img').read_bytes()
                result, message = self.quiet_prepare(workspace)
                self.assertIsNone(result)
                self.assertIn('original image retained', message)
                self.assertFalse((workspace / 'local/boot-patches').exists())
                self.assertEqual((workspace / 'images/ramdisk.img').read_bytes(), before)

    def test_modified_receipt_image_stale_input_and_unexpected_cache_path_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            path, _ = self.quiet_prepare(workspace)
            receipt = path.with_suffix('.json')
            original_receipt, original_image = (receipt.read_bytes(), path.read_bytes())
            receipt.write_bytes(b'user receipt')
            self.assertIsNone(self.quiet_prepare(workspace)[0])
            with self.assertRaisesRegex(RuntimeError, 'unknown or modified.*receipt'):
                fixes.verify_cache(workspace, path)
            self.assertEqual(receipt.read_bytes(), b'user receipt')
            receipt.write_bytes(original_receipt)
            path.write_bytes(b'user image')
            self.assertIsNone(self.quiet_prepare(workspace)[0])
            self.assertEqual(path.read_bytes(), b'user image')
            path.write_bytes(original_image)
            with self.assertRaisesRegex(RuntimeError, 'authenticated local cache path'):
                fixes.verify_cache(workspace, path.parent / 'wrong.img')
            source = workspace / 'images/ramdisk.img'
            source.write_bytes(fixes.pack('gzip', self.archive()))
            with self.assertRaisesRegex(RuntimeError, 'authenticated local cache path'):
                fixes.verify_cache(workspace, path)

    def test_symlink_hardlink_and_cache_parent_alias_are_retained_with_clear_skip(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            source = workspace / 'images/ramdisk.img'
            saved = source.read_bytes()
            source.unlink()
            other = Path(folder) / 'other.img'
            other.write_bytes(saved)
            source.symlink_to(other)
            self.assertIsNone(self.quiet_prepare(workspace)[0])
            source.unlink()
            source.write_bytes(saved)
            os.link(source, Path(folder) / 'alias.img')
            self.assertIsNone(self.quiet_prepare(workspace)[0])
            (Path(folder) / 'alias.img').unlink()
            target = Path(folder) / 'external-cache'
            target.mkdir()
            (workspace / 'local/boot-patches').symlink_to(target, target_is_directory=True)
            self.assertIsNone(self.quiet_prepare(workspace)[0])
            self.assertEqual(list(target.iterdir()), [])

    def test_publish_does_not_clobber_a_racing_unknown_leaf(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'output.img'
            real_link = os.link

            def raced(source, destination):
                Path(destination).write_bytes(b'unknown racing output')
                return real_link(source, destination)
            with patch.object(fixes.os, 'link', side_effect=raced):
                with self.assertRaisesRegex(RuntimeError, 'unexpectedly created'):
                    fixes._publish(path, b'expected')
            self.assertEqual(path.read_bytes(), b'unknown racing output')
            self.assertEqual([p.name for p in Path(folder).iterdir()], ['output.img'])

    def test_prepatched_original_needs_no_override_or_cache(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            source = workspace / 'images/ramdisk.img'
            source.write_bytes(self.archive(member=patch_kernelsu.patch_bytes(self.module)))
            result, message = self.quiet_prepare(workspace)
            self.assertIsNone(result)
            self.assertIn('already contains', message)
            self.assertFalse((workspace / 'local/boot-patches').exists())

if __name__ == '__main__':
    unittest.main()


# --- tests/test_patch_kernelsu.py ---

'Check the exact KernelSU task-scan derivative without a guest or compiler.'

class KernelSUUnknownInputTests(unittest.TestCase):

    def test_unknown_input_does_not_create_output_or_replace_existing_data(self):
        with tempfile.TemporaryDirectory() as folder:
            source, output = (Path(folder) / 'source.ko', Path(folder) / 'new/output.ko')
            source.write_bytes(b'unknown ELF')
            with self.assertRaisesRegex(RuntimeError, 'Unsupported KernelSU'):
                patch_kernelsu.patch(source, output)
            self.assertFalse(output.parent.exists())
            output.parent.mkdir()
            output.write_bytes(b'user customized output')
            with self.assertRaisesRegex(RuntimeError, 'Unsupported KernelSU'):
                patch_kernelsu.patch(source, output)
            self.assertEqual(output.read_bytes(), b'user customized output')

    def test_exact_official_asset_pin_remains_the_download_authority(self):
        self.assertEqual(patch_kernelsu.BEFORE, KSU_ASSETS[patch_kernelsu.ASSET])
        self.assertEqual(patch_kernelsu.BEFORE, 'c31d994aaf285e7bf4cf1ec38c2bbf2d7f303d1a4a7d616405bcd9f850d684e5')
        self.assertNotEqual(patch_kernelsu.AFTER, patch_kernelsu.BEFORE)
        self.assertEqual(patch_kernelsu.receipt()['source_review_commit'], '932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e')
        self.assertNotIn('source_build_commit', patch_kernelsu.receipt())

    def test_current_receipt_uses_canonical_release_and_keeps_legacy_default(self):
        before = kernelsu_release.ASSETS[patch_kernelsu.ASSET]
        current = patch_kernelsu.receipt(before)
        self.assertEqual(current['before'], before)
        self.assertEqual(current['version'], kernelsu_release.VERSION)
        self.assertEqual(current['source_review_commit'], kernelsu_release.REVIEW_COMMIT)
        self.assertEqual(current['source_review_commit'], '0c0fdb960178fa12d80d6cbcfdcb6ad8be6a865d')
        self.assertEqual((current['site'], current['resume']), (8668, 8684))
        self.assertEqual(patch_kernelsu.receipt()['before'], patch_kernelsu.BEFORE)
        self.assertEqual(patch_kernelsu.receipt()['after'], patch_kernelsu.AFTER)
        self.assertEqual(patch_kernelsu.receipt(current['after']), current)
        self.assertNotIn('source_build_commit', current)
        for value in (b'unknown', 'unknown', True, 1, {}, []):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, 'Unsupported KernelSU'):
                    patch_kernelsu.receipt(value)

class KernelSUArtifactTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        source = REPO / 'tools' / patch_kernelsu.ASSET
        if not source.is_file():
            raise unittest.SkipTest('Official KernelSU asset is not cached.')
        cls.original = source.read_bytes()
        if hashlib.sha256(cls.original).hexdigest() != patch_kernelsu.BEFORE:
            raise AssertionError('Cached official KernelSU module was modified.')
        cls.modified = patch_kernelsu.patch_bytes(cls.original)

    def test_the_only_changed_instruction_branches_to_existing_credential_cleanup(self):
        audit = patch_kernelsu.audit(self.original)
        offset = audit['offset']
        self.assertEqual(offset, 29028)
        self.assertEqual(self.original[offset:offset + 4], patch_kernelsu.ORIGINAL)
        self.assertEqual(self.modified[offset:offset + 4], patch_kernelsu.BRANCH)
        self.assertEqual(self.original[:offset], self.modified[:offset])
        self.assertEqual(self.original[offset + 4:], self.modified[offset + 4:])
        instruction = struct.unpack_from('<I', self.modified, offset)[0]
        self.assertEqual(instruction >> 26, 5)
        self.assertEqual(patch_kernelsu.SITE + (instruction & 67108863) * 4, patch_kernelsu.RESUME)
        self.assertEqual(self.modified[29044:29052], bytes.fromhex('13faffb405000014'))
        self.assertEqual(hashlib.sha256(self.modified).hexdigest(), patch_kernelsu.AFTER)

    def test_all_relocations_symbols_strings_permissions_and_locks_are_preserved(self):
        header = struct.unpack_from('<16sHHIQQQIHHHHHH', self.original)
        sections = [struct.unpack_from('<IIQQQQIIQQ', self.original, header[6] + i * 64) for i in range(header[12])]
        relocation_count = 0
        for section in sections:
            if section[1] not in (2, 3, 4):
                continue
            offset, size = section[4:6]
            self.assertEqual(self.original[offset:offset + size], self.modified[offset:offset + size])
            if section[1] == 4:
                relocation_count += size // section[9]
        self.assertGreater(relocation_count, 4000)
        self.assertEqual(self.modified[29000:29028], self.original[29000:29028])
        self.assertEqual(self.modified[28712:29000], self.original[28712:29000])
        self.assertEqual(self.modified[29044:29196], self.original[29044:29196])
        self.assertEqual(self.modified[29200:29952], self.original[29200:29952])

    def test_after_is_idempotent_and_unknown_partial_or_tampered_content_is_refused(self):
        self.assertTrue(patch_kernelsu.audit(self.modified)['patched'])
        self.assertIs(patch_kernelsu.patch_bytes(self.modified), self.modified)
        variants = [self.original[:-1], self.original + b'\x00', b'', bytearray(self.original)]
        for offset in (0, 29028, 159448, len(self.original) - 1):
            value = bytearray(self.original)
            value[offset] ^= 1
            variants.append(bytes(value))
        for data in variants:
            with self.subTest(size=len(data)):
                with self.assertRaisesRegex(RuntimeError, 'Unsupported KernelSU'):
                    patch_kernelsu.patch_bytes(data)

    def test_atomic_output_preserves_official_asset_and_reuses_verified_output(self):
        with tempfile.TemporaryDirectory() as folder:
            source, output = (Path(folder) / 'source.ko', Path(folder) / 'derivative.ko')
            source.write_bytes(self.original)
            source_before = source.stat()
            with patch.object(patch_kernelsu, 'tempfile', wraps=patch_kernelsu.tempfile) as temporary:
                self.assertEqual(patch_kernelsu.patch(source, output), output)
                temporary.mkstemp.assert_called_once()
            self.assertEqual(source.read_bytes(), self.original)
            self.assertEqual((source.stat().st_ino, source.stat().st_mtime_ns), (source_before.st_ino, source_before.st_mtime_ns))
            self.assertEqual(output.read_bytes(), self.modified)
            original_inode = output.stat().st_ino
            with patch.object(patch_kernelsu.tempfile, 'mkstemp') as create:
                patch_kernelsu.patch(source, output)
                create.assert_not_called()
            self.assertEqual(output.stat().st_ino, original_inode)
            self.assertEqual(sorted((item.name for item in Path(folder).iterdir())), ['derivative.ko', 'source.ko'])

    def test_source_overwrite_custom_output_links_and_aliases_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            source, output = (Path(folder) / 'source.ko', Path(folder) / 'derivative.ko')
            source.write_bytes(self.original)
            with self.assertRaisesRegex(RuntimeError, 'official KernelSU source'):
                patch_kernelsu.patch(source, source)
            output.write_bytes(b'custom')
            with self.assertRaisesRegex(RuntimeError, 'unknown KernelSU derivative'):
                patch_kernelsu.patch(source, output)
            self.assertEqual(output.read_bytes(), b'custom')
            output.unlink()
            output.symlink_to(source)
            with self.assertRaisesRegex(RuntimeError, 'official KernelSU source'):
                patch_kernelsu.patch(source, output)
            output.unlink()
            alias = Path(folder) / 'alias.ko'
            output.write_bytes(self.modified)
            os.link(output, alias)
            with self.assertRaisesRegex(RuntimeError, 'Unsafe KernelSU derivative'):
                patch_kernelsu.patch(source, output)
            self.assertEqual(output.read_bytes(), self.modified)

    def test_atomic_publish_does_not_overwrite_a_racing_unknown_output(self):
        with tempfile.TemporaryDirectory() as folder:
            source, output = (Path(folder) / 'source.ko', Path(folder) / 'derivative.ko')
            source.write_bytes(self.original)
            real_link = os.link

            def raced(temporary, destination):
                Path(destination).write_bytes(b'new user output')
                return real_link(temporary, destination)
            with patch.object(patch_kernelsu.os, 'link', side_effect=raced):
                with self.assertRaisesRegex(RuntimeError, 'unexpectedly created'):
                    patch_kernelsu.patch(source, output)
            self.assertEqual(output.read_bytes(), b'new user output')
            self.assertEqual(sorted((p.name for p in Path(folder).iterdir())), ['derivative.ko', 'source.ko'])

class CurrentKernelSUArtifactTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        source = REPO / 'tools' / kernelsu_release.DIRECTORY / patch_kernelsu.ASSET
        if not source.is_file():
            raise unittest.SkipTest('Current official KernelSU asset is not cached.')
        cls.original = source.read_bytes()
        cls.before = kernelsu_release.ASSETS[patch_kernelsu.ASSET]
        if hashlib.sha256(cls.original).hexdigest() != cls.before:
            raise AssertionError('Current cached official KernelSU module was modified.')
        cls.modified = patch_kernelsu.patch_bytes(cls.original)
        cls.receipt = patch_kernelsu.receipt(cls.before)

    def test_only_new_nonrelocated_site_branches_to_credential_cleanup(self):
        self.assertEqual(len(self.original), 330664)
        verified = patch_kernelsu.audit(self.original)
        self.assertEqual(verified['offset'], 29148)
        self.assertEqual(verified['receipt'], self.receipt)
        self.assertEqual(self.original[29148:29152], patch_kernelsu.ORIGINAL)
        self.assertEqual(self.modified[29148:29152], patch_kernelsu.BRANCH)
        self.assertEqual(self.original[:29148], self.modified[:29148])
        self.assertEqual(self.original[29152:], self.modified[29152:])
        self.assertEqual(self.modified[29164:29172], bytes.fromhex('13faffb405000014'))
        self.assertEqual(hashlib.sha256(self.modified).hexdigest(), self.receipt['after'])
        self.assertEqual(self.receipt['after'], '055a4fc38fa8a8f55233b7c576cadcc54a3a79ba080bc073b8aacf0b85b82305')

    def test_new_function_is_independently_bound_and_all_relocations_unchanged(self):
        header = struct.unpack_from('<16sHHIQQQIHHHHHH', self.original)
        sections = [struct.unpack_from('<IIQQQQIIQQ', self.original, header[6] + index * 64) for index in range(header[12])]
        count = 0
        for section in sections:
            if section[1] not in (2, 3, 4):
                continue
            offset, size = section[4:6]
            self.assertEqual(self.original[offset:offset + size], self.modified[offset:offset + size])
            if section[1] == 4:
                count += size // section[9]
        self.assertGreater(count, 4400)
        self.assertEqual(hashlib.sha256(self.original[28832:29316]).hexdigest(), patch_kernelsu.FUNCTION_HASHES[patch_kernelsu.BEFORE])
        self.assertEqual(hashlib.sha256(self.modified[28832:29316]).hexdigest(), patch_kernelsu.FUNCTION_HASHES[patch_kernelsu.AFTER])
        self.assertEqual(self.modified[29120:29148], patch_kernelsu.FLOW_GUARD[:28])

    def test_current_after_is_idempotent_and_partial_or_tampered_input_refuses(self):
        self.assertTrue(patch_kernelsu.audit(self.modified)['patched'])
        self.assertIs(patch_kernelsu.patch_bytes(self.modified), self.modified)
        variants = [self.original[:-1], self.original + b'\x00', bytearray(self.original)]
        for offset in (0, 29148, 8680 + 20480, 154920, len(self.original) - 1):
            altered = bytearray(self.original)
            altered[offset] ^= 1
            variants.append(bytes(altered))
        for value in variants:
            with self.assertRaisesRegex(RuntimeError, 'Unsupported KernelSU'):
                patch_kernelsu.patch_bytes(value)

    def test_atomic_current_output_reuse_preserves_official_source(self):
        with tempfile.TemporaryDirectory() as folder:
            source, output = (Path(folder) / 'official.ko', Path(folder) / 'quiet.ko')
            source.write_bytes(self.original)
            patch_kernelsu.patch(source, output)
            inode = output.stat().st_ino
            patch_kernelsu.patch(source, output)
            self.assertEqual(output.stat().st_ino, inode)
            self.assertEqual(output.read_bytes(), self.modified)
            self.assertEqual(source.read_bytes(), self.original)
            with self.assertRaisesRegex(RuntimeError, 'official KernelSU source'):
                patch_kernelsu.patch(source, source)

if __name__ == '__main__':
    unittest.main()


# --- tests/test_kernelsu_update.py ---

'Check offline KernelSU identity selection and preservation during upgrades.'

DAEMON = 'ksud-aarch64-linux-android'

CURRENT_DAEMON = release.ASSETS[DAEMON]

CURRENT_MANAGER = release.ASSETS[release.MANAGER]

LEGACY_DAEMON = KSU_ASSETS[DAEMON]

LEGACY_MANAGER = KSU_ASSETS[update.LEGACY_MANAGER]

ACTIVE = '/data/app/official-manager/base.apk'

def manager_certificates(data):
    """Read the pinned official APK's v2/v3 DER certificates without a SDK."""

    def field(body, offset=0):
        length, = struct.unpack_from('<I', body, offset)
        result = body[offset + 4:offset + 4 + length]
        if len(result) != length:
            raise AssertionError('Invalid certificate field bounds.')
        return (result, offset + 4 + length)
    block = signing_block(data)
    position, certificates = (8, set())
    while position < len(block) - 24:
        size, identifier = struct.unpack_from('<QI', block, position)
        value = block[position + 12:position + 8 + size]
        position += 8 + size
        if identifier not in (1896449818, 4031998144):
            continue
        signers, _ = field(value)
        signer, _ = field(signers)
        signed, _ = field(signer)
        _, next_field = field(signed)
        certs, _ = field(signed, next_field)
        cert, _ = field(certs)
        certificates.add(hashlib.sha256(cert).hexdigest())
    return certificates

class CanonicalReleaseTests(unittest.TestCase):

    def test_current_names_pins_and_legacy_contract_are_independent(self):
        self.assertEqual((release.VERSION, release.CODE), ('v3.3.1', 32680))
        self.assertEqual(release.MANAGER, 'KernelSU_v3.3.1_32680-release.apk')
        self.assertEqual(release.MANAGER, f'KernelSU_{release.VERSION}_{release.CODE}-release.apk')
        self.assertEqual(release.DIRECTORY, 'kernelsu-' + release.VERSION)
        self.assertEqual(release.MANAGER_CERTIFICATE, 'c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6')
        self.assertEqual(CURRENT_DAEMON, '049491e2b4cc0a6c913d3920cb90b8c94c9e8ca96c0ee92818293304973bfb1b')
        self.assertEqual(CURRENT_MANAGER, 'b4a059ace71de2fa65cc7f12b1c58d55fc23ab25e057ee4230ce779742abe450')
        self.assertEqual(KSU_VERSION, 'v3.3.0')
        self.assertEqual(KSU_ASSETS, {'ksud-aarch64-apple-darwin': '40ca97a2fb61284129909abac5325dcae790736d9b88901f4f31cc7ec6d9a705', DAEMON: '8614de6cdc2233c71fd0d1c64381ea10fbe6658651bae9b5a8dab4fe08e6344b', release.LKM: 'c31d994aaf285e7bf4cf1ec38c2bbf2d7f303d1a4a7d616405bcd9f850d684e5', 'lkm-aarch64-android16-6.12_kernelsu.ko': '877286f81d500c4ec546c96e9718c186b7379573c97ba5d5a35dd9a91465d076', update.LEGACY_MANAGER: 'c197060ecb89702e7d54a4c95e29cf5e8d97369bbbb436979ab7fd6bcde7b077'})

    def test_absent_current_assets_keep_legacy_bootstrap_without_network_or_guest(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(update, 'adb') as adb:
            root = Path(directory)
            self.assertFalse(release.available(root))
            self.assertEqual(update.bootstrap(root), (root / 'tools' / DAEMON, root / 'tools' / update.LEGACY_MANAGER))
            self.assertEqual(update.install({}, root)['state'], 'legacy')
            adb.assert_not_called()

    def test_partial_or_symlinked_current_cache_refuses_instead_of_silent_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / 'tools' / release.DIRECTORY
            selected.mkdir(parents=True)
            with self.assertRaises((RuntimeError, FileNotFoundError)):
                release.available(root)
            selected.rmdir()
            other = root / 'elsewhere'
            other.mkdir()
            selected.symlink_to(other, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'aliased'):
                release.available(root)

    def test_asset_authentication_preserves_unknown_bytes_and_rejects_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / 'tools' / release.DIRECTORY
            selected.mkdir(parents=True)
            good = b'authenticated fixture'
            expected = hashlib.sha256(good).hexdigest()
            path = selected / DAEMON
            path.write_bytes(good)
            with mock.patch.dict(release.ASSETS, {DAEMON: expected}):
                self.assertEqual(release.asset(root, DAEMON), path)
                alias = selected / 'alias'
                os.link(path, alias)
                with self.assertRaises(RuntimeError):
                    release.asset(root, DAEMON)
                alias.unlink()
                path.write_bytes(b'custom daemon')
                with self.assertRaises(RuntimeError):
                    release.asset(root, DAEMON)
                self.assertEqual(path.read_bytes(), b'custom daemon')
                path.unlink()
                alias.write_bytes(good)
                path.symlink_to(alias)
                with self.assertRaises(RuntimeError):
                    release.asset(root, DAEMON)
                self.assertTrue(path.is_symlink())
            with self.assertRaisesRegex(RuntimeError, 'Unknown'):
                release.asset(root, '../unknown')

    def test_actual_cached_assets_are_exact_and_current_bootstrap_selects_them(self):
        directory = ROOT / 'tools' / release.DIRECTORY
        if not directory.is_dir():
            self.skipTest('Official current assets unavailable; no download attempted.')
        self.assertTrue(release.available(ROOT))
        for name in release.RUNTIME_ASSETS:
            path = release.asset(ROOT, name)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), release.ASSETS[name])
        self.assertEqual(update.bootstrap(ROOT), (directory / DAEMON, directory / release.MANAGER))

    def test_actual_old_and_new_manager_bytes_keep_the_same_official_signer(self):
        paths = [(ROOT / 'tools' / update.LEGACY_MANAGER, LEGACY_MANAGER), (ROOT / 'tools' / release.DIRECTORY / release.MANAGER, CURRENT_MANAGER)]
        if not all((path.is_file() for path, _ in paths)):
            self.skipTest('Official old/current Managers unavailable; no download attempted.')
        for path, expected in paths:
            data = path.read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), expected)
            self.assertEqual(manager_certificates(data), {release.MANAGER_CERTIFICATE})

    def test_manager_embedded_daemon_pins_come_from_exact_official_apk_members(self):
        variants = ((ROOT / 'tools' / update.LEGACY_MANAGER, LEGACY_MANAGER, release.LEGACY_MANAGER_DAEMON, 4892712), (ROOT / 'tools' / release.DIRECTORY / release.MANAGER, CURRENT_MANAGER, release.CURRENT_MANAGER_DAEMON, 4990848))
        if not all((path.is_file() for path, *_ in variants)):
            self.skipTest('Official old/current Managers unavailable; no download attempted.')
        for path, apk_hash, member_hash, length in variants:
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), apk_hash)
            with zipfile.ZipFile(path) as archive:
                self.assertEqual(archive.namelist().count(release.MANAGER_DAEMON), 1)
                member = archive.read(release.MANAGER_DAEMON)
            self.assertEqual(len(member), length)
            self.assertEqual(hashlib.sha256(member).hexdigest(), member_hash)
            self.assertEqual(member[:7], b'\x7fELF\x02\x01\x01')
            self.assertEqual(struct.unpack_from('<H', member, 18)[0], 183)
        self.assertEqual(release.LEGACY_DAEMONS, {LEGACY_DAEMON, release.LEGACY_MANAGER_DAEMON})
        self.assertEqual(release.CURRENT_DAEMONS, {CURRENT_DAEMON, release.CURRENT_MANAGER_DAEMON})

class UpdateTests(unittest.TestCase):

    def harness(self, daemon=CURRENT_DAEMON, manager=CURRENT_MANAGER, package=None, fail_stage=False):
        """Mock only guest boundaries; keep real upgrade decisions and commands."""
        hashes = {'/data/adb/ksud': daemon, ACTIVE: manager}
        paths = ['package:' + ACTIVE] if package is None else list(package)
        staged = []

        def adb(_config, kind, command, **_options):
            self.assertEqual((kind, command), ('shell', 'pm path ' + update.PACKAGE))
            return SimpleNamespace(returncode=0 if paths else 1, stdout='\n'.join(paths) + ('\n' if paths else ''), stderr='')

        def stage(_config, source, execute):
            command = execute('/data/local/tmp/owned-' + source.name)
            staged.append((source.name, command))
            if fail_stage:
                raise RuntimeError('simulated staging failure')
            if source.name == DAEMON:
                hashes['/data/adb/ksud'] = CURRENT_DAEMON
            elif source.name == release.MANAGER:
                paths[:] = ['package:' + ACTIVE]
                hashes[ACTIVE] = CURRENT_MANAGER
            else:
                raise AssertionError('Unexpected asset selected: ' + source.name)
            return 'Success'
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(release, 'available', return_value=True))
        stack.enter_context(mock.patch.object(release, 'asset', side_effect=lambda _root, name: Path('/cache') / name))
        stack.enter_context(mock.patch.object(update, '_hash', side_effect=lambda _config, path: hashes.get(path)))
        stack.enter_context(mock.patch.object(update, 'adb', side_effect=adb))
        stack.enter_context(mock.patch.object(update, '_stage', side_effect=stage))
        return (hashes, paths, staged)

    def test_exact_current_stack_is_verified_without_mutation(self):
        _, _, staged = self.harness()
        result = update.install({}, ROOT)
        self.assertEqual((result['daemon'], result['manager']), ('verified', 'verified'))
        self.assertEqual(staged, [])

    def test_current_manager_embedded_daemon_is_verified_without_replacement(self):
        _, _, staged = self.harness(daemon=release.CURRENT_MANAGER_DAEMON)
        result = update.install({}, ROOT)
        self.assertEqual((result['daemon'], result['manager']), ('verified', 'verified'))
        self.assertEqual(staged, [])

    def test_legacy_manager_embedded_daemon_updates_with_its_actual_before_guard(self):
        _, _, staged = self.harness(daemon=release.LEGACY_MANAGER_DAEMON)
        result = update.install({}, ROOT)
        self.assertEqual((result['daemon'], result['manager']), ('updated', 'verified'))
        self.assertEqual([name for name, _ in staged], [DAEMON])
        command = staged[0][1]
        self.assertEqual(command.count('= ' + release.LEGACY_MANAGER_DAEMON + ' ]'), 2)
        self.assertNotIn('= ' + LEGACY_DAEMON + ' ]', command)
        self.assertNotIn(' install', command)
        self.assertIn('mv -f', command)

    def test_replace_daemon_refuses_an_unregistered_before_identity(self):
        with self.assertRaisesRegex(RuntimeError, 'Unreviewed'):
            update._replace_daemon('/data/local/tmp/owned', '0' * 64)

    def test_custom_or_missing_daemon_and_custom_manager_are_preserved(self):
        for daemon in (None, 'custom daemon', 'unavailable'):
            with self.subTest(daemon=daemon):
                _, _, staged = self.harness(daemon=daemon, manager='custom manager')
                result = update.install({}, ROOT)
                self.assertEqual((result['daemon'], result['manager']), ('preserved-custom', 'preserved-custom'))
                self.assertEqual(staged, [])

    def test_split_or_unknown_package_layout_is_preserved(self):
        for package in (['package:' + ACTIVE, 'package:/data/app/split.apk'],):
            with self.subTest(package=package):
                _, _, staged = self.harness(package=package)
                self.assertEqual(update.install({}, ROOT)['manager'], 'preserved-custom-layout')
                self.assertEqual(staged, [])

    def test_failed_or_ambiguous_presence_probe_never_authorizes_an_install(self):
        for status, output, error in ((0, '', ''), (1, 'package:' + ACTIVE, ''), (1, '', 'permission denied'), (2, '', ''), (0, 'unknown package path', ''), (0, 'package:' + ACTIVE, 'unexpected warning')):
            with self.subTest(status=status, output=output, error=error):
                _, _, staged = self.harness()
                result = SimpleNamespace(returncode=status, stdout=output, stderr=error)
                with mock.patch.object(update, 'adb', return_value=result):
                    with self.assertRaisesRegex(RuntimeError, 'presence was not confirmed'):
                        update.install({}, ROOT)
                self.assertEqual(staged, [])

    def test_known_legacy_stack_updates_without_install_reset_or_restart(self):
        hashes, _, staged = self.harness(daemon=LEGACY_DAEMON, manager=LEGACY_MANAGER)
        result = update.install({}, ROOT)
        self.assertEqual((result['daemon'], result['manager']), ('updated', 'updated'))
        self.assertEqual(hashes['/data/adb/ksud'], CURRENT_DAEMON)
        self.assertEqual(hashes[ACTIVE], CURRENT_MANAGER)
        self.assertEqual([name for name, _ in staged], [DAEMON, release.MANAGER])
        daemon_command = staged[0][1]
        self.assertNotIn(' install', daemon_command)
        self.assertIn('/data/adb/ksud', daemon_command)
        self.assertIn('mv', daemon_command)
        self.assertEqual(staged[1][1], 'pm install -r /data/local/tmp/owned-' + release.MANAGER)
        for _, command in staged:
            for forbidden in ('pm clear', 'pm uninstall', 'rm -rf', 'killall', 'reboot', 'feature reset'):
                self.assertNotIn(forbidden, command)

    def test_missing_manager_is_installed_and_verified(self):
        _, _, staged = self.harness(package=[])
        result = update.install({}, ROOT)
        self.assertEqual(result['manager'], 'installed')
        self.assertEqual([name for name, _ in staged], [release.MANAGER])

    def test_failed_staging_does_not_continue_to_manager_mutation(self):
        _, _, staged = self.harness(daemon=LEGACY_DAEMON, manager=LEGACY_MANAGER, fail_stage=True)
        with self.assertRaisesRegex(RuntimeError, 'staging failure'):
            update.install({}, ROOT)
        self.assertEqual([name for name, _ in staged], [DAEMON])

    def test_confirmation_refuses_a_failed_or_custom_manager_output(self):
        _, _, _ = self.harness(manager=LEGACY_MANAGER)
        with mock.patch.object(update, '_hash', side_effect=[CURRENT_DAEMON, LEGACY_MANAGER, 'custom changed APK']):
            with self.assertRaisesRegex(RuntimeError, 'Manager update was not confirmed'):
                update.install({}, ROOT)

    def test_missing_manager_install_cannot_report_success_without_output_confirmation(self):
        _, _, _ = self.harness(package=[])
        with mock.patch.object(update, '_hash', return_value=CURRENT_DAEMON):
            with self.assertRaisesRegex(RuntimeError, 'Manager .*not confirmed'):
                update.install({}, ROOT)

class BoundaryTests(unittest.TestCase):

    def test_hash_probes_only_nonaliased_regular_files_and_quotes_path(self):
        path = "/data/app/odd ' name/base.apk"
        with mock.patch.object(update, 'root', return_value='unavailable') as root:
            self.assertEqual(update._hash({}, path), 'unavailable')
        command = root.call_args.args[1]
        self.assertIn('[ -f ' + shlex.quote(path) + ' ]', command)
        self.assertIn('[ ! -L ' + shlex.quote(path) + ' ]', command)
        self.assertIn('stat -c %h ' + shlex.quote(path), command)
        self.assertIn(' = 1 ]', command)

    def test_stage_uses_root_wrapper_without_duplicate_timeout_and_always_cleans_owned_stage(self):
        events = []
        response = SimpleNamespace(returncode=0, stdout='Success', stderr='')

        def adb(_config, *arguments, **_options):
            events.append(arguments)
            return response
        source = Path('/verified') / release.MANAGER
        with mock.patch.object(update, 'adb', side_effect=adb), mock.patch.object(apply_flutter_fix, 'adb', side_effect=adb):
            update._stage({}, source, lambda remote: 'pm install -r ' + remote)
        self.assertEqual(events[0][:2], ('push', str(source)))
        self.assertEqual(events[-1][0], 'shell')
        self.assertTrue(events[-1][1].startswith('rm -f /data/local/tmp/hyperos-avd-ksu-'))
        self.assertEqual(sum((row[0] == 'push' for row in events)), 1)
        script = events[1][1]
        self.assertIn(CURRENT_MANAGER, script)
        self.assertIn('stat -c %h', script)
        self.assertIn('chmod 700', script)

    def test_staging_command_failure_keeps_guest_state_and_cleans_only_unique_stage(self):
        response = SimpleNamespace(returncode=0, stdout='', stderr='')
        with mock.patch.object(update, 'adb', return_value=response) as adb, mock.patch.object(update, 'root', side_effect=RuntimeError('guest command failed')):
            with self.assertRaisesRegex(RuntimeError, 'guest command failed'):
                update._stage({}, Path('/cache') / DAEMON, lambda remote: remote + ' --version')
        self.assertEqual(adb.call_count, 2)
        last = adb.call_args.args
        self.assertEqual(last[1], 'shell')
        self.assertTrue(last[2].startswith('rm -f /data/local/tmp/hyperos-avd-ksu-'))
        self.assertNotIn('/data/adb/', last[2])

class FreshBootstrapTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.adb = self.root / 'adb'
        self.remote = self.root / 'official-bootstrap'
        self.marker = self.root / 'install-called'
        self.remote.write_text('#!/bin/sh\n[ "$1" = install ] || exit 3\nprintf called > "$FIXTURE_INSTALL_MARKER"\nmkdir -p "$FIXTURE_ADB"\nchmod 700 "$FIXTURE_ADB"\ncp "$0" "$FIXTURE_ADB/ksud"\nchmod "${FIXTURE_INSTALLED_MODE:-755}" "$FIXTURE_ADB/ksud"\nif [ "${FIXTURE_INSTALL_CORRUPT:-0}" = 1 ]; then printf unknown > "$FIXTURE_ADB/ksud"; fi\nif [ "${FIXTURE_INSTALL_ALIAS:-0}" = 1 ]; then\n    rm "$FIXTURE_ADB/ksud"\n    ln -s "$0" "$FIXTURE_ADB/ksud"\nfi\n')
        self.remote.chmod(448)
        self.digest = hashlib.sha256(self.remote.read_bytes()).hexdigest()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        (self.bin / 'stat').write_text('#!' + sys.executable + "\nimport os,stat,sys\nfmt,path=sys.argv[2],sys.argv[3];info=os.stat(path)\nvalues={'%u':'0','%g':'0','%a':oct(stat.S_IMODE(info.st_mode))[2:],'%h':str(info.st_nlink)}\nfor key,value in values.items():fmt=fmt.replace(key,value)\nprint(fmt)\n")
        (self.bin / 'id').write_text('#!/bin/sh\nprintf "%s\\n" "${FIXTURE_UID:-0}"\n')
        (self.bin / 'getenforce').write_text('#!/bin/sh\nprintf "%s\\n" "${FIXTURE_SELINUX:-Enforcing}"\n')
        for path in self.bin.iterdir():
            path.chmod(493)

    def run_script(self, **environment):
        script = update._fresh_bootstrap_command(str(self.remote), self.digest, 'verified-fresh')
        script = script.replace('/data/adb', str(self.adb))
        return subprocess.run(['/bin/sh', '-c', script], capture_output=True, text=True, env={**os.environ, 'PATH': str(self.bin) + ':' + os.environ['PATH'], 'FIXTURE_INSTALL_MARKER': str(self.marker), 'FIXTURE_ADB': str(self.adb), **environment})

    def test_absent_or_private_empty_userdata_allows_first_official_install(self):
        for empty in (False, True):
            with self.subTest(empty=empty):
                if empty:
                    (self.adb / 'ksud').unlink()
                    self.marker.unlink()
                result = self.run_script()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('verified-fresh', result.stdout.splitlines())
                self.assertEqual(self.adb.joinpath('ksud').read_bytes(), self.remote.read_bytes())
                self.assertTrue(self.marker.is_file())

    def test_any_existing_daemon_helper_module_profile_or_hidden_state_is_preserved(self):
        self.adb.mkdir(mode=448)
        for name in ('ksud', 'ksu', 'modules', 'modules_update', 'tools', 'allowlist', '.unknown'):
            selected = self.adb / name
            selected.write_bytes(b'user state and loaded executable')
            inode = selected.stat().st_ino
            with selected.open('rb') as loaded, self.subTest(name=name):
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('state was preserved', result.stderr)
                self.assertFalse(self.marker.exists())
                self.assertEqual(selected.stat().st_ino, inode)
                self.assertEqual(loaded.read(), b'user state and loaded executable')
            selected.unlink()
        (self.adb / 'empty-custom-directory').mkdir()
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertTrue((self.adb / 'empty-custom-directory').is_dir())
        self.assertFalse(self.marker.exists())

    def test_official_private_mode_700_install_is_confirmed_with_exact_content(self):
        result = self.run_script(FIXTURE_INSTALLED_MODE='700')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('verified-fresh', result.stdout.splitlines())
        self.assertEqual((self.adb / 'ksud').stat().st_mode & 511, 448)
        self.assertEqual((self.adb / 'ksud').read_bytes(), self.remote.read_bytes())

    def test_postinstall_unsafe_mode_unknown_content_or_alias_never_confirms_bootstrap(self):
        for values in ({'FIXTURE_INSTALLED_MODE': '777'}, {'FIXTURE_INSTALLED_MODE': '775'}, {'FIXTURE_INSTALLED_MODE': '750'}, {'FIXTURE_INSTALLED_MODE': '644'}, {'FIXTURE_INSTALL_CORRUPT': '1'}, {'FIXTURE_INSTALL_ALIAS': '1'}):
            with self.subTest(values=values):
                result = self.run_script(**values)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('verified-fresh', result.stdout.splitlines())
                self.assertTrue(self.marker.exists())
                self.assertTrue((self.adb / 'ksud').exists())
                shutil.rmtree(self.adb)
                self.marker.unlink()

    def test_alias_wrong_permissions_nonroot_and_permissive_refuse_without_install(self):
        elsewhere = self.root / 'elsewhere'
        elsewhere.mkdir(mode=448)
        self.adb.symlink_to(elsewhere)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.adb.unlink()
        self.adb.mkdir(mode=493)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.adb.chmod(448)
        for values in ({'FIXTURE_UID': '2000'}, {'FIXTURE_SELINUX': 'Permissive'}):
            self.assertNotEqual(self.run_script(**values).returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertEqual(list(self.adb.iterdir()), [])
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_unknown_local_bootstrap_never_reaches_adb(self):
        with mock.patch.object(update, 'adb') as adb:
            with self.assertRaisesRegex(RuntimeError, 'Unknown'):
                update.initialize_fresh({}, self.remote)
            adb.assert_not_called()
        alias = self.root / 'alias'
        alias.symlink_to(self.remote)
        with self.assertRaisesRegex(RuntimeError, 'unverified'):
            update.initialize_fresh({}, alias)

    def test_transport_requires_fresh_success_marker_and_cleans_only_unique_stage(self):
        events = []

        def adb(_config, *arguments, **options):
            events.append((arguments, options))
            if arguments[-1].endswith(' debug su'):
                return SimpleNamespace(returncode=0, stdout='no actual bootstrap\n', stderr='')
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        with mock.patch.dict(KSU_ASSETS, {DAEMON: self.digest}), mock.patch.object(update, 'adb', side_effect=adb):
            with self.assertRaisesRegex(RuntimeError, 'not confirmed'):
                update.initialize_fresh({}, self.remote)
        self.assertEqual(events[0][0][:2], ('push', str(self.remote)))
        remote = events[0][0][2]
        self.assertTrue(remote.startswith('/data/local/tmp/hyperos-avd-bootstrap-'))
        script = events[2][1]['input']
        self.assertLess(script.index('entries=$(find'), script.index(' install || refuse'))
        self.assertEqual(events[-1][0], ('shell', 'rm -f ' + remote))
        self.assertNotIn('/data/adb', events[-1][0][1])

class LaunchBootstrapTests(unittest.TestCase):

    def test_existing_su_refusal_uses_safe_helper_and_stops_without_persistent_changes(self):

        def adb(_config, *arguments, **_options):
            return SimpleNamespace(returncode=0, stdout='uid=2000(shell)\n', stderr='')
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(launch, 'ROOT', Path(directory)), mock.patch.object(launch, 'is_os4', return_value=False), mock.patch.object(launch, 'adb', side_effect=adb) as transport, mock.patch.object(update, 'initialize_fresh', side_effect=RuntimeError('Existing state preserved')) as fresh:
            with self.assertRaisesRegex(RuntimeError, 'Existing state'):
                launch.initialize({})
            fresh.assert_called_once_with({}, Path(directory) / 'tools' / DAEMON)
            self.assertEqual(transport.call_count, 2)
            self.assertFalse((Path(directory) / 'local/last-boot.json').exists())

    def test_existing_authorized_su_never_runs_bootstrap(self):

        def adb(_config, *arguments, **_options):
            command = arguments[-1]
            output = '1\n' if command == 'getprop sys.boot_completed' else 'package:/known/Manager.apk\n' if command == 'pm path me.weishu.kernelsu' else 'uid=0(root)\nEnforcing\n'
            return SimpleNamespace(returncode=0, stdout=output, stderr='')
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(launch, 'ROOT', Path(directory)), mock.patch.object(launch, 'is_os4', return_value=False), mock.patch.object(launch, 'adb', side_effect=adb), mock.patch.object(update, 'initialize_fresh') as fresh:
            launch.initialize({'name': 'Renamed_Legacy_AVD', 'port': 5566})
            fresh.assert_not_called()

class AtomicDaemonTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.adb = self.root / 'adb'
        self.adb.mkdir(mode=448)
        self.old = self.adb / 'ksud'
        self.old.write_bytes(b'old loaded executable')
        self.old.chmod(493)
        self.remote = self.root / 'remote'
        self.remote.write_bytes(b'new official executable')
        self.before = hashlib.sha256(self.old.read_bytes()).hexdigest()
        self.after = hashlib.sha256(self.remote.read_bytes()).hexdigest()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        stat_code = "import os,stat,sys\nfmt,path=sys.argv[2],sys.argv[3];info=os.stat(path)\nvalues={'%u':'0','%g':'0','%a':oct(stat.S_IMODE(info.st_mode))[2:],'%h':str(info.st_nlink),'%d':str(info.st_dev)}\nfor key,value in values.items():fmt=fmt.replace(key,value)\nprint(fmt)\n"
        (self.bin / 'stat').write_text('#!' + sys.executable + '\n' + stat_code)
        (self.bin / 'ls').write_text('#!/bin/sh\nprintf "%s %s\\n" "${FIXTURE_LABEL:-u:object_r:ksu_file:s0}" "$2"\n')
        (self.bin / 'chown').write_text('#!/bin/sh\nexit 0\n')
        (self.bin / 'chcon').write_text('#!/bin/sh\nexit "${FIXTURE_CONTEXT_FAILURE:-0}"\n')
        for path in self.bin.iterdir():
            path.chmod(493)

    def run_script(self, **environment):
        with mock.patch.dict(KSU_ASSETS, {DAEMON: self.before}), mock.patch.dict(release.ASSETS, {DAEMON: self.after}), mock.patch.object(release, 'LEGACY_DAEMONS', frozenset((self.before,))):
            script = update._replace_daemon(shlex.quote(str(self.remote)))
        script = 'set -e\n' + script.replace('/data/adb', str(self.adb))
        return subprocess.run(['/bin/sh', '-c', script], env={**os.environ, 'PATH': str(self.bin) + ':' + os.environ['PATH'], **environment}, capture_output=True, text=True)

    def test_atomic_success_keeps_open_old_inode_and_does_not_rewrite_helpers(self):
        sentinel = self.adb / 'modules-and-allowlist-sentinel'
        sentinel.write_bytes(b'userdata state')
        old_inode = self.old.stat().st_ino
        with self.old.open('rb') as loaded:
            result = self.run_script()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(loaded.read(), b'old loaded executable')
            self.assertEqual(os.fstat(loaded.fileno()).st_ino, old_inode)
            self.assertNotEqual(self.old.stat().st_ino, old_inode)
        self.assertEqual(self.old.read_bytes(), b'new official executable')
        self.assertEqual(self.old.stat().st_mode & 511, 493)
        self.assertEqual(self.old.stat().st_nlink, 1)
        self.assertEqual(sentinel.read_bytes(), b'userdata state')
        self.assertFalse(list(self.adb.glob('.hyperos-avd-ksud-*')))

    def test_staged_context_or_content_failure_preserves_old_inode_and_metadata(self):
        for environment, tamper in (({'FIXTURE_CONTEXT_FAILURE': '1'}, False), ({}, True)):
            with self.subTest(environment=environment, tamper=tamper):
                before = self.old.stat()
                if tamper:
                    self.remote.write_bytes(b'not the authenticated new executable')
                    expected = self.after
                    self.after = '0' * 64
                result = self.run_script(**environment)
                if tamper:
                    self.after = expected
                self.assertNotEqual(result.returncode, 0)
                after = self.old.stat()
                self.assertEqual((after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_mtime_ns), (before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_mtime_ns))
                self.assertEqual(self.old.read_bytes(), b'old loaded executable')
                self.assertFalse(list(self.adb.glob('.hyperos-avd-ksud-*')))

    def test_custom_mode_label_and_hardlink_refuse_before_publication(self):
        before = self.old.stat().st_ino
        self.old.chmod(448)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.old.chmod(493)
        self.assertNotEqual(self.run_script(FIXTURE_LABEL='u:object_r:custom_file:s0').returncode, 0)
        alias = self.adb / 'custom-alias'
        os.link(self.old, alias)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual(self.old.stat().st_ino, before)
        self.assertEqual(self.old.read_bytes(), b'old loaded executable')
        self.assertFalse(list(self.adb.glob('.hyperos-avd-ksud-*')))

class ProducerAndBundleTests(unittest.TestCase):

    def setUp(self):
        official = ROOT / 'tools' / release.DIRECTORY / release.LKM
        if not official.is_file():
            self.skipTest('Current official LKM unavailable; no download attempted.')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.repo, self.workspace = (base / 'repo', base / 'workspace')
        self.assets = {name: official.read_bytes() if name == release.LKM else name.encode() for name in release.ASSETS}
        namespace = self.repo / 'tools' / release.DIRECTORY
        namespace.mkdir(parents=True)
        for name, body in self.assets.items():
            (namespace / name).write_bytes(body)
        self.legacy = {DAEMON: b'legacy floor daemon', update.LEGACY_MANAGER: b'legacy floor Manager'}
        for name, body in self.legacy.items():
            (self.repo / 'tools' / name).write_bytes(body)
        for name in ('tools', 'work', 'images', 'logs', 'local'):
            (self.workspace / name).mkdir(parents=True, exist_ok=True)
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.dict(release.ASSETS, {name: hashlib.sha256(body).hexdigest() for name, body in self.assets.items()}))
        stack.enter_context(mock.patch.dict(KSU_ASSETS, {name: hashlib.sha256(body).hexdigest() for name, body in self.legacy.items()}))
        self.fetch = stack.enter_context(mock.patch.object(release, 'fetch'))

    def test_shared_builder_uses_current_receipt_and_content_addressed_quiet_lkm(self):
        old = self.workspace / 'work/kernelsu-marker.ko'
        old.write_bytes(b'prior producer output')
        stack = phone_builder.prepare_kernelsu(self.repo, self.workspace)
        self.fetch.assert_called_once_with(self.repo)
        self.assertEqual(stack['receipt'], patch_kernelsu.receipt(self.assets[release.LKM]))
        self.assertEqual(stack['receipt']['version'], release.VERSION)
        self.assertIn(stack['receipt']['after'], stack['lkm'].name)
        self.assertEqual(stack['host'].parent.name, release.DIRECTORY)
        self.assertEqual(hashlib.sha256(stack['lkm'].read_bytes()).hexdigest(), stack['receipt']['after'])
        self.assertEqual(old.read_bytes(), b'prior producer output')
        for name, body in self.legacy.items():
            self.assertEqual((self.workspace / 'tools' / name).read_bytes(), body)
        inode = stack['lkm'].stat().st_ino
        self.assertEqual(phone_builder.prepare_kernelsu(self.repo, self.workspace), stack)
        self.assertEqual(stack['lkm'].stat().st_ino, inode)
        source = (ROOT / 'scripts/build_os4_pad.py').read_text()
        self.assertIn('ksu = prepare_kernelsu(repo, ROOT)', source)
        self.assertIn('patch_kernelsu_ramdisk(ROOT, ksu)', source)
        self.assertNotIn('ksu_marker_receipt()', source)

    def test_unknown_current_workspace_attachment_is_retained(self):
        target = self.workspace / 'tools' / release.DIRECTORY / release.MANAGER
        target.parent.mkdir()
        target.write_bytes(b'custom Manager')
        with self.assertRaisesRegex(RuntimeError, 'Preserving an unknown'):
            phone_builder.prepare_kernelsu(self.repo, self.workspace)
        self.assertEqual(target.read_bytes(), b'custom Manager')

    def test_boot_output_is_staged_and_never_overwrites_unknown_existing_output(self):
        stack = phone_builder.prepare_kernelsu(self.repo, self.workspace)
        expected_ramdisk = cpio([(b'kernelsu.ko', stack['lkm'].read_bytes(), {})])
        source = self.workspace / 'images/ramdisk.img'
        source.write_bytes(b'base ramdisk')
        old = self.workspace / 'work/ramdisk-kernelsu.img'
        old.write_bytes(b'prior producer output')

        def build(command, **options):
            self.assertEqual(command[0], str(stack['host']))
            self.assertEqual(command[command.index('-m') + 1], str(stack['lkm']))
            destination = Path(command[command.index('-o') + 1]) / command[command.index('--out-name') + 1]
            self.assertNotEqual(destination.parent, self.workspace / 'work')
            destination.write_bytes(expected_ramdisk)
        with mock.patch.object(phone_builder.subprocess, 'run', side_effect=build):
            output = phone_builder.patch_kernelsu_ramdisk(self.workspace, stack)
            self.assertEqual(source.read_bytes(), expected_ramdisk)
            self.assertEqual(old.read_bytes(), b'prior producer output')
            source.write_bytes(b'base ramdisk')
            output.write_bytes(b'custom cached output')
            with self.assertRaisesRegex(RuntimeError, 'Preserving an unknown'):
                phone_builder.patch_kernelsu_ramdisk(self.workspace, stack)
            self.assertEqual(source.read_bytes(), b'base ramdisk')
            self.assertEqual(output.read_bytes(), b'custom cached output')
            self.assertFalse(list((self.workspace / 'work').glob('.kernelsu-boot-*')))

    def test_zero_filled_host_output_is_normalized_only_after_full_stream_and_lkm_audit(self):
        stack = phone_builder.prepare_kernelsu(self.repo, self.workspace)
        archive = cpio([(b'kernelsu.ko', stack['lkm'].read_bytes(), {})])
        canonical = ksu_ramdisk.pack('lz4-legacy', archive)
        source = self.workspace / 'images/ramdisk.img'
        for padding in (b'', bytes(4), bytes(128)):
            with self.subTest(padding=len(padding)):
                source.write_bytes(b'base ramdisk')
                produced = canonical + padding
                if padding:
                    with self.assertRaises(RuntimeError):
                        ksu_ramdisk.unpack(produced)

                def build(command, **options):
                    output = Path(command[command.index('-o') + 1]) / command[command.index('--out-name') + 1]
                    output.write_bytes(produced)
                with mock.patch.object(phone_builder.subprocess, 'run', side_effect=build):
                    output = phone_builder.patch_kernelsu_ramdisk(self.workspace, stack)
                self.assertEqual(output.read_bytes(), canonical)
                self.assertEqual(source.read_bytes(), canonical)
                self.assertEqual(ksu_ramdisk.unpack(source.read_bytes()), ('lz4-legacy', archive))

    def test_producer_padding_does_not_allow_truncation_concatenation_or_unknown_lkm(self):
        stack = phone_builder.prepare_kernelsu(self.repo, self.workspace)
        archive = cpio([(b'kernelsu.ko', stack['lkm'].read_bytes(), {})])
        canonical = ksu_ramdisk.pack('lz4-legacy', archive)
        other = cpio([(b'kernelsu.ko', b'unknown module', {})])
        invalid = (canonical[:-1], canonical + b'\x00' * 3, canonical + bytes(4) + b'nonzero', canonical + canonical, canonical + bytes(4) + canonical, ksu_ramdisk.pack('lz4-legacy', other) + bytes(128), ksu_ramdisk.LZ4_MAGIC + bytes(128))
        source = self.workspace / 'images/ramdisk.img'
        source.write_bytes(b'base ramdisk')
        for produced in invalid:
            with self.subTest(size=len(produced)):

                def build(command, **options):
                    output = Path(command[command.index('-o') + 1]) / command[command.index('--out-name') + 1]
                    output.write_bytes(produced)
                with mock.patch.object(phone_builder.subprocess, 'run', side_effect=build), self.assertRaises(RuntimeError):
                    phone_builder.patch_kernelsu_ramdisk(self.workspace, stack)
                self.assertEqual(source.read_bytes(), b'base ramdisk')
                self.assertFalse(list((self.workspace / 'work').glob('ramdisk-kernelsu-*.img')))
                self.assertFalse(list((self.workspace / 'work').glob('.kernelsu-boot-*')))

    def test_real_pinned_host_zero_filled_output_keeps_exact_cpio_and_current_lkm(self):
        path = ROOT / 'work/formal-release-validation-20261014/ksu-lz4-format-probe/producer.img'
        if not path.is_file():
            self.skipTest('Private pinned-host output fixture unavailable; no producer execution attempted.')
        produced = path.read_bytes()
        self.assertEqual(hashlib.sha256(produced).hexdigest(), '8f3d8c512a79f81e284897eba99d299807647eac0dbfc423a541a861921895b1')
        with self.assertRaises(RuntimeError):
            ksu_ramdisk.unpack(produced)
        stack = phone_builder.prepare_kernelsu(self.repo, self.workspace)
        source = self.workspace / 'images/ramdisk.img'
        source.write_bytes(b'base ramdisk')

        def build(command, **options):
            output = Path(command[command.index('-o') + 1]) / command[command.index('--out-name') + 1]
            output.write_bytes(produced)
        with mock.patch.object(phone_builder.subprocess, 'run', side_effect=build):
            output = phone_builder.patch_kernelsu_ramdisk(self.workspace, stack)
        self.assertEqual(output.stat().st_size, 2290636)
        self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), '7ab2ab7c861d842e7022c8bc99d816d03ed333e7d0bf5db5ba37723e89517acf')
        _, archive = ksu_ramdisk.unpack(output.read_bytes())
        self.assertEqual(hashlib.sha256(archive).hexdigest(), '6fa595d97e598a5c2a28b5be6e0f225efe51c85331b95e305c73695fa3510c5e')
        entries = ksu_ramdisk.parse_cpio(archive)
        self.assertEqual(len(entries), 32)
        member = next((entry for entry in entries if entry['name'] == b'kernelsu.ko'))
        audited = patch_kernelsu.audit(archive[member['body']:member['body'] + member['size']])
        self.assertEqual(audited['receipt'], stack['receipt'])
        self.assertEqual(source.read_bytes(), output.read_bytes())
        self.assertEqual(path.read_bytes(), produced)

    def test_portable_current_trio_requires_complete_authenticated_cache(self):
        metadata = {'format': 3, 'variant': 'os4-pad'}
        self.assertEqual(package_release.current_kernelsu_paths(self.workspace, metadata), {})
        phone_builder.prepare_kernelsu(self.repo, self.workspace)
        paths = package_release.current_kernelsu_paths(self.workspace, metadata)
        self.assertEqual(set(paths), {'tools/' + release.DIRECTORY + '/' + name for name in release.RUNTIME_ASSETS})
        for legacy in ({'format': 1}, {'format': 3, 'variant': 'os3'}, {'format': 2, 'variant': 'os4-official'}):
            self.assertEqual(package_release.current_kernelsu_paths(self.workspace, legacy), {})
        (self.workspace / 'tools' / release.DIRECTORY / release.MANAGER).write_bytes(b'custom Manager')
        with self.assertRaises(RuntimeError):
            package_release.current_kernelsu_paths(self.workspace, metadata)

    def test_partial_current_runtime_attachments_are_refused_before_archive_creation(self):
        phone_builder.prepare_kernelsu(self.repo, self.workspace)
        metadata = {'format': 3, 'variant': 'os4-pad', 'build': {}}
        paths = package_release.current_kernelsu_paths(self.workspace, metadata)
        only_one = {next(iter(paths)): next(iter(paths.values()))}
        destination = self.workspace / 'bundle'
        with self.assertRaisesRegex(RuntimeError, 'every verified runtime asset'):
            package_release.write_bundle(destination, 'pad-vtest', metadata, only_one, 1)
        self.assertFalse(destination.exists())

    def test_complete_runtime_attachment_bytes_are_verified_before_archiving(self):
        phone_builder.prepare_kernelsu(self.repo, self.workspace)
        metadata = {'format': 3, 'variant': 'os4-pad', 'build': {}}
        paths = package_release.current_kernelsu_paths(self.workspace, metadata)
        system = self.workspace / 'images/system.img'
        system.write_bytes(b'packed system fixture')
        paths['images/system.img'] = system
        bad = paths['tools/' + release.DIRECTORY + '/' + release.MANAGER]
        bad.write_bytes(b'unknown Manager output')
        destination = self.workspace / 'bundle'
        with self.assertRaisesRegex(RuntimeError, 'official pin'):
            package_release.write_bundle(destination, 'pad-vtest', metadata, paths, 1)
        self.assertFalse(destination.exists())

    def test_current_image_without_its_runtime_trio_cannot_silently_use_legacy(self):
        metadata = {'format': 3, 'variant': 'os4-pad', 'build': {'kernelsu_marker_fix': patch_kernelsu.receipt(self.assets[release.LKM])}}
        with self.assertRaisesRegex(RuntimeError, 'complete verified offline'):
            package_release.current_kernelsu_paths(self.workspace, metadata)
        system = self.workspace / 'images/system.img'
        system.write_bytes(b'current image fixture')
        destination = self.workspace / 'bundle'
        with self.assertRaisesRegex(RuntimeError, 'every verified runtime asset'):
            package_release.write_bundle(destination, 'pad-vtest', metadata, {'images/system.img': system}, 1)
        self.assertFalse(destination.exists())
        self.assertEqual(system.read_bytes(), b'current image fixture')

    def test_actual_current_receipt_updates_metadata_and_refuses_legacy_format2(self):
        info = build_info()
        path = self.workspace / 'local/build.json'
        path.write_text(json.dumps(info))
        legacy = package_release.release_metadata(self.workspace, 'os4-pad')
        self.assertEqual(legacy['kernelsu'], '3.3.0 (32601)')
        info['kernelsu_marker_fix'] = patch_kernelsu.receipt(self.assets[release.LKM])
        path.write_text(json.dumps(info))
        current = package_release.release_metadata(self.workspace, 'os4-pad')
        self.assertEqual(current['kernelsu'], '3.3.1 (32680)')
        self.assertEqual(current['build']['kernelsu_marker_fix'], info['kernelsu_marker_fix'])
        nonportable = {'format': 2, 'variant': 'os4-official', 'build': info}
        with self.assertRaisesRegex(RuntimeError, 'portable format3'):
            package_release.current_kernelsu_paths(self.workspace, nonportable)
        with self.assertRaisesRegex(RuntimeError, 'portable format3'):
            package_release.write_bundle(self.workspace / 'bundle', 'vtest', nonportable, {}, 1)
        self.assertFalse((self.workspace / 'bundle').exists())

if __name__ == '__main__':
    unittest.main()
