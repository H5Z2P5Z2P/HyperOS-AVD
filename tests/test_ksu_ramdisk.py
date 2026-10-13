"""Verify bounded offline ramdisk derivation and immutable local cache ownership."""
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import ksu_ramdisk as fixes
import patch_kernelsu
import kernelsu_release


def cpio(items):
    output = bytearray()
    for index, (name, data, metadata) in enumerate([*items, (b'TRAILER!!!', b'', {})]):
        fields = [index + 100, 0o100755, 0, 0, 1, 1700000000, len(data),
                  0, 0, 0, 0, len(name) + 1, 0]
        for key, value in metadata.items():
            fields[key] = value
        output.extend(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields))
        output.extend(name + b'\0')
        output.extend(b'\0' * (-len(output) % 4))
        output.extend(data)
        output.extend(b'\0' * (-len(output) % 4))
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
        # One literal A, an overlapping four-byte repeat, then one final Z.
        block = b'\x10A\x01\0\x10Z'
        packed = fixes.LZ4_MAGIC + struct.pack('<I', len(block)) + block
        self.assertEqual(fixes.unpack(packed), ('lz4-legacy', b'AAAAAZ'))

    def test_lz4_corruption_and_expansion_bounds_are_rejected(self):
        malformed = [b'', b'\x10', b'\x10A\0\0\0', b'\x10A\x02\0\0',
                     b'\xf0\xff', b'\x10A\x01', b'\x11A']
        for block in malformed:
            packed = fixes.LZ4_MAGIC + struct.pack('<I', len(block)) + block
            with self.subTest(block=block), self.assertRaises(RuntimeError):
                fixes.unpack(packed)
        valid = fixes.pack('lz4-legacy', b'12345')
        for value in (valid[:-1], valid + b'x', fixes.LZ4_MAGIC,
                      fixes.LZ4_MAGIC + b'\xff' * 4):
            with self.subTest(size=len(value)), self.assertRaises(RuntimeError):
                fixes.unpack(value)
        with patch.object(fixes, 'MAX_LZ4_BLOCK', 4):
            with self.assertRaisesRegex(RuntimeError, 'oversized'):
                fixes.unpack(valid)

    def test_gzip_trailer_optional_headers_multiple_members_and_size_bound_fail_closed(self):
        value = fixes.pack('gzip', b'0123456789')
        for bad in (value[:-1], value + value, value[:3] + b'\x08' + value[4:],
                    value[:-8] + b'\0' * 8):
            with self.subTest(size=len(bad)), self.assertRaises(RuntimeError):
                fixes.unpack(bad)
        with patch.object(fixes, 'MAX_RAMDISK', len(value)):
            compressed = __import__('gzip').compress(b'x' * 1024, mtime=0)
            with self.assertRaisesRegex(RuntimeError, 'Oversized'):
                fixes.unpack(compressed)

    def test_cpio_malformed_names_duplicate_entries_crc_and_trailing_archives_are_rejected(self):
        good = cpio([(b'other', b'data', {})])
        self.assertEqual(len(fixes.parse_cpio(good)), 2)
        variants = [good[:-1], good + good, good.replace(b'070701', b'070702', 1),
                    cpio([(b'../escape', b'', {})]), cpio([(b'/absolute', b'', {})]),
                    cpio([(b'dup', b'1', {}), (b'dup', b'2', {})]),
                    cpio([(b'dup', b'1', {}), (b'./dup', b'2', {})]),
                    cpio([(b'bad\0name', b'', {})])]
        for bad in variants:
            with self.subTest(size=len(bad)), self.assertRaises(RuntimeError):
                fixes.parse_cpio(bad)
        self.assertEqual(fixes.parse_cpio(good + b'\0' * 512), fixes.parse_cpio(good))


class RamdiskArtifactFixture:
    @classmethod
    def setUpClass(cls):
        path = REPO / 'tools' / patch_kernelsu.ASSET
        if not path.is_file():
            raise unittest.SkipTest('Official KernelSU asset is not cached.')
        cls.module = path.read_bytes()
        patch_kernelsu.audit(cls.module)

    def archive(self, member=None, metadata=None, extra=None):
        items = [(b'init', b'original init bytes', {5: 123, 0: 700}),
                 (b'symlink', b'init', {1: 0o120777, 0: 701}),
                 (fixes.MEMBER, self.module if member is None else member, metadata or {})]
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
        variants = [self.archive(member=b'unknown module'),
                    self.archive(metadata={4: 2}), self.archive(metadata={2: 2000}),
                    self.archive(metadata={1: 0o120777}),
                    self.archive(extra=[(b'alias.ko', self.module, {})]),
                    self.archive(extra=[(b'inode-alias', b'', {0: 102, 4: 2})]),
                    cpio([(b'init', b'init', {})])]
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
        self.assertEqual(marker['output_sha256'],
                         '73eb1206806a2b282328195c1a53bd0d2567dad3c5924181e31b87f0c96c7e00')
        self.assertEqual(marker['output_size'], 4481427)
        _, before = fixes.unpack(original)
        _, after = fixes.unpack(output)
        self.assertEqual(len(before), 4463912)
        self.assertEqual(fixes.parse_cpio(before), fixes.parse_cpio(after))
        entries = fixes.parse_cpio(before)
        self.assertEqual(len(entries), 32)
        for entry in entries:
            start, end = entry['offset'], entry['end']
            if entry['name'] == fixes.MEMBER:
                body = entry['body']
                self.assertEqual(before[start:body], after[start:body])
                self.assertEqual(patch_kernelsu.audit(after[body:body + entry['size']])['sha256'],
                                 patch_kernelsu.AFTER)
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
        return self.archive(member=member, extra=[(b'ksu_config', config, {1: 0o100644})])

    def test_current_replacement_updates_only_member_size_body_padding_and_keeps_config(self):
        before = self.configured_archive()
        for kind in ('cpio', 'lz4-legacy', 'gzip'):
            with self.subTest(kind=kind):
                output, marker = fixes.patch_ramdisk(fixes.pack(kind, before), target=self.current)
                _, after = fixes.unpack(output)
                old_entries, new_entries = fixes.parse_cpio(before), fixes.parse_cpio(after)
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
                self.assertEqual(marker['original_config'], {
                    'sha256': hashlib.sha256(b'allow_shell=1').hexdigest(), 'parameters': ['allow_shell']})
                self.assertIsNone(fixes.patch_ramdisk(output, target=self.current)[0])

    def test_old_quiet_source_can_upgrade_and_new_official_source_can_be_quieted(self):
        for member in (patch_kernelsu.patch_bytes(self.module), self.current):
            with self.subTest(source=hashlib.sha256(member).hexdigest()):
                source = self.configured_archive(member=member)
                output, marker = fixes.patch_ramdisk(source, target=self.current)
                _, archive = fixes.unpack(output)
                entry = next(item for item in fixes.parse_cpio(archive) if item['name'] == fixes.MEMBER)
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
                source, stat = path.read_bytes(), path.stat()
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
        (workspace / 'local/build.json').write_text(json.dumps({
            'hyperos': 'OS4.0.999.0.XBMCNXM', 'android_api': 37,
            'kernel_page_size': 4096, 'hardware_base_api': 36}))
        (workspace / 'images/source.properties').write_text(
            'SystemImage.Abi=arm64-v8a\nAndroidVersion.ApiLevel=36\n')
        (workspace / 'images/kernel-ranchu').write_bytes(self.kernel)
        (workspace / 'images/ramdisk.img').write_bytes(fixes.pack('lz4-legacy', self.archive()))
        return workspace.resolve()

    def quiet_prepare(self, workspace):
        with redirect_stdout(io.StringIO()) as text:
            result = fixes.prepare_runtime(workspace)
        return result, text.getvalue()

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
        (source / 'local/installed-release.json').write_text(json.dumps(
            {'project': 'HyperOS-AVD', 'version': version, 'files': files}))
        (workspace / 'local/manager.json').write_text(json.dumps(
            {'schema': 1, 'version': version, 'runtime': 'versions/' + version + '/runtime'}))
        return source

    def current_stack(self):
        try:
            path = kernelsu_release.asset(REPO, kernelsu_release.LKM)
        except (RuntimeError, OSError) as error:
            self.skipTest('Current official KernelSU fixture is unavailable: ' + str(error))
        return (patch.object(kernelsu_release, 'available', return_value=True),
                patch.object(kernelsu_release, 'asset', return_value=path))

    def test_current_offline_stack_upgrades_legacy_cache_but_legacy_receipt_still_verifies(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            legacy, _ = self.quiet_prepare(workspace)
            before = {path: (path.read_bytes(), path.stat().st_ino) for path in
                      (legacy, legacy.with_suffix('.json'), workspace / 'images/ramdisk.img')}
            available, asset = self.current_stack()
            with available, asset:
                current, message = self.quiet_prepare(workspace)
                self.assertIsNotNone(current, message)
                self.assertNotEqual(current, legacy)
                self.assertEqual(fixes.verify_cache(workspace, legacy), legacy)
                self.assertEqual(fixes.verify_cache(workspace, current), current)
                self.assertEqual(json.loads(current.with_suffix('.json').read_text())['target_release'], kernelsu_release.VERSION)
            # Proof of an existing current cache is self-contained: it does
            # not require re-downloading the target official attachment.
            self.assertEqual(fixes.verify_cache(workspace, current), current)
            self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_ino) for path in before})

    def test_saved_current_target_receipt_reproduces_frozen_source_and_refreshes_after_image_switch(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            available, asset = self.current_stack()
            with available, asset:
                old, _ = self.quiet_prepare(workspace)
                self.frozen_source(workspace)
                original = old.read_bytes(), old.with_suffix('.json').read_bytes()
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
            original = relocated.read_bytes(), relocated.with_suffix('.json').read_bytes()
            self.assertEqual(fixes.rebase_cache_selection(workspace, current, old_images), relocated)
            self.assertEqual(original, (relocated.read_bytes(), relocated.with_suffix('.json').read_bytes()))

    def test_stale_owned_cache_refresh_authenticates_one_saved_source_and_preserves_old_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            old_cache, _ = self.quiet_prepare(workspace)
            source = self.frozen_source(workspace)
            before = {path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                      for path in (*source.rglob('*'), old_cache, old_cache.with_suffix('.json'))
                      if path.is_file()}
            current = workspace / 'images/ramdisk.img'
            current.write_bytes(fixes.pack('gzip', self.archive()))
            selected = fixes.refresh_saved_cache(workspace, old_cache)
            self.assertNotEqual(selected, old_cache)
            self.assertEqual(fixes.verify_cache(workspace, selected), selected)
            self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                                      for path in before})
            self.assertEqual(current.read_bytes(), fixes.pack('gzip', self.archive()))

    def test_stale_cache_can_clear_override_only_for_an_authenticated_prepatched_current_source(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            old_cache, _ = self.quiet_prepare(workspace)
            self.frozen_source(workspace, version='pad-v0.1.1-a17-hyperos4-yingtian-r2')
            (workspace / 'images/ramdisk.img').write_bytes(
                self.archive(member=patch_kernelsu.patch_bytes(self.module)))
            self.assertIsNone(fixes.refresh_saved_cache(workspace, old_cache))
            self.assertTrue(old_cache.is_file())
            self.assertTrue(old_cache.with_suffix('.json').is_file())

    def test_stale_cache_missing_modified_and_aliased_provenance_is_refused_without_writes(self):
        for change in ('missing-manager', 'version-traversal', 'manifest-hash', 'old-source',
                       'kernel', 'receipt', 'cache', 'source-directory-alias'):
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
            with patch.object(fixes, 'prepare_runtime', return_value=None), \
                    self.assertRaisesRegex(RuntimeError, 'existing selection was retained'):
                fixes.refresh_saved_cache(workspace, old_cache)

    def test_reserved_cache_locator_is_generic_and_does_not_follow_foreign_custom_selections(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = self.workspace(folder)
            self.assertTrue(fixes.is_owned_cache_selection(workspace,
                workspace / 'local/boot-patches' / ('ramdisk-' + 'a' * 64 + '.img')))
            for path in (workspace / 'user/custom.img', workspace / 'local/boot-patches/custom.img',
                         workspace / 'local/boot-patches' / ('ramdisk-' + 'a' * 64 + '.img/extra')):
                self.assertFalse(fixes.is_owned_cache_selection(workspace, path))

    def test_moved_workspace_cache_rebase_uses_previous_image_binding_and_exact_current_proof(self):
        with tempfile.TemporaryDirectory() as folder:
            previous = self.workspace(folder)
            old_cache, _ = self.quiet_prepare(previous)
            old_images = str(previous / 'images') + '/'
            workspace = previous.with_name('Moved workspace')
            previous.rename(workspace)
            relocated = workspace / old_cache.relative_to(previous)
            before = relocated.read_bytes(), relocated.stat().st_ino, relocated.stat().st_mtime_ns
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
        for change in ('old-still-exists', 'foreign-binding', 'custom-name', 'traversal-binding',
                       'tampered-cache', 'tampered-receipt', 'dangling-old-alias'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                previous = self.workspace(folder)
                old_cache, _ = self.quiet_prepare(previous)
                workspace = previous.with_name('Moved workspace')
                previous.rename(workspace)
                selected, binding = old_cache, str(previous / 'images')
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
            before, info = source.read_bytes(), source.stat()
            result, message = self.quiet_prepare(workspace)
            self.assertIsNotNone(result, message)
            self.assertIn('separate local ramdisk', message)
            self.assertEqual(result.parent, workspace / 'local/boot-patches')
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual((source.stat().st_ino, source.stat().st_mtime_ns),
                             (info.st_ino, info.st_mtime_ns))
            all_before = {p.name: (p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes())
                          for p in result.parent.iterdir()}
            self.assertEqual(fixes.verify_cache(workspace, result), result)
            self.assertEqual(self.quiet_prepare(workspace)[0], result)
            all_after = {p.name: (p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes())
                         for p in result.parent.iterdir()}
            self.assertEqual(all_before, all_after)

    def test_unknown_kernel_abi_page_size_build_and_ramdisk_skip_without_writes(self):
        for change in ('kernel', 'abi', 'page-size', 'build', 'module'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                workspace = self.workspace(folder)
                if change == 'kernel':
                    (workspace / 'images/kernel-ranchu').write_bytes(b'unknown kernel')
                elif change == 'abi':
                    (workspace / 'images/source.properties').write_text(
                        'SystemImage.Abi=x86_64\nAndroidVersion.ApiLevel=36\n')
                elif change in ('page-size', 'build'):
                    path = workspace / 'local/build.json'
                    data = json.loads(path.read_text())
                    data['kernel_page_size' if change == 'page-size' else 'hyperos'] = (
                        16384 if change == 'page-size' else '3.0.0.0.UNKNOWN')
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
            original_receipt, original_image = receipt.read_bytes(), path.read_bytes()
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
