"""Check the exact KernelSU task-scan derivative without a guest or compiler."""
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import patch_kernelsu as fixes
from common import KSU_ASSETS
import kernelsu_release


class KernelSUUnknownInputTests(unittest.TestCase):
    def test_unknown_input_does_not_create_output_or_replace_existing_data(self):
        with tempfile.TemporaryDirectory() as folder:
            source, output = Path(folder) / 'source.ko', Path(folder) / 'new/output.ko'
            source.write_bytes(b'unknown ELF')
            with self.assertRaisesRegex(RuntimeError, 'Unsupported KernelSU'):
                fixes.patch(source, output)
            self.assertFalse(output.parent.exists())
            output.parent.mkdir()
            output.write_bytes(b'user customized output')
            with self.assertRaisesRegex(RuntimeError, 'Unsupported KernelSU'):
                fixes.patch(source, output)
            self.assertEqual(output.read_bytes(), b'user customized output')

    def test_exact_official_asset_pin_remains_the_download_authority(self):
        self.assertEqual(fixes.BEFORE, KSU_ASSETS[fixes.ASSET])
        self.assertEqual(fixes.BEFORE,
                         'c31d994aaf285e7bf4cf1ec38c2bbf2d7f303d1a4a7d616405bcd9f850d684e5')
        self.assertNotEqual(fixes.AFTER, fixes.BEFORE)
        self.assertEqual(fixes.receipt()['source_review_commit'],
                         '932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e')
        self.assertNotIn('source_build_commit', fixes.receipt())

    def test_current_receipt_uses_canonical_release_and_keeps_legacy_default(self):
        before = kernelsu_release.ASSETS[fixes.ASSET]
        current = fixes.receipt(before)
        self.assertEqual(current['before'], before)
        self.assertEqual(current['version'], kernelsu_release.VERSION)
        self.assertEqual(current['source_review_commit'], kernelsu_release.REVIEW_COMMIT)
        self.assertEqual(current['source_review_commit'], '0c0fdb960178fa12d80d6cbcfdcb6ad8be6a865d')
        self.assertEqual((current['site'], current['resume']), (0x21dc, 0x21ec))
        self.assertEqual(fixes.receipt()['before'], fixes.BEFORE)
        self.assertEqual(fixes.receipt()['after'], fixes.AFTER)
        self.assertEqual(fixes.receipt(current['after']), current)
        self.assertNotIn('source_build_commit', current)
        for value in (b'unknown', 'unknown', True, 1, {}, []):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, 'Unsupported KernelSU'):
                    fixes.receipt(value)


class KernelSUArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = REPO / 'tools' / fixes.ASSET
        if not source.is_file():
            raise unittest.SkipTest('Official KernelSU asset is not cached.')
        cls.original = source.read_bytes()
        if hashlib.sha256(cls.original).hexdigest() != fixes.BEFORE:
            raise AssertionError('Cached official KernelSU module was modified.')
        cls.modified = fixes.patch_bytes(cls.original)

    def test_the_only_changed_instruction_branches_to_existing_credential_cleanup(self):
        audit = fixes.audit(self.original)
        offset = audit['offset']
        self.assertEqual(offset, 0x7164)
        self.assertEqual(self.original[offset:offset + 4], fixes.ORIGINAL)
        self.assertEqual(self.modified[offset:offset + 4], fixes.BRANCH)
        self.assertEqual(self.original[:offset], self.modified[:offset])
        self.assertEqual(self.original[offset + 4:], self.modified[offset + 4:])
        instruction = struct.unpack_from('<I', self.modified, offset)[0]
        self.assertEqual(instruction >> 26, 0b000101)  # ARM64 unconditional B.
        self.assertEqual(fixes.SITE + (instruction & 0x3ffffff) * 4, fixes.RESUME)
        self.assertEqual(self.modified[0x7174:0x717c], bytes.fromhex('13faffb405000014'))
        self.assertEqual(hashlib.sha256(self.modified).hexdigest(), fixes.AFTER)

    def test_all_relocations_symbols_strings_permissions_and_locks_are_preserved(self):
        header = struct.unpack_from('<16sHHIQQQIHHHHHH', self.original)
        sections = [struct.unpack_from('<IIQQQQIIQQ', self.original, header[6] + i * 64)
                    for i in range(header[12])]
        relocation_count = 0
        for section in sections:
            if section[1] not in (2, 3, 4):  # All symbol/string/RELA sections.
                continue
            offset, size = section[4:6]
            self.assertEqual(self.original[offset:offset + size],
                             self.modified[offset:offset + size])
            if section[1] == 4:
                relocation_count += size // section[9]
        self.assertGreater(relocation_count, 4000)
        # Mark/clear atomics and branch convergence precede the skipped call.
        self.assertEqual(self.modified[0x7148:0x7164], self.original[0x7148:0x7164])
        # The loop, predicate checks, lock acquisition and cleanup stay exact.
        self.assertEqual(self.modified[0x7028:0x7148], self.original[0x7028:0x7148])
        self.assertEqual(self.modified[0x7174:0x720c], self.original[0x7174:0x720c])
        # Outer IRQ lock and unrelated direct task marking/logging stay exact.
        self.assertEqual(self.modified[0x7210:0x7500], self.original[0x7210:0x7500])

    def test_after_is_idempotent_and_unknown_partial_or_tampered_content_is_refused(self):
        self.assertTrue(fixes.audit(self.modified)['patched'])
        self.assertIs(fixes.patch_bytes(self.modified), self.modified)
        variants = [self.original[:-1], self.original + b'\0', b'', bytearray(self.original)]
        for offset in (0, 0x7164, 0x26ed8, len(self.original) - 1):
            value = bytearray(self.original)
            value[offset] ^= 1
            variants.append(bytes(value))
        for data in variants:
            with self.subTest(size=len(data)):
                with self.assertRaisesRegex(RuntimeError, 'Unsupported KernelSU'):
                    fixes.patch_bytes(data)

    def test_atomic_output_preserves_official_asset_and_reuses_verified_output(self):
        with tempfile.TemporaryDirectory() as folder:
            source, output = Path(folder) / 'source.ko', Path(folder) / 'derivative.ko'
            source.write_bytes(self.original)
            source_before = source.stat()
            with patch.object(fixes, 'tempfile', wraps=fixes.tempfile) as temporary:
                self.assertEqual(fixes.patch(source, output), output)
                temporary.mkstemp.assert_called_once()
            self.assertEqual(source.read_bytes(), self.original)
            self.assertEqual((source.stat().st_ino, source.stat().st_mtime_ns),
                             (source_before.st_ino, source_before.st_mtime_ns))
            self.assertEqual(output.read_bytes(), self.modified)
            original_inode = output.stat().st_ino
            with patch.object(fixes.tempfile, 'mkstemp') as create:
                fixes.patch(source, output)
                create.assert_not_called()
            self.assertEqual(output.stat().st_ino, original_inode)
            self.assertEqual(sorted(item.name for item in Path(folder).iterdir()),
                             ['derivative.ko', 'source.ko'])

    def test_source_overwrite_custom_output_links_and_aliases_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            source, output = Path(folder) / 'source.ko', Path(folder) / 'derivative.ko'
            source.write_bytes(self.original)
            with self.assertRaisesRegex(RuntimeError, 'official KernelSU source'):
                fixes.patch(source, source)
            output.write_bytes(b'custom')
            with self.assertRaisesRegex(RuntimeError, 'unknown KernelSU derivative'):
                fixes.patch(source, output)
            self.assertEqual(output.read_bytes(), b'custom')
            output.unlink()
            output.symlink_to(source)
            with self.assertRaisesRegex(RuntimeError, 'official KernelSU source'):
                fixes.patch(source, output)
            output.unlink()
            alias = Path(folder) / 'alias.ko'
            output.write_bytes(self.modified)
            os.link(output, alias)
            with self.assertRaisesRegex(RuntimeError, 'Unsafe KernelSU derivative'):
                fixes.patch(source, output)
            self.assertEqual(output.read_bytes(), self.modified)

    def test_atomic_publish_does_not_overwrite_a_racing_unknown_output(self):
        with tempfile.TemporaryDirectory() as folder:
            source, output = Path(folder) / 'source.ko', Path(folder) / 'derivative.ko'
            source.write_bytes(self.original)
            real_link = os.link
            def raced(temporary, destination):
                Path(destination).write_bytes(b'new user output')
                return real_link(temporary, destination)
            with patch.object(fixes.os, 'link', side_effect=raced):
                with self.assertRaisesRegex(RuntimeError, 'unexpectedly created'):
                    fixes.patch(source, output)
            self.assertEqual(output.read_bytes(), b'new user output')
            self.assertEqual(sorted(p.name for p in Path(folder).iterdir()),
                             ['derivative.ko', 'source.ko'])


class CurrentKernelSUArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = REPO / 'tools' / kernelsu_release.DIRECTORY / fixes.ASSET
        if not source.is_file():
            raise unittest.SkipTest('Current official KernelSU asset is not cached.')
        cls.original = source.read_bytes()
        cls.before = kernelsu_release.ASSETS[fixes.ASSET]
        if hashlib.sha256(cls.original).hexdigest() != cls.before:
            raise AssertionError('Current cached official KernelSU module was modified.')
        cls.modified = fixes.patch_bytes(cls.original)
        cls.receipt = fixes.receipt(cls.before)

    def test_only_new_nonrelocated_site_branches_to_credential_cleanup(self):
        self.assertEqual(len(self.original), 330664)
        verified = fixes.audit(self.original)
        self.assertEqual(verified['offset'], 0x71dc)
        self.assertEqual(verified['receipt'], self.receipt)
        self.assertEqual(self.original[0x71dc:0x71e0], fixes.ORIGINAL)
        self.assertEqual(self.modified[0x71dc:0x71e0], fixes.BRANCH)
        self.assertEqual(self.original[:0x71dc], self.modified[:0x71dc])
        self.assertEqual(self.original[0x71e0:], self.modified[0x71e0:])
        self.assertEqual(self.modified[0x71ec:0x71f4], bytes.fromhex('13faffb405000014'))
        self.assertEqual(hashlib.sha256(self.modified).hexdigest(), self.receipt['after'])
        self.assertEqual(self.receipt['after'], '055a4fc38fa8a8f55233b7c576cadcc54a3a79ba080bc073b8aacf0b85b82305')

    def test_new_function_is_independently_bound_and_all_relocations_unchanged(self):
        header = struct.unpack_from('<16sHHIQQQIHHHHHH', self.original)
        sections = [struct.unpack_from('<IIQQQQIIQQ', self.original, header[6] + index * 64)
                    for index in range(header[12])]
        count = 0
        for section in sections:
            if section[1] not in (2, 3, 4):
                continue
            offset, size = section[4:6]
            self.assertEqual(self.original[offset:offset + size], self.modified[offset:offset + size])
            if section[1] == 4:
                count += size // section[9]
        self.assertGreater(count, 4400)
        self.assertEqual(hashlib.sha256(self.original[0x70a0:0x7284]).hexdigest(),
                         fixes.FUNCTION_HASHES[fixes.BEFORE])
        self.assertEqual(hashlib.sha256(self.modified[0x70a0:0x7284]).hexdigest(),
                         fixes.FUNCTION_HASHES[fixes.AFTER])
        # Exact full-byte preservation covers all unrelated task logging,
        # credential references, marker atomics, locks and SELinux behavior.
        self.assertEqual(self.modified[0x71c0:0x71dc], fixes.FLOW_GUARD[:0x1c])

    def test_current_after_is_idempotent_and_partial_or_tampered_input_refuses(self):
        self.assertTrue(fixes.audit(self.modified)['patched'])
        self.assertIs(fixes.patch_bytes(self.modified), self.modified)
        variants = [self.original[:-1], self.original + b'\0', bytearray(self.original)]
        for offset in (0, 0x71dc, 0x21e8 + 0x5000, 154920, len(self.original) - 1):
            altered = bytearray(self.original)
            altered[offset] ^= 1
            variants.append(bytes(altered))
        for value in variants:
            with self.assertRaisesRegex(RuntimeError, 'Unsupported KernelSU'):
                fixes.patch_bytes(value)

    def test_atomic_current_output_reuse_preserves_official_source(self):
        with tempfile.TemporaryDirectory() as folder:
            source, output = Path(folder) / 'official.ko', Path(folder) / 'quiet.ko'
            source.write_bytes(self.original)
            fixes.patch(source, output)
            inode = output.stat().st_ino
            fixes.patch(source, output)
            self.assertEqual(output.stat().st_ino, inode)
            self.assertEqual(output.read_bytes(), self.modified)
            self.assertEqual(source.read_bytes(), self.original)
            with self.assertRaisesRegex(RuntimeError, 'official KernelSU source'):
                fixes.patch(source, source)


if __name__ == '__main__':
    unittest.main()
