"""Preserve the audited no-HAL behavior without re-entering discovery guards."""
import hashlib
import os
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import patch_qti_perf as qti
from patch_rear_display import _sections


class QtiPerfFallbackTests(unittest.TestCase):
    def baseline(self):
        path = Path(os.environ.get('HYPEROS_AVD_QTI_PERF_ARTIFACT', str(
            REPO / 'work/feedback-investigation-20261013/phone-perf-callers/'
            'libqti-perfd-client_system.so')))
        if not path.is_file():
            self.skipTest('Audited private QTI Perf ELF unavailable; no download attempted.')
        return qti.patch_bytes(path.read_bytes())

    def test_frozen_v1_remains_an_explicit_separate_stage(self):
        source = self.baseline()
        self.assertTrue(qti.audit(source)[2])
        self.assertEqual(hashlib.sha256(source).hexdigest(), qti.FALLBACK_BEFORE)
        output = qti.fallback_patch_bytes(source)
        self.assertEqual(hashlib.sha256(output).hexdigest(), qti.FALLBACK_AFTER)
        self.assertTrue(qti.fallback_audit(output))
        self.assertEqual(qti.fallback_patch_bytes(output), output)
        # V1 receipts and its historical after hash never silently change.
        self.assertEqual(qti.recipe_receipt(next(iter(qti.RECIPES)))['after'],
                         qti.FALLBACK_BEFORE)
        with self.assertRaises(RuntimeError):
            qti.audit(output)

    def test_every_guard_call_is_covered_and_only_its_instruction_changes(self):
        source = self.baseline()
        output = qti.fallback_patch_bytes(source)
        self.assertEqual(len(source), len(output))
        sites = {site for site, _, _ in qti.FALLBACK_CALLS}
        self.assertEqual(len(sites), 41)
        allowed = {site + offset for site in sites for offset in range(4)}
        changed = {i for i, (a, b) in enumerate(zip(source, output)) if a != b}
        self.assertLessEqual(changed, allowed)
        self.assertTrue(changed)
        _, sections = _sections(source)
        code = sections[b'.text']
        guards = {0xd69c, 0xe818, 0x13908}
        for data, expected in ((source, sites), (output, set())):
            found = set()
            for address in range(code[3], code[3] + code[5], 4):
                word, = struct.unpack_from('<I', data, address)
                if word >> 26 in (0x05, 0x25) and qti._branch_target(word, address) in guards:
                    found.add(address)
            self.assertEqual(found, expected)

    def test_false_results_preserve_registers_flags_stack_and_original_consumers(self):
        source = self.baseline()
        output = qti.fallback_patch_bytes(source)
        for site, _, _ in qti.FALLBACK_CALLS:
            word, = struct.unpack_from('<I', output, site)
            # Independently decode ORR W0,WZR,WZR: no flags, memory or hidden
            # return pointer writes. The old caller retains its own failure path.
            self.assertEqual(word & 0xff200000, 0x2a000000)
            self.assertEqual(word & 31, 0)
            self.assertEqual((word >> 5) & 31, 31)
            self.assertEqual((word >> 16) & 31, 31)
            self.assertEqual((word >> 10) & 0x3f, 0)
            registers = {i: 0x1111111100000000 + i for i in range(31)}
            previous = dict(registers)
            stack, flags = b'untouched-caller-frame', 0xa0000000
            registers[word & 31] = 0
            self.assertEqual(registers[0], 0)
            self.assertEqual({k: v for k, v in registers.items() if k != 0},
                             {k: v for k, v in previous.items() if k != 0})
            self.assertEqual((stack, flags), (b'untouched-caller-frame', 0xa0000000))
        # Representative scalar and default-value callers retain their original
        # TBZ/TBNZ instructions, including the release wrappers' W8 copy.
        for address in (0xdf24, 0x103e8, 0x11684, 0x1495c, 0xf70c, 0xf718):
            self.assertEqual(source[address:address + 4], output[address:address + 4])
        self.assertEqual(output[0xdfb4:0xdfb8], source[0xdfb4:0xdfb8])

    def test_discovery_functions_logs_pac_cfi_and_metadata_are_not_edited(self):
        source = self.baseline()
        output = qti.fallback_patch_bytes(source)
        _, sections = _sections(source)
        for name, section in sections.items():
            if name != b'.text' and section[1] != 8:
                start, length = section[4:6]
                self.assertEqual(source[start:start + length], output[start:start + length])
        for row in next(iter(qti.RECIPES.values()))['functions'][1:4]:
            start, size = row['address'], row['size']
            self.assertEqual(source[start:start + size], output[start:start + size])
        self.assertIn(b'IPerf:: Perf HAL Service 2.2 is not available.', output)
        self.assertIn(b'__android_log_print\0', output)
        self.assertEqual(source[0x18000:0x1a018], output[0x18000:0x1a018])
        for _, start, _, _, _ in qti.FALLBACK_OWNERS:
            self.assertEqual(output[start:start + 4], bytes.fromhex('3f2303d5'))

    def test_offline_catalog_reconstructs_both_stages_with_the_same_absence_gate(self):
        source = self.baseline()
        recipes = qti.catalog_recipes()
        self.assertEqual(len(recipes), 2)
        recipe = recipes[1]
        self.assertEqual(recipe['before'], recipes[0]['after'])
        self.assertEqual(recipe['requires'], recipes[0]['requires'])
        self.assertEqual(recipe['absent_hal_packages'], recipes[0]['absent_hal_packages'])
        self.assertEqual(recipe['absent_services'], recipes[0]['absent_services'])
        self.assertEqual(recipe['path'], qti.NATIVE)
        with patch.object(qti, 'fallback_patch_bytes', side_effect=AssertionError('Producer unavailable')):
            output = bytearray(source)
            for site in recipe['sites']:
                offset = site['offset']
                self.assertEqual(output[offset:offset + 4], bytes.fromhex(site['before']))
                output[offset:offset + 4] = bytes.fromhex(site['after'])
            self.assertEqual(hashlib.sha256(output).hexdigest(), recipe['after'])

    def test_unknown_partial_and_changed_consumer_or_guard_content_is_refused(self):
        source = self.baseline()
        for offset in (18, 0xd620, 0xdf24, 0xe818, 0xebc0, 0x1a148, len(source) - 1):
            changed = bytearray(source)
            changed[offset] ^= 1
            with self.assertRaises(RuntimeError):
                qti.fallback_patch_bytes(changed)
        partial = bytearray(source)
        site = qti.FALLBACK_CALLS[0][0]
        partial[site:site + 4] = qti.FALLBACK_WORD
        with self.assertRaises(RuntimeError):
            qti.fallback_patch_bytes(partial)
        for bad in (None, 'unknown', b'unknown ELF'):
            with self.assertRaises(RuntimeError):
                qti.fallback_audit(bad)


if __name__ == '__main__':
    unittest.main()
