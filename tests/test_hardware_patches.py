"""Consolidated unit tests for OS4 hardware, performance, and vendor capability patches."""
import copy
import hashlib
import io
import itertools
import json
import math
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile
import zlib

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import package_native_module
import patch_bufferqueue_perf as perf
import patch_display_brightness as brightness
import patch_display_metadata as metadata
import patch_display_privacy as privacy
import patch_perfflinger as perfflinger
import patch_qti_perf as qti
from patch_rear_display import _sections
import patch_rear_input_policy as policy
import patch_thermal_capability as thermal
import patch_uniperf as uniperf
import patch_wifi_capabilities as wifi
import patch_xiaomi_ims as ims
import patch_xqos as xqos
import patch_xqos
import tcm_capability as tcm_producer
import test_native_module_runtime as fixture



# --- tests/test_bufferqueue_perf_patch.py ---

"""Verify the physical hint return without changing BufferQueue behavior."""

def execute_hint(data, start, corrupt_canary=False):
    """Interpret the small actual AArch64 path, rejecting any hardware call.

    This independent decoder exercises stack restoration and the checked
    failure path; it does not use the producer's frame or target constants.
    """
    registers = {index: 0x1000 + index for index in range(31)}
    initial = dict(registers)
    stack, initial_stack, tls = 0x10000, 0x10000, 0x8000
    memory = {tls + 0x28: 0x123456789abcdef0}
    equal, visited = False, []

    def read(index, sp=False):
        return stack if sp and index == 31 else registers.get(index, 0)

    for _ in range(40):
        pc = start
        visited.append(pc)
        word, = struct.unpack_from('<I', data, pc)
        start += 4
        rd, rn, rm = word & 31, (word >> 5) & 31, (word >> 16) & 31
        if word == 0xd65f03c0:  # RET
            return initial, registers, initial_stack, stack, visited
        if word >> 26 == 0x25:  # BL must never execute on driver-free hardware.
            raise AssertionError('Unexpected call on the unsupported hint path.')
        if word >> 26 == 0x05:  # B
            displacement = word & 0x3ffffff
            if displacement & 0x2000000:
                displacement -= 0x4000000
            start = pc + displacement * 4
            continue
        if word & 0xff000010 == 0x54000000:  # B.NE
            if word & 15 != 1:
                raise AssertionError('Unexpected conditional branch.')
            if not equal:
                displacement = (word >> 5) & 0x7ffff
                if displacement & 0x40000:
                    displacement -= 0x80000
                start = pc + displacement * 4
            continue
        if word & 0xff000000 in (0x91000000, 0xd1000000):  # ADD/SUB immediate.
            immediate = ((word >> 10) & 0xfff) << (12 if word & (1 << 22) else 0)
            value = read(rn, sp=True) + (-immediate if word & (1 << 30) else immediate)
            if rd == 31:
                stack = value
            else:
                registers[rd] = value
            continue
        if word & 0xffc00000 in (0xa9000000, 0xa9400000):  # STP/LDP offset.
            displacement = (word >> 15) & 0x7f
            if displacement & 0x40:
                displacement -= 0x80
            address = read(rn, sp=True) + displacement * 8
            second = (word >> 10) & 31
            if word & (1 << 22):
                registers[rd], registers[second] = memory[address], memory[address + 8]
            else:
                memory[address], memory[address + 8] = read(rd), read(second)
            continue
        if word & ~31 == 0xd53bd040:  # MRS TPIDR_EL0.
            registers[rd] = tls
            continue
        if word & 0xffe0ffe0 in (0x2a0003e0, 0xaa0003e0):  # MOV register.
            value = read(rm)
            registers[rd] = value if word & (1 << 31) else value & 0xffffffff
            continue
        if word & 0xffc00000 == 0xf9400000:  # LDR unsigned offset.
            registers[rd] = memory[read(rn, sp=True) + ((word >> 10) & 0xfff) * 8]
            continue
        if word & 0xffe00c00 in (0xf8000000, 0xf8400000):  # STUR/LDUR signed.
            displacement = (word >> 12) & 0x1ff
            if displacement & 0x100:
                displacement -= 0x200
            address = read(rn, sp=True) + displacement
            if word & (1 << 22):
                registers[rd] = memory[address]
            else:
                memory[address] = read(rd)
                if corrupt_canary:
                    memory[address] ^= 1
            continue
        if word & 0xffe0fc1f == 0xeb00001f:  # CMP register.
            equal = read(rn) == read(rm)
            continue
        raise AssertionError('Unexpected instruction %08x at %x.' % (word, pc))
    raise AssertionError('Unsupported hint did not return within its frame.')

class BufferQueuePerfPatchTests(unittest.TestCase):
    def artifact(self, kind='pad'):
        variable = 'HYPEROS_AVD_BUFFERQUEUE_' + kind.upper() + '_ARTIFACT'
        source = Path(os.environ.get(variable, str(
            REPO / 'work/feedback-investigation-20261013/bufferqueue-perf' / (kind + '-libgui.so'))))
        if not source.is_file():
            self.skipTest('Audited private BufferQueue ELF unavailable; no download attempted.')
        return source.read_bytes()

    def test_only_one_instruction_in_the_physical_hint_changes(self):
        source = self.artifact()
        before, recipe, already = perf.audit(source)
        self.assertFalse(already)
        output = perf.patch_bytes(source)
        self.assertEqual(hashlib.sha256(output).hexdigest(), recipe['after'])
        self.assertEqual(len(output), len(source))
        site = recipe['site']
        self.assertEqual(source[:site], output[:site])
        self.assertEqual(source[site + 4:], output[site + 4:])
        self.assertEqual(output[site:site + 4], bytes.fromhex('3b000014'))
        self.assertEqual(perf.patch_bytes(output), output)
        self.assertTrue(perf.audit(output)[2])

    def test_actual_checked_return_restores_every_callee_saved_register_and_stack(self):
        output = perf.patch_bytes(self.artifact())
        initial, result, original_sp, result_sp, visited = execute_hint(output, 0x153f80)
        self.assertEqual(visited, list(range(0x153f80, 0x153fb4, 4)) + list(range(0x15409c, 0x1540c4, 4)))
        self.assertEqual(original_sp, result_sp)
        for register in range(19, 31):
            self.assertEqual(result[register], initial[register], 'x%d not restored' % register)
        # The original canary failure remains reachable. It is not bypassed by
        # a synthetic immediate RET that would leave a live frame or mask damage.
        with self.assertRaisesRegex(AssertionError, 'Unexpected call'):
            execute_hint(output, 0x153f80, corrupt_canary=True)

    def test_queue_throttle_render_metadata_and_driver_diagnostics_are_unchanged(self):
        source = self.artifact()
        output = perf.patch_bytes(source)
        _, recipe, _ = perf.audit(output)
        start, size = recipe['address'], recipe['function_size']
        self.assertEqual(source[:start], output[:start])
        self.assertEqual(source[start + size:], output[start + size:])
        # Actual exported queueBuffer, dequeueBuffer and cancelBuffer extents.
        for start, size in ((0x126e04, 6360), (0x12885c, 5364), (0x152fc8, 1260)):
            self.assertEqual(source[start:start + size], output[start:start + size])
        _, sections = _sections(source)
        for name, section in sections.items():
            if name == b'.text' or section[1] == 8:
                continue
            offset, length = section[4:6]
            self.assertEqual(source[offset:offset + length], output[offset:offset + length], name)
        self.assertIn(b'/dev/xr_fbt\0', output)
        self.assertIn(b'sendPerfSignal open perf fbt fail', output)
        self.assertIn(b'__android_log_print\0', output)
        # Failed open/ioctl paths and their original logs remain byte identical.
        self.assertEqual(source[0x154018:0x154150], output[0x154018:0x154150])

    def test_offline_receipt_uses_one_canonical_hardware_capability(self):
        self.assertIs(perf.ABSENT_NODES, patch_xqos.ABSENT_NODES)
        self.assertEqual(perf.REQUIRES, patch_xqos.REQUIRES)
        receipt, = perf.catalog_recipes()
        self.assertEqual(receipt['path'], '/system/lib64/libgui.so')
        self.assertEqual(receipt['absent_nodes'], list(patch_xqos.ABSENT_NODES))
        source = self.artifact()
        result = bytearray(source)
        for site in receipt['sites']:
            self.assertEqual(result[site['offset']:site['offset'] + 4], bytes.fromhex(site['before']))
            result[site['offset']:site['offset'] + 4] = bytes.fromhex(site['after'])
        self.assertEqual(hashlib.sha256(result).hexdigest(), receipt['after'])
        self.assertEqual(perf.receipt(result), receipt)

    def test_phone_without_the_physical_hint_is_not_mistaken_for_an_audited_recipe(self):
        source = self.artifact('phone')
        self.assertEqual(hashlib.sha256(source).hexdigest(),
                         'eac6faa437e227198987def15b6c2d6d01ba03b5debaf51bcedc59c17cf474ea')
        for symbol in (perf.SYMBOL, b'/dev/xr_fbt\0', b'open perf fbt fail'):
            self.assertNotIn(symbol, source)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            perf.patch_bytes(source)

    def test_unknown_partial_and_structurally_changed_input_are_preserved(self):
        source = self.artifact()
        selected = perf.select_recipe(source)
        for offset in (4, 18, 0x80826, 0x126e04, 0x153f80, 0x153fb0, 0x1540a8, len(source) - 1):
            with self.subTest(offset=offset):
                changed = bytearray(source); changed[offset] ^= 1
                with self.assertRaises(RuntimeError):
                    perf.patch_bytes(changed)
                with patch.object(perf, 'select_recipe', return_value=selected), self.assertRaises(RuntimeError):
                    perf.audit(changed)
        with self.assertRaises(RuntimeError):
            perf.patch_bytes(b'custom binary')
        with self.assertRaises(RuntimeError):
            perf.recipe_receipt('0' * 64)

    def test_atomic_separate_output_retains_factory_custom_content_and_aliases(self):
        data = self.artifact()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'factory.so'; target = root / 'result.so'
            source.write_bytes(data)
            perf.patch(source, target)
            original_inode = target.stat().st_ino
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)
            self.assertEqual(target.stat().st_nlink, 1)
            perf.patch(source, target)
            self.assertEqual(target.stat().st_ino, original_inode)
            self.assertEqual(source.read_bytes(), data)
            with self.assertRaises(RuntimeError):
                perf.patch(source, source)
            alias = root / 'alias.so'; alias.symlink_to(source)
            with self.assertRaises(RuntimeError):
                perf.patch(alias, target)
            with self.assertRaises(RuntimeError):
                perf.patch(source, alias)
            target.write_bytes(b'custom output')
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                perf.patch(source, target)
            self.assertEqual(target.read_bytes(), b'custom output')
            self.assertFalse(list(root.glob('.bufferqueue-perf-*')))

    def test_publication_failure_and_racing_destination_do_not_replace_unknown_files(self):
        data = self.artifact()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'factory.so'; target = root / 'result.so'
            source.write_bytes(data)
            with patch.object(perf.os, 'fsync', side_effect=OSError('disk full')), self.assertRaises(OSError):
                perf.patch(source, target)
            self.assertFalse(target.exists())
            self.assertEqual(source.read_bytes(), data)
            self.assertFalse(list(root.glob('.bufferqueue-perf-*')))
            def race(*_):
                target.write_bytes(b'user content')
                raise FileExistsError()
            with patch.object(perf.os, 'link', side_effect=race), self.assertRaisesRegex(RuntimeError, 'unknown'):
                perf.patch(source, target)
            self.assertEqual(target.read_bytes(), b'user content')
            self.assertFalse(list(root.glob('.bufferqueue-perf-*')))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_display_brightness_patch.py ---

"""Verify truthful capability fallback without changing HWC or display power."""

def execute(body, header, support, force, rear, light, sdr, boost):
    """Execute the actual bounded DEX subset and capture every setter argument."""
    units = struct.unpack('<' + 'H' * (len(body) // 2), body)
    first = header[0] - header[1]
    registers = {first: 'adapter', first + 1: sdr, first + 2: 8.0,
                 first + 3: 0.3, first + 4: 12.0, first + 5: boost}
    fields = {0x232c: support, 0x2329: force, 0x232a: rear,
              0x2327: 'light' if light else None, 0x232b: 'proxy', 0x2328: 'token'}
    pc, last, calls = 0, None, []
    for _ in range(100):
        unit = units[pc]
        opcode, high = unit & 255, unit >> 8
        if opcode in (0x54, 0x55):  # iget-object/boolean
            assert registers[high >> 4] == 'adapter'
            registers[high & 15] = fields[units[pc + 1]]
            pc += 2
        elif opcode in (0x38, 0x39):  # if-eqz/nez
            zero = registers[high] is None or registers[high] == 0
            delta = units[pc + 1]
            pc += (delta if delta < 32768 else delta - 65536) if zero == (opcode == 0x38) else 2
        elif opcode == 0x28:  # goto
            pc += high if high < 128 else high - 256
        elif opcode == 0x29:  # goto/16
            assert high == 0
            delta = units[pc + 1]
            pc += delta if delta < 32768 else delta - 65536
        elif opcode == 0x15:  # const/high16 float NaN
            registers[high] = struct.unpack('<f', struct.pack('<I', units[pc + 1] << 16))[0]
            pc += 2
        elif opcode == 0x01:  # move
            registers[high & 15] = registers[high >> 4]
            pc += 1
        elif opcode in (0x6e, 0x71):  # invoke-virtual/static
            count = high >> 4
            operand = units[pc + 2]
            indices = [(operand >> shift) & 15 for shift in (0, 4, 8, 12)] + [high & 15]
            args = [registers[index] for index in indices[:count]]
            method = units[pc + 1]
            if opcode == 0x71:
                assert method == 0x20ae
                last = args[0] == args[1] or (math.isnan(args[0]) and math.isnan(args[1]))
            else:
                assert method in (0x9ed5, 0x638e)
                calls.append((method, *args))
            pc += 3
        elif opcode == 0x74:  # invoke-virtual/range
            assert units[pc + 1] in (0x638f, 0x6390)
            start = units[pc + 2]
            calls.append((units[pc + 1], *(registers[index] for index in range(start, start + high))))
            pc += 3
        elif opcode == 0x0a:  # move-result
            registers[high] = last
            pc += 1
        elif opcode == 0x0e:  # return-void
            return calls
        else:
            raise AssertionError('Unexpected brightness opcode: ' + hex(opcode))
    raise AssertionError('Brightness method did not terminate.')

class DisplayBrightnessBehaviorTests(unittest.TestCase):
    def test_all_three_reviewed_composers_keep_the_same_nonbrightness_capability(self):
        import patch_composer as alpha
        import patch_rear_display as rear
        import patch_display_privacy as privacy
        pins = {line.split('|')[2] for line in brightness.capability_recipe().decode().splitlines()
                if line.startswith('composer|')}
        inventory = {line.split('|')[2] for line in privacy.capability_recipe().decode().splitlines()
                     if line.startswith('composer|')}
        self.assertEqual(pins, set(brightness.composer_identities()))
        self.assertEqual(pins, inventory)
        source = ROOT / 'work/feedback-investigation-20261013/pad-metadata-caller-audit/composer.ranchu'
        if not source.is_file():
            self.skipTest('Private audited composer is unavailable; no download attempted.')
        data = bytearray(source.read_bytes())
        for offset, original, _ in alpha.SITES:
            data[offset:offset + len(original)] = original
        for offset, original, _ in rear.SITES:
            data[offset:offset + len(original)] = original
        canonical = bytes(data)
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), alpha.BEFORE)
        fixed = alpha.patch(canonical)
        for value in (canonical, fixed, rear.patch(fixed)):
            proof = brightness.audit_composer(value)
            self.assertEqual(proof['values'], [1, 8])
            self.assertFalse(proof['brightness'])
        unknown = bytearray(fixed); unknown[0x26a8c] ^= 1
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            brightness.audit_composer(bytes(unknown))

    def test_actual_overloads_keep_capability_force_lights_and_null_fallback(self):
        cases = itertools.product((False, True), repeat=5)
        cases = list(cases)
        for _, _, _, header, original in brightness.METHODS:
            modified = brightness.patched_body(original)
            for support, force, rear, light, boost in cases:
                for sdr in (0.4, float('nan')):
                    values = support, force, rear, light, sdr, boost
                    before = execute(original, header, *values)
                    after = execute(modified, header, *values)
                    if support or force or not rear:
                        self.assertEqual(after, before, values)
                    else:
                        self.assertEqual(after, [(0x9ed5, 'light', 0.3)] if light else [], values)
                    if support or force:
                        self.assertEqual(len(after), 1)
                        self.assertEqual(after[0][1:3], ('proxy', 'token'))
                        self.assertIn(after[0][0], (0x638e, 0x638f, 0x6390))
                    else:
                        self.assertFalse(any(call[0] in (0x638e, 0x638f, 0x6390) for call in after))

    def test_recipe_is_one_canonical_unsigned_edge_with_a_real_capability_requirement(self):
        receipt = brightness.recipe_receipt()
        self.assertEqual(brightness.BEFORE, policy.AFTER)
        self.assertEqual(brightness.SIZE, policy.SIZE)
        self.assertEqual(receipt['requires'], 'ranchu-without-display-brightness')
        self.assertEqual(receipt['format'], 'framework-jar')
        self.assertEqual(receipt['methods'], [row[0] for row in brightness.METHODS])
        self.assertEqual(brightness.catalog_recipes(), (receipt,))
        self.assertEqual(len(receipt['sites']), 5)
        receipt['sites'].clear()
        self.assertEqual(len(brightness.recipe_receipt()['sites']), 5)
        with self.assertRaises(RuntimeError):
            brightness.recipe_receipt(policy.BEFORE)

    def test_unknown_inputs_do_not_create_or_replace_outputs(self):
        for content in (b'', b'PK\x03\x04', b'unknown signed framework'):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                brightness.patch_bytes(content)
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'custom.jar'
            output = Path(temporary) / 'new/derivative.jar'
            source.write_bytes(b'custom user content')
            with self.assertRaises(RuntimeError):
                brightness.patch(source, output)
            self.assertFalse(output.parent.exists())
            self.assertEqual(source.read_bytes(), b'custom user content')

class DisplayBrightnessArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        default = ROOT / ('work/feedback-investigation-20261013/rear-state-sync/'
                         'phone-services-' + policy.BEFORE + '.jar')
        source = Path(os.environ.get('HYPEROS_AVD_DISPLAY_BRIGHTNESS_ARTIFACT', str(default)))
        if not source.is_file():
            raise unittest.SkipTest('Private audited services JAR unavailable; no download attempted.')
        content = source.read_bytes()
        cls.original = policy.patch_bytes(content) if hashlib.sha256(content).hexdigest() == policy.BEFORE else content
        cls.output = brightness.patch_bytes(cls.original)

    def test_content_method_selection_idempotence_and_offline_recipe_agree(self):
        self.assertFalse(brightness.audit(self.original))
        self.assertTrue(brightness.audit(self.output))
        self.assertEqual(brightness.patch_bytes(self.output), self.output)
        self.assertEqual(brightness.receipt(self.original), brightness.receipt(self.output))
        replay = bytearray(self.original)
        for offset, before, after in brightness.SITES:
            self.assertEqual(replay[offset:offset + len(bytes.fromhex(before))].hex(), before)
            replay[offset:offset + len(bytes.fromhex(after))] = bytes.fromhex(after)
        self.assertEqual(bytes(replay), self.output)
        self.assertEqual(hashlib.sha256(self.output).hexdigest(), brightness.AFTER)
        old = self.original[brightness.DEX_OFFSET:brightness.DEX_OFFSET + brightness.DEX_SIZE]
        new = self.output[brightness.DEX_OFFSET:brightness.DEX_OFFSET + brightness.DEX_SIZE]
        self.assertEqual(brightness._methods(old), brightness._methods(new))
        for _, _, code, header, body in brightness.METHODS:
            self.assertEqual(struct.unpack_from('<4H2I', new, code), header)
            self.assertEqual(new[code + 16:code + 16 + len(body)], brightness.patched_body(body))
        self.assertEqual(new[12:32], hashlib.sha1(new[32:]).digest())
        self.assertEqual(struct.unpack_from('<I', new, 8)[0], zlib.adler32(new[12:]) & 0xffffffff)

    def test_only_two_branch_words_and_required_checksums_change(self):
        self.assertEqual(len(self.original), len(self.output))
        cursor = 0
        for offset, before, after in brightness.SITES:
            self.assertEqual(self.original[cursor:offset], self.output[cursor:offset])
            self.assertEqual(self.original[offset:offset + len(bytes.fromhex(before))].hex(), before)
            self.assertEqual(self.output[offset:offset + len(bytes.fromhex(after))].hex(), after)
            cursor = offset + len(bytes.fromhex(before))
        self.assertEqual(self.original[cursor:], self.output[cursor:])
        with zipfile.ZipFile(io.BytesIO(self.original)) as before, zipfile.ZipFile(io.BytesIO(self.output)) as after:
            self.assertIsNone(after.testzip())
            self.assertEqual(before.namelist(), after.namelist())
            for first, second in zip(before.infolist(), after.infolist()):
                for field in ('filename', 'compress_type', 'header_offset', 'file_size', 'compress_size',
                              'flag_bits', 'date_time', 'extra', 'comment', 'external_attr', 'internal_attr'):
                    self.assertEqual(getattr(first, field), getattr(second, field))
                if first.filename != brightness.MEMBER:
                    self.assertEqual(before.read(first.filename), after.read(second.filename))
            self.assertEqual(before.read(policy.MEMBER), after.read(policy.MEMBER))

    def test_foreign_tampered_partial_signed_or_predecessor_input_is_refused(self):
        for offset in (0, brightness.DEX_OFFSET + 8, brightness.SITES[2][0], len(self.original) - 1):
            modified = bytearray(self.original)
            modified[offset] ^= 1
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                brightness.patch_bytes(modified)
        partial = bytearray(self.original)
        offset = brightness.SITES[2][0]
        partial[offset:offset + 4] = brightness.GATE_AFTER
        with self.assertRaises(RuntimeError):
            brightness.patch_bytes(partial)
        with self.assertRaises(RuntimeError):
            brightness.patch_bytes(self.original + b'APK Sig Block 42')

    def test_outputs_preserve_loaded_inodes_unknown_files_and_aliases(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, output = Path(temporary) / 'source.jar', Path(temporary) / 'derivative.jar'
            source.write_bytes(self.original)
            brightness.patch(source, output)
            inode = output.stat().st_ino
            brightness.patch(source, output)
            self.assertEqual(output.stat().st_ino, inode)
            alias = Path(temporary) / 'alias.jar'
            alias.symlink_to(output)
            with self.assertRaises(RuntimeError):
                brightness.patch(source, alias)
            hardlink = Path(temporary) / 'hardlink.jar'
            os.link(output, hardlink)
            with self.assertRaises(RuntimeError):
                brightness.patch(source, output)
            hardlink.unlink()
            output.write_bytes(b'user derivative')
            with self.assertRaises(RuntimeError):
                brightness.patch(source, output)
            self.assertEqual(output.read_bytes(), b'user derivative')
            self.assertFalse(list(Path(temporary).glob('.display-brightness-*')))

    def test_racing_output_is_preserved_and_temporary_is_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, output = Path(temporary) / 'source.jar', Path(temporary) / 'derivative.jar'
            source.write_bytes(self.original)

            def occupied(*_):
                output.write_bytes(b'racing user output')
                raise FileExistsError()

            with patch.object(brightness.os, 'link', side_effect=occupied), self.assertRaises(RuntimeError):
                brightness.patch(source, output)
            self.assertEqual(output.read_bytes(), b'racing user output')
            self.assertFalse(list(Path(temporary).glob('.display-brightness-*')))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_display_metadata_patch.py ---

"""Exercise exact unsupported contracts and their real cleanup instructions."""

def execute_ui_failure(data, layout, heap=False):
    """Decode the real scalar failure path with a protected caller optional.

    Local vectors have already been constructed at the exact replaced call.
    Both inline and allocated temporaries are exercised; no output write, mapper
    call, fabricated decoded payload or unrelated helper call is permitted.
    """
    site, negative, cleanup, restore, vector, inline, free_call, frame = layout
    registers = {i: 0x5000 + i for i in range(31)}
    stack, caller = 0x10000, 0x80000
    registers[19], registers[29] = caller, stack + frame
    inline_pointer = stack + inline + 0x20
    pointer = 0x90000 if heap else inline_pointer
    memory = {stack + vector: pointer, stack + inline: inline_pointer}
    output = bytes(range(32))
    memory.update({caller + i: value for i, value in enumerate(output)})
    visited, freed, equal, pc = [], [], False, site

    def read(index, sp=False):
        return stack if sp and index == 31 else registers.get(index, 0)

    def write(address, value):
        if caller <= address < caller + len(output):
            raise AssertionError('Unsupported metadata changed the caller optional.')
        memory[address] = value

    def branch(word, bits, shift):
        immediate = (word >> shift) & ((1 << bits) - 1)
        if immediate & (1 << (bits - 1)):
            immediate -= 1 << bits
        return visited[-1] + immediate * 4

    for _ in range(50):
        if pc == restore:
            return registers[0], bytes(memory[caller + i] for i in range(32)), freed, visited
        visited.append(pc)
        word, = struct.unpack_from('<I', data, pc)
        pc += 4
        rd, rn, rm = word & 31, (word >> 5) & 31, (word >> 16) & 31
        if word & 0xff800000 == 0x12800000:  # MOVN Wd,#imm16.
            registers[rd] = (~(((word >> 5) & 0xffff) << (((word >> 21) & 3) * 16))) & 0xffffffff
        elif word & 0xffe0ffe0 in (0x2a0003e0, 0xaa0003e0):  # MOV W/X register.
            registers[rd] = read(rm) & (0xffffffffffffffff if word & (1 << 31) else 0xffffffff)
        elif word & 0x7e000000 == 0x36000000:  # TBZ/TBNZ.
            bit = ((word >> 19) & 31) | ((word >> 26) & 32)
            if bool(read(rd) & (1 << bit)) == bool(word & (1 << 24)):
                pc = branch(word, 14, 5)
        elif word & 0x7e000000 == 0x34000000:  # CBZ/CBNZ.
            if bool(read(rd)) == bool(word & (1 << 24)):
                pc = branch(word, 19, 5)
        elif word & 0xffc003ff == 0x3100007f:  # CMN W3,#immediate.
            equal = (read(rn) + ((word >> 10) & 0xfff)) & 0xffffffff == 0
        elif word & 0xff000010 == 0x54000000:  # B.EQ/B.NE.
            condition = word & 15
            if condition not in (0, 1):
                raise AssertionError('Unreviewed failure branch condition.')
            if equal == (condition == 0):
                pc = branch(word, 19, 5)
        elif word >> 26 == 0x05:  # B
            pc = branch(word, 26, 0)
        elif word >> 26 == 0x25:  # Only the original owned temporary free may execute.
            if branch(word, 26, 0) != free_call:
                raise AssertionError('Unreviewed call on unsupported metadata path.')
            freed.append(registers[0])
            registers[0], registers[8], registers[9] = 0xdead, 0xbad, 0xbeef
        elif word & 0xffc00000 in (0x39000000, 0xb9000000, 0xf9000000):
            scale = (word >> 30) & 3
            write(read(rn, sp=True) + ((word >> 10) & 0xfff) * (1 << scale), read(rd))
        elif word & 0xffc00000 in (0xb9400000, 0xf9400000):
            scale = (word >> 30) & 3
            registers[rd] = memory[read(rn, sp=True) + ((word >> 10) & 0xfff) * (1 << scale)]
        elif word & 0xffe0fc1f == 0xeb00001f:  # CMP Xn,Xm.
            equal = read(rn) == read(rm)
        else:
            raise AssertionError('Unreviewed instruction %08x at %x.' % (word, pc - 4))
    raise AssertionError('Metadata failure did not reach original restore.')

class DisplayMetadataPatchTests(unittest.TestCase):
    def artifact(self, name):
        key = 'HYPEROS_AVD_METADATA_' + name.replace('-', '_').replace('.', '_').upper()
        source = Path(os.environ.get(key, str(
            REPO / 'work/feedback-investigation-20261013/pad-metadata-caller-audit' / name)))
        if not source.is_file():
            self.skipTest('Audited private display ELF unavailable; no download attempted.')
        return source.read_bytes()

    def consumers(self):
        return [('libui.so', self.artifact('libui.so')),
                ('phone-libui.so', self.artifact('phone-libui.so')),
                ('libsurfaceflinger.so', self.artifact('libsurfaceflinger.so'))]

    def test_exact_mapper_rejects_standard24_and_custom_namespace_without_modification(self):
        source = self.artifact('mapper.ranchu.so')
        proof = metadata.audit_mapper(source)
        self.assertEqual(hashlib.sha256(source).hexdigest(), proof['sha256'])
        self.assertEqual(proof['unsupported_standard_types'], [24])
        self.assertEqual(proof['unsupported_namespace'], 'xring.graphics.XringMetadataType')
        # Independently decode (type-1)>22; 24 reaches the actual -7 return.
        subtract, _, compare, branch = struct.unpack_from('<IIII', source, 0x5bc0)
        self.assertEqual(subtract, 0xd1000448)
        self.assertEqual((compare >> 10) & 0xfff, 22)
        self.assertEqual(branch & 15, 8)  # B.HI unsigned comparison.
        self.assertEqual(metadata._branch_target(branch, 0x5bcc, 19, 5), 0x5c30)
        self.assertEqual(source[0x5c60:0x5c64], bytes.fromhex('c0008012'))
        # Nonstandard namespace strcmp failure returns -7 without decoding data.
        self.assertEqual(source[0x59bc:0x59c0], bytes.fromhex('e90d0094'))
        self.assertEqual(source[0x59c0:0x59c4], bytes.fromhex('60020034'))
        self.assertEqual(source[0x59f4:0x59f8], bytes.fromhex('c0008012'))
        self.assertEqual(metadata.capability_recipe(), (
            'schema|1\nmapper|' + metadata.MAPPER + '|' + metadata.MAPPER_SHA256 + '\n').encode())
        modified = bytearray(source); modified[0x5bc8] ^= 1
        with self.assertRaises(RuntimeError):
            metadata.audit_mapper(modified)

    def test_each_content_recipe_changes_only_its_one_word_and_is_idempotent(self):
        for name, source in self.consumers():
            with self.subTest(artifact=name):
                _, row, patched = metadata.audit(source)
                self.assertFalse(patched)
                output = metadata.patch_bytes(source)
                self.assertEqual(len(output), len(source))
                self.assertEqual(hashlib.sha256(output).hexdigest(), row['after'])
                site = row['site']
                self.assertEqual(output[:site], source[:site])
                self.assertEqual(output[site + 4:], source[site + 4:])
                self.assertEqual(output[site:site + 4], bytes.fromhex(row['replacement']))
                self.assertEqual(metadata.patch_bytes(output), output)
                self.assertTrue(metadata.audit(output)[2])

    def test_actual_ui_cleanup_keeps_optional_untouched_and_frees_only_its_temporary(self):
        fixtures = [('libui.so', (0x3a32c, 0x3a43c, 0x3a3ac, 0x3a40c, 0x90, 0xa8, 0x61020, 0x140)),
                    ('phone-libui.so', (0x3a020, 0x3a124, 0x3a0a0, 0x3a100, 0x38, 0x50, 0x60e68, 0x130))]
        for name, layout in fixtures:
            output = metadata.patch_bytes(self.artifact(name))
            for heap in (False, True):
                with self.subTest(artifact=name, allocated=heap):
                    result, optional, frees, visited = execute_ui_failure(output, layout, heap)
                    self.assertEqual(result, (-74) & 0xffffffff)
                    self.assertEqual(optional, bytes(range(32)))
                    self.assertEqual(frees, [0x90000] if heap else [])
                    self.assertIn(layout[1], visited)
                    self.assertIn(layout[2], visited)
                    # Capacity retry and optional mutation never execute.
                    self.assertNotIn(0x3a484 if name == 'libui.so' else 0x3a168, visited)

    def test_ui_pac_canary_return_frames_and_supported_metadata_remain_identical(self):
        for name in ('libui.so', 'phone-libui.so'):
            source = self.artifact(name); output = metadata.patch_bytes(source)
            _, row, _ = metadata.audit(source)
            start, site = row['address'], row['site']
            self.assertEqual(output[start:site], source[start:site])
            self.assertEqual(output[site + 4:start + row['function_size']], source[site + 4:start + row['function_size']])
            if name.startswith('phone'):
                self.assertEqual(output[start:start + 4], bytes.fromhex('3f2303d5'))
                self.assertEqual(output[row['restore_end'] - 8:row['restore_end']], bytes.fromhex('bf2303d5c0035fd6'))
            else:
                self.assertEqual(output[row['restore']:row['restore'] + 16],
                                 bytes.fromhex('a81640f9a9835ff81f0109eb81020054'))
            # Full immutable hash includes every supported getter, all setters,
            # metadata readers, strings, CFI and relocation data.
            self.assertEqual(hashlib.sha256(output[:start] + output[start + row['function_size']:]).hexdigest(),
                             row['immutable_sha256'])

    def test_dolby_false_path_balances_original_shared_reference_before_buffer_acquire(self):
        source = self.artifact('libsurfaceflinger.so'); output = metadata.patch_bytes(source)
        # Original shared-control acquire remains before the new unconditional
        # branch. GraphicBuffer's later incStrong must never be skipped midway.
        self.assertEqual(output[0x6787c0:0x6787d0], source[0x6787c0:0x6787d0])
        self.assertEqual(output[0x6787cc:0x6787d0], bytes.fromhex('b57cf397'))
        word, = struct.unpack_from('<I', output, 0x6787d0)
        self.assertEqual(word >> 26, 5)
        self.assertEqual(metadata._branch_target(word, 0x6787d0), 0x678860)
        self.assertEqual(output[0x678860:0x678864], bytes.fromhex('f4031f2a'))  # W20=false.
        # Null controls skip release; live controls retain their original
        # decrement, zero-count destruction and shared-weak release branches.
        self.assertEqual(output[0x678864:0x678890], source[0x678864:0x678890])
        self.assertEqual(output[0x678870:0x678874], bytes.fromhex('a07bf397'))
        self.assertEqual(output[0x67888c:0x678890], bytes.fromhex('15921794'))
        self.assertEqual(output[0x6788a0:0x6788a4], bytes.fromhex('e003142a'))  # W0=W20.
        self.assertEqual(output[0x678890:0x6788c4], source[0x678890:0x6788c4])
        self.assertEqual(output[0x6787f4:0x6787f8], source[0x6787f4:0x6787f8])  # Unexecuted incStrong.
        self.assertEqual(output[0x678ac0:0x678b08], source[0x678ac0:0x678b08])  # Original acquired-buffer cleanup.

    def test_all_properties_logs_elf_metadata_and_other_phone_dolby_abi_are_preserved(self):
        for name, source in self.consumers():
            output = metadata.patch_bytes(source)
            _, sections = _sections(source)
            for label, section in sections.items():
                if label == b'.text' or section[1] == 8:
                    continue
                offset, length = section[4:6]
                self.assertEqual(source[offset:offset + length], output[offset:offset + length], label)
            self.assertIn(b'__android_log_print\0', output)
            if name == 'libsurfaceflinger.so':
                for site in (0x4b7800, 0x4b7dd8):
                    self.assertEqual(source[site - 20:site + 20], output[site - 20:site + 20])
                self.assertIn(b'ro.vendor.display.bt2020.supported\0', output)
        phone = self.artifact('phone-libsurfaceflinger.so')
        self.assertEqual(hashlib.sha256(phone).hexdigest(),
                         'fef17e489200a456fcff3cc32fc3e8f6b692526fe72afbdd30d313286c809559')
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            metadata.patch_bytes(phone)

    def test_offline_receipts_reproduce_every_exact_derivative_and_bind_mapper_proof(self):
        self.assertEqual(len(metadata.catalog_recipes()), 3)
        for _, source in self.consumers():
            receipt = metadata.receipt(source)
            self.assertEqual(receipt['mapper_capability'], metadata.mapper_capability())
            self.assertEqual(receipt['requires'], metadata.REQUIRES)
            output = bytearray(source)
            for site in receipt['sites']:
                self.assertEqual(output[site['offset']:site['offset'] + 4], bytes.fromhex(site['before']))
                output[site['offset']:site['offset'] + 4] = bytes.fromhex(site['after'])
            self.assertEqual(hashlib.sha256(output).hexdigest(), receipt['after'])
            self.assertEqual(metadata.receipt(output), receipt)

    def test_unknown_and_structure_tampering_is_refused(self):
        for _, source in self.consumers():
            selected = metadata.select_recipe(source); row = selected[1]
            for offset in (4, 18, row['site'], row['cleanup'], row['restore'], len(source) - 1):
                with self.subTest(source=selected[0], offset=offset):
                    modified = bytearray(source); modified[offset] ^= 1
                    with self.assertRaises(RuntimeError):
                        metadata.patch_bytes(modified)
                    with patch.object(metadata, 'select_recipe', return_value=selected), self.assertRaises(RuntimeError):
                        metadata.audit(modified)
        with self.assertRaises(RuntimeError):
            metadata.patch_bytes(b'user customized input')
        with self.assertRaises(RuntimeError):
            metadata.recipe_receipt('0' * 64)

    def test_atomic_derivative_publication_retains_factory_and_unknown_aliases(self):
        source_data = self.artifact('libui.so')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'factory.so'; target = root / 'result.so'
            source.write_bytes(source_data)
            metadata.patch(source, target)
            original_inode = target.stat().st_ino
            self.assertEqual(target.stat().st_nlink, 1)
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)
            metadata.patch(source, target)
            self.assertEqual(target.stat().st_ino, original_inode)
            self.assertEqual(source.read_bytes(), source_data)
            alias = root / 'alias.so'; alias.symlink_to(source)
            for src, dst in ((source, source), (alias, target), (source, alias)):
                with self.assertRaises(RuntimeError):
                    metadata.patch(src, dst)
            target.write_bytes(b'custom output')
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                metadata.patch(source, target)
            self.assertEqual(target.read_bytes(), b'custom output')
            self.assertFalse(list(root.glob('.display-metadata-*')))

    def test_failed_publication_or_race_does_not_replace_user_content(self):
        data = self.artifact('libui.so')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'factory.so'; target = root / 'result.so'
            source.write_bytes(data)
            with patch.object(metadata.os, 'fsync', side_effect=OSError('disk full')), self.assertRaises(OSError):
                metadata.patch(source, target)
            self.assertFalse(target.exists())
            def race(*_):
                target.write_bytes(b'user content')
                raise FileExistsError()
            with patch.object(metadata.os, 'link', side_effect=race), self.assertRaisesRegex(RuntimeError, 'unknown'):
                metadata.patch(source, target)
            self.assertEqual(target.read_bytes(), b'user content')
            self.assertEqual(source.read_bytes(), data)
            self.assertFalse(list(root.glob('.display-metadata-*')))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_display_privacy_patch.py ---

"""Verify the privacy fallback patch against optional audited ELF artifacts."""

class DisplayPrivacyPatchTests(unittest.TestCase):
    def artifact(self):
        path = Path(os.environ.get('HYPEROS_AVD_PRIVACY_ARTIFACT', str(
            REPO / 'work/feedback-investigation-20261013/phone-libmisurfaceflinger.so')))
        if not path.is_file():
            self.skipTest('Audited proprietary display ELF is not distributed in Git.')
        return path.read_bytes()

    def test_real_patch_changes_only_the_absent_hal_baseline_and_is_idempotent(self):
        before = self.artifact(); after = privacy.patch(before)
        self.assertEqual(privacy.privacy_symbol(before), (privacy.FUNCTION_ADDRESS,
                                                       privacy.FUNCTION_SIZE, privacy.FUNCTION_ADDRESS))
        self.assertEqual(hashlib.sha256(after).hexdigest(), privacy.AFTER)
        self.assertEqual(privacy.patch(after), after)
        site, original, replacement = privacy.SITES[0]
        self.assertEqual(before[:site], after[:site])
        self.assertEqual(before[site + 4:], after[site + 4:])
        instruction = struct.unpack('<I', replacement)[0]
        self.assertEqual(instruction & 0xffc00000, 0xb9000000)
        self.assertEqual(instruction & 31, 31)  # WZR, never the requested mode.
        self.assertEqual((instruction >> 5) & 31, 19)
        self.assertEqual(((instruction >> 10) & 0xfff) * 4, 0x4b8)
        # The original equality gate, real-HAL null branch and success store
        # continue to execute unchanged. No call/log function is bypassed.
        for address, expected in ((0x635b8, '68ba44b9'), (0x63658, 'b70300b4'),
                                  (0x63698, '74ba04b9')):
            self.assertEqual(after[address:address + 4].hex(), expected)

    def test_unknown_or_tampered_full_elf_is_never_patched(self):
        before = self.artifact()
        for position in (4, 40, 0x634c4, 0x636cc, len(before) - 1):
            data = bytearray(before); data[position] ^= 1
            with self.subTest(position=position), self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                privacy.patch(data)

    def test_function_resolver_refuses_malformed_exported_layout(self):
        before = self.artifact()
        for position in (4, 40):
            data = bytearray(before); data[position] ^= 1
            with self.subTest(position=position), self.assertRaises(RuntimeError):
                privacy.privacy_symbol(data)
        with self.assertRaises(RuntimeError):
            privacy.privacy_symbol(before[:-1])

    def test_full_reviewed_vendor_inventory_proves_no_declared_privacy_hal(self):
        root = Path(os.environ.get('HYPEROS_AVD_PRIVACY_VINTF', str(
            REPO / 'work/feedback-investigation-20261013/phone-vintf')))
        if not root.is_dir():
            self.skipTest('Audited vendor VINTF fixture is not distributed in Git.')
        files = {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in root.rglob('*') if path.is_file()}
        self.assertEqual(files, privacy.VINTF_FILES)
        for relative in files:
            tree = ET.fromstring((root / relative).read_bytes())
            self.assertNotIn('vendor.xiaomi.hardware.display.mihwcextension',
                             [node.text for node in tree.iter('name')])

    def test_reviewed_apex_packages_and_active_fragments_prove_declaration_absence(self):
        root = REPO / 'work/feedback-investigation-20261013/privacy-extra-inventory'
        if not root.is_dir():
            self.skipTest('Audited vendor APEX evidence is not distributed in Git.')
        receipt = json.loads((root / 'receipt.json').read_text())
        self.assertEqual(receipt['vendor_apex_packages'], privacy.APEX_PACKAGES)
        self.assertEqual(receipt['apex_fragments'], privacy.APEX_FRAGMENTS)
        for name, checksum in privacy.APEX_FRAGMENTS.items():
            data = (root / name.lstrip('/')).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), checksum)
            tree = ET.fromstring(data)
            self.assertEqual(tree.attrib['type'], 'device')
            self.assertNotIn('vendor.xiaomi.hardware.display.mihwcextension',
                             [node.text for node in tree.iter('name')])

if __name__ == '__main__':
    unittest.main()


# --- tests/test_perfflinger_patch.py ---

"""Preserve the XRING client's original missing-HAL ABI without Binder retries."""

class PerfFlingerPatchTests(unittest.TestCase):
    def artifact(self):
        path = Path(os.environ.get('HYPEROS_AVD_PERFFLINGER_ARTIFACT', str(REPO /
            'work/feedback-investigation-20261014/final-audit/remaining-capability-audit/pad-PerfFlingerClient.jar')))
        if not path.is_file():
            self.skipTest('Audited proprietary unsigned framework is not distributed in Git.')
        return path.read_bytes()

    def test_exact_idempotent_derivative_and_only_declared_sites_change(self):
        source = self.artifact(); output = perfflinger.patch_bytes(source)
        self.assertFalse(perfflinger.audit(source)); self.assertTrue(perfflinger.audit(output))
        self.assertEqual(hashlib.sha256(output).hexdigest(), perfflinger.AFTER)
        self.assertEqual(perfflinger.patch_bytes(output), output)
        self.assertEqual(len(source), len(output))
        allowed = {offset+i for offset, old, _ in perfflinger.SITES for i in range(len(bytes.fromhex(old)))}
        self.assertLessEqual({i for i, (a, b) in enumerate(zip(source, output)) if a != b}, allowed)
        self.assertEqual(len(perfflinger.SITES), 5)

    def test_entry_prefixes_cover_complete_instructions_and_preserve_return_abi(self):
        # Getter: CONST/4 + SGET_OBJECT, replaced by false/return/NOP.
        self.assertEqual(perfflinger.CODE[0][-2:], ('120062010700', '12000f000000'))
        # Hint: INVOKE_STATIC + MOVE_RESULT, replaced by wide -1/return/NOP.
        # Covering MOVE_RESULT avoids stranding an unmatched result opcode.
        self.assertEqual(perfflinger.CODE[1][-2:], ('71002e0000000a00', '1600ffff10000000'))
        self.assertEqual(struct.unpack('<4H', bytes.fromhex(perfflinger.CODE[1][-1])), (0x16, 0xffff, 0x10, 0))
        self.assertEqual([row[1] for row in perfflinger.CODE], [9, 1])
        self.assertEqual([row[3][:3] for row in perfflinger.CODE], [(7, 0, 3), (19, 6, 9)])

    def test_all_other_code_tables_debug_and_exception_handlers_are_preserved(self):
        source = self.artifact(); output = perfflinger.patch_bytes(source)
        start, size = perfflinger.DEX_OFFSET, perfflinger.DEX_SIZE
        old, new = source[start:start+size], output[start:start+size]
        self.assertEqual(perfflinger._methods(old), perfflinger._methods(new))
        allowed = set(range(8, 32))
        for _, _, offset, header, *_, before, after in perfflinger.CODE:
            self.assertEqual(struct.unpack_from('<4H2I', new, offset), header)
            body_end = offset+16+header[5]*2
            handler_start = (body_end+3)&~3
            self.assertEqual(old[handler_start:handler_start+header[3]*8], new[handler_start:handler_start+header[3]*8])
            allowed.update(range(offset+16, offset+16+len(bytes.fromhex(before))))
        self.assertLessEqual({i for i, (a, b) in enumerate(zip(old, new)) if a != b}, allowed)
        self.assertIn(perfflinger.HAL.encode()+b'\0', new)

    def test_archive_and_dex_checksums_remain_valid_without_repacking(self):
        source = self.artifact(); output = perfflinger.patch_bytes(source)
        with zipfile.ZipFile(io.BytesIO(source)) as before, zipfile.ZipFile(io.BytesIO(output)) as after:
            self.assertIsNone(after.testzip()); self.assertEqual(before.namelist(), after.namelist())
            self.assertEqual(before.read('META-INF/MANIFEST.MF'), after.read('META-INF/MANIFEST.MF'))
            for a, b in zip(before.infolist(), after.infolist()):
                for key in ('filename', 'header_offset', 'flag_bits', 'compress_type', 'file_size',
                            'compress_size', 'date_time', 'extra', 'comment', 'external_attr', 'internal_attr'):
                    self.assertEqual(getattr(a, key), getattr(b, key))
            dex = after.read('classes.dex')
        self.assertEqual(hashlib.sha256(dex).hexdigest(), perfflinger.DEX_AFTER)
        self.assertEqual(dex[12:32], hashlib.sha1(dex[32:]).digest())
        self.assertEqual(struct.unpack_from('<I', dex, 8)[0], zlib.adler32(dex[12:])&0xffffffff)
        self.assertNotIn(b'APK Sig Block 42', output)

    def test_unknown_or_corrupt_content_is_not_admitted(self):
        source = self.artifact()
        for offset in (0, 14, 52, perfflinger.SITES[2][0], perfflinger.SITES[3][0], len(source)-1):
            with self.subTest(offset=offset):
                value = bytearray(source); value[offset] ^= 1
                with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                    perfflinger.patch_bytes(value)
        for value in (b'', b'custom framework', source+b'x'):
            with self.assertRaises(RuntimeError): perfflinger.patch_bytes(value)

    def test_offline_receipt_has_exact_hardware_requirement_and_canonical_sites(self):
        receipt = perfflinger.recipe_receipt()
        self.assertEqual(receipt['path'], perfflinger.PATH)
        self.assertEqual(receipt['requires'], 'ranchu-without-physical-perfflinger')
        self.assertEqual(receipt['absent_hal'], perfflinger.HAL)
        self.assertEqual(receipt['methods'], list(perfflinger.METHODS))
        self.assertEqual(perfflinger.catalog_recipes(), (receipt,))
        self.assertEqual([(x['offset'], x['before'], x['after']) for x in receipt['sites']], list(perfflinger.SITES))
        with self.assertRaises(RuntimeError): perfflinger.recipe_receipt('0'*64)

    def test_inplace_unknown_outputs_aliases_and_hardlinks_are_preserved(self):
        source = self.artifact()
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp); original = folder/'source.jar'; original.write_bytes(source)
            output = folder/'patched.jar'; perfflinger.patch(original, output)
            self.assertEqual(perfflinger.patch(original, output), output)
            with self.assertRaises(RuntimeError): perfflinger.patch(original, original)
            self.assertEqual(original.read_bytes(), source)
            output.write_bytes(b'User customized output')
            with self.assertRaises(RuntimeError): perfflinger.patch(original, output)
            self.assertEqual(output.read_bytes(), b'User customized output')
            output.unlink(); output.symlink_to(original)
            with self.assertRaises(RuntimeError): perfflinger.patch(original, output)
            self.assertEqual(original.read_bytes(), source)
            output.unlink(); output.write_bytes(perfflinger.patch_bytes(source)); os.link(output, folder/'hardlink')
            with self.assertRaises(RuntimeError): perfflinger.patch(original, output)
            self.assertEqual(output.read_bytes(), perfflinger.patch_bytes(source))


# --- tests/test_qti_perf_patch.py ---

"""Audit the physical QTI lookup ABI, coverage and immutable failure paths."""

class QtiPerfPatchTests(unittest.TestCase):
    def artifact(self):
        source = Path(os.environ.get('HYPEROS_AVD_QTI_PERF_ARTIFACT', str(
            REPO / 'work/feedback-investigation-20261013/phone-perf-callers/libqti-perfd-client_system.so')))
        if not source.is_file():
            self.skipTest('Audited private QTI Perf ELF unavailable; no download attempted.')
        return source.read_bytes()

    def test_all_five_physical_lookup_calls_are_removed_and_only_their_words_change(self):
        source = self.artifact()
        before, recipe, already = qti.audit(source)
        self.assertFalse(already)
        output = qti.patch_bytes(source)
        self.assertEqual(hashlib.sha256(output).hexdigest(), recipe['after'])
        self.assertEqual(len(output), len(source))
        self.assertEqual(qti.patch_bytes(output), output)
        self.assertTrue(qti.audit(output)[2])
        expected = {row['site'] for row in recipe['functions']}
        self.assertEqual(expected, {0xd5dc, 0xd7fc, 0xe954, 0x13aa8, 0x16ed8})
        allowed = {site + index for site in expected for index in range(4)}
        changed = {i for i, (old, new) in enumerate(zip(source, output)) if old != new}
        self.assertEqual(len(changed), 17)
        self.assertLessEqual(changed, allowed)
        physical = {row['plt'] for row in recipe['functions']}
        for row in recipe['functions']:
            word, = struct.unpack_from('<I', source, row['site'])
            self.assertEqual(word >> 26, 0x25)
            self.assertEqual(qti._branch_target(word, row['site']), row['plt'])
        _, sections = _sections(output)
        text = sections[b'.text']
        calls = set()
        for address in range(text[3], text[3] + text[5], 4):
            word, = struct.unpack_from('<I', output, text[4] + address - text[3])
            if word >> 26 in (0x05, 0x25) and qti._branch_target(word, address) in physical:
                calls.add(address)
        self.assertEqual(calls, set())

    def test_hidden_sp_returns_store_exactly_one_null_pointer_without_register_clobber(self):
        source = self.artifact()
        _, recipe, _ = qti.audit(source)
        output = qti.patch_bytes(source)
        for row in recipe['functions']:
            if row['result'] != 'sp-null':
                continue
            with self.subTest(function=row['symbol']):
                word, = struct.unpack_from('<I', output, row['site'])
                # Decode STR's actual AArch64 ABI operands independently. A
                # NOP or MOV W0,0 would leave this callee-constructed sp dirty.
                self.assertEqual(word & 0xffc00000, 0xf9000000)
                self.assertEqual(word & 31, 31)  # Rt=XZR.
                self.assertEqual((word >> 5) & 31, 8)  # Rn=X8 hidden return slot.
                self.assertEqual((word >> 10) & 0xfff, 0)
                width = 1 << (word >> 30)
                self.assertEqual(width, 8)
                frame = bytearray(b'left-boundary---' + b'poisoned' + b'--right-boundary')
                registers = {i: 0x100 + i for i in range(31)}
                registers[8] = 16
                previous = dict(registers)
                destination = registers[(word >> 5) & 31]
                frame[destination:destination + width] = (0).to_bytes(width, 'little')
                self.assertEqual(frame[:16], b'left-boundary---')
                self.assertEqual(frame[16:24], b'\0' * 8)
                self.assertEqual(frame[24:], b'--right-boundary')
                self.assertEqual(registers, previous)
                start, end = row['address'], row['address'] + row['size']
                self.assertEqual(source[start:row['site']], output[start:row['site']])
                self.assertEqual(source[row['site'] + 4:end], output[row['site'] + 4:end])

    def test_scalar_null_results_preserve_existing_failure_branches(self):
        source = self.artifact()
        output = qti.patch_bytes(source)
        self.assertEqual(output[0xd5dc:0xd5e0], bytes.fromhex('e0031f2a'))  # MOV W0,WZR.
        self.assertEqual(output[0xd5e0:0xd5e4], bytes.fromhex('1f000072'))  # TST W0,#1.
        self.assertEqual(output[0xd7fc:0xd800], bytes.fromhex('e0031faa'))  # MOV X0,XZR.
        self.assertEqual(output[0xd800:0xd804], bytes.fromhex('e00700f9'))  # Store returned Binder.
        branch, = struct.unpack_from('<I', output, 0xd804)
        self.assertEqual(branch & 0xff00001f, 0xb4000000)  # CBZ X0.
        displacement = (branch >> 5) & 0x7ffff
        if displacement & 0x40000:
            displacement -= 0x80000
        self.assertEqual(0xd804 + displacement * 4, 0xd914)
        # The original null branch preserves failure, cleanup and diagnostic.
        self.assertEqual(source[0xd914:0xd938], output[0xd914:0xd938])

    def test_all_metadata_cfi_pac_frames_logs_and_nonlookup_code_remain_identical(self):
        source = self.artifact()
        _, recipe, _ = qti.audit(source)
        output = qti.patch_bytes(source)
        _, sections = _sections(source)
        for name, section in sections.items():
            if name == b'.text' or section[1] == 8:
                continue
            with self.subTest(section=name):
                offset, length = section[4:6]
                self.assertEqual(source[offset:offset + length], output[offset:offset + length])
        self.assertIn(b'__cfi_slowpath\0', output)
        self.assertIn(b'__android_log_print\0', output)
        for row in recipe['functions']:
            body = output[row['address']:row['address'] + row['size']]
            self.assertTrue(body.startswith(bytes.fromhex('3f2303d5')))  # PACIASP.
            self.assertIn(bytes.fromhex('bf2303d5c0035fd6'), body)  # Original AUTIASP/RET.
        # CFI dispatch and every exported trampoline are outside the five sites.
        self.assertEqual(source[0x18000:0x1a018], output[0x18000:0x1a018])

    def test_canonical_offline_catalog_binds_capability_and_reproduces_exact_derivative(self):
        self.assertEqual(len(qti.catalog_recipes()), 2)
        receipt = qti.catalog_recipes()[0]
        self.assertEqual(receipt['path'], qti.NATIVE)
        self.assertEqual(receipt['requires'], 'ranchu-without-qti-perf-hal')
        self.assertEqual(receipt['absent_hal_packages'], list(qti.ABSENT_HAL_PACKAGES))
        self.assertEqual(receipt['absent_services'], list(qti.ABSENT_SERVICES))
        self.assertEqual(len(receipt['sites']), 5)
        source = self.artifact()
        output = bytearray(source)
        for site in receipt['sites']:
            old, new = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
            self.assertEqual(len(old), 4); self.assertEqual(len(new), 4)
            self.assertEqual(output[site['offset']:site['offset'] + 4], old)
            output[site['offset']:site['offset'] + 4] = new
        self.assertEqual(hashlib.sha256(output).hexdigest(), receipt['after'])
        self.assertEqual(qti.receipt(output), receipt)

    def test_unknown_and_partial_files_and_unverified_structure_are_refused(self):
        source = self.artifact()
        selected = qti.select_recipe(source)
        for offset in (4, 18, 0xd4e4, 0xe948, 0xd804, 0x1a598, len(source) - 1):
            with self.subTest(offset=offset):
                modified = bytearray(source); modified[offset] ^= 1
                with self.assertRaises(RuntimeError):
                    qti.patch_bytes(modified)
                with patch.object(qti, 'select_recipe', return_value=selected), self.assertRaises(RuntimeError):
                    qti.audit(modified)
        partial = bytearray(source)
        partial[0xd5dc:0xd5e0] = bytes.fromhex('e0031f2a')
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            qti.patch_bytes(partial)
        with self.assertRaises(RuntimeError):
            qti.patch_bytes(b'unknown ELF')
        with self.assertRaises(RuntimeError):
            qti.recipe_receipt('0' * 64)

    def test_atomic_separate_publication_preserves_factory_aliases_and_unknown_output(self):
        source = self.artifact()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); factory = root / 'factory.so'; target = root / 'result.so'
            factory.write_bytes(source)
            qti.patch(factory, target)
            old = target.stat()
            self.assertEqual(old.st_mode & 0o777, 0o644)
            self.assertEqual(old.st_nlink, 1)
            qti.patch(factory, target)
            self.assertEqual(target.stat().st_ino, old.st_ino)
            self.assertEqual(factory.read_bytes(), source)
            with self.assertRaises(RuntimeError):
                qti.patch(factory, factory)
            alias = root / 'alias.so'; alias.symlink_to(factory)
            with self.assertRaises(RuntimeError):
                qti.patch(alias, target)
            with self.assertRaises(RuntimeError):
                qti.patch(factory, alias)
            target.write_bytes(b'custom output')
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                qti.patch(factory, target)
            self.assertEqual(target.read_bytes(), b'custom output')
            self.assertFalse(list(root.glob('.qti-perf-*')))

    def test_racing_unknown_destination_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'factory.so'; target = root / 'result.so'
            source.write_bytes(self.artifact())
            def race(*_):
                target.write_bytes(b'user content')
                raise FileExistsError()
            with patch.object(qti.os, 'link', side_effect=race), self.assertRaisesRegex(RuntimeError, 'unknown'):
                qti.patch(source, target)
            self.assertEqual(target.read_bytes(), b'user content')
            self.assertFalse(list(root.glob('.qti-perf-*')))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_qti_perf_fallback.py ---

"""Preserve the audited no-HAL behavior without re-entering discovery guards."""

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


# --- tests/test_thermal_capability_patch.py ---

"""Keep missing board-temperature hardware out of the audited monitor startup."""

class ThermalCapabilityPatchTests(unittest.TestCase):
    def artifacts(self):
        paths = [Path(os.environ.get('HYPEROS_AVD_THERMAL_' + form.upper() + '_ARTIFACT', str(
            REPO / 'work/feedback-investigation-20261013' /
            (form + '-uniperf-loaded-caller') / 'miui-services-gated.jar')))
                 for form in ('phone', 'pad')]
        if not all(path.is_file() for path in paths):
            self.skipTest('Audited proprietary unsigned Phone/Pad JARs are not distributed in Git.')
        return [path.read_bytes() for path in paths]

    def test_rules_share_prerequisite_identities_and_require_actual_missing_node(self):
        self.assertEqual(len(thermal.RECIPES), 2)
        self.assertEqual({row['after'] for row in uniperf.RECIPES.values()
                          if row['path'] == thermal.PATH}, set(thermal.RECIPES))
        for row in (thermal.recipe_receipt(before) for before in thermal.RECIPES):
            self.assertEqual(row['requires'], 'ranchu-without-board-temperature-node')
            self.assertEqual(row['absent_node'], thermal.NODE)
            self.assertEqual(row['methods'][0], thermal.METHOD)
            self.assertTrue(set(row['methods']) <= {thermal.METHOD, thermal.SCENE_METHOD})
            self.assertEqual(row['path'], thermal.PATH)
            self.assertEqual(row['format'], 'framework-jar')
            self.assertEqual(len(row['sites']), 3 + len(row['methods']))
            self.assertEqual(sum(len(bytes.fromhex(site['before'])) for site in row['sites']),
                             36 + (12 if thermal.SCENE_METHOD in row['methods'] else 0))
            self.assertNotIn('avd', row['path'].lower())

    def test_unknown_input_is_rejected_without_any_output(self):
        for value in (b'unknown', b'', None, 'not bytes'):
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                thermal.patch_bytes(value)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            thermal.recipe_receipt('unknown')
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'source.jar', Path(directory) / 'out.jar'
            source.write_bytes(b'unknown')
            with self.assertRaises(RuntimeError):
                thermal.patch(source, output)
            self.assertFalse(output.exists())

    def test_both_real_derivatives_are_exact_idempotent_and_only_change_declared_sites(self):
        for original in self.artifacts():
            before, rule, patched = thermal.select_recipe(original)
            self.assertFalse(patched)
            result = thermal.patch_bytes(original)
            self.assertFalse(thermal.audit(original))
            self.assertTrue(thermal.audit(result))
            self.assertEqual(hashlib.sha256(result).hexdigest(), rule['after'])
            self.assertEqual(thermal.patch_bytes(result), result)
            self.assertEqual(thermal.receipt(original), thermal.recipe_receipt(before))
            self.assertEqual(thermal.receipt(result), thermal.receipt(original))
            self.assertEqual(len(result), len(original))
            allowed = {offset + index for offset, old, _ in rule['sites']
                       for index in range(len(bytes.fromhex(old)))}
            actual = {index for index, (old, new) in enumerate(zip(original, result)) if old != new}
            self.assertLessEqual(actual, allowed)

    def test_return_precedes_lock_handler_and_sampler_without_fabricating_a_reading(self):
        for original in self.artifacts():
            _, rule, _ = thermal.select_recipe(original)
            result = thermal.patch_bytes(original)
            offset, code = rule['dex_offset'], rule['code_offset']
            old = original[offset:offset + rule['dex_size']]
            new = result[offset:offset + rule['dex_size']]
            self.assertEqual(thermal._method(old, rule), code)
            self.assertEqual(thermal._method(new, rule), code)
            self.assertEqual(struct.unpack_from('<4H2I', new, code), rule['code_header'])
            # IGET_OBJECT takes two code units; replace it fully before MONITOR_ENTER.
            self.assertEqual(old[code + 16], 0x54)
            self.assertEqual(new[code + 16:code + 20], b'\x0e\0\0\0')
            if 'scene' in rule:
                site = rule['scene']['code_offset'] + 16
                self.assertEqual(old[32:site], new[32:site])
                self.assertEqual(old[site + 12:code + 16], new[site + 12:code + 16])
            else:
                self.assertEqual(old[32:code + 16], new[32:code + 16])
            self.assertEqual(old[code + 20:], new[code + 20:])
            self.assertEqual(new[code + 20], 0x1d)
            # Preserve the OEM method's complete body/tables, including parsing
            # and INVALID_TEMPERATURE fallback, rather than inventing a value.
            self.assertIn(thermal.NODE.encode() + b'\0', new)

    def test_scene_uses_original_failure_sentinel_and_retains_thermal_zone_fallback(self):
        seen = 0
        for original in self.artifacts():
            _, rule, _ = thermal.select_recipe(original)
            if 'scene' not in rule:
                continue
            seen += 1
            scene = rule['scene']
            old = original[rule['dex_offset']:rule['dex_offset'] + rule['dex_size']]
            result = thermal.patch_bytes(original)
            new = result[rule['dex_offset']:rule['dex_offset'] + rule['dex_size']]
            code = thermal._method(new, scene, scene=True)
            self.assertEqual(code, scene['code_offset'])
            self.assertEqual(struct.unpack_from('<4H2I', new, code), scene['code_header'])
            self.assertEqual(new[code + 16:code + 28], thermal.UNAVAILABLE_BOARD)
            # CONST/4 v0,-1 then five NOPs replaces complete fixed-node
            # CONST_STRING, INVOKE_STATIC and MOVE_RESULT instructions.
            # IF_LTZ and the original optional thermal-zone read stay intact.
            self.assertEqual(new[code + 28:code + 60], old[code + 28:code + 60])
            self.assertEqual(new[code + 28:code + 32], bytes.fromhex('3a000300'))
            self.assertEqual(old[code + 16:code + 28], bytes.fromhex(scene['original']))
            self.assertEqual(new[code + 58:code + 60], bytes.fromhex('0f01'))
        self.assertEqual(seen, 1)

    def test_dex_and_zip_checksums_metadata_and_other_members_are_preserved(self):
        for original in self.artifacts():
            _, rule, _ = thermal.select_recipe(original)
            result = thermal.patch_bytes(original)
            with zipfile.ZipFile(io.BytesIO(original)) as old, zipfile.ZipFile(io.BytesIO(result)) as new:
                self.assertIsNone(new.testzip())
                self.assertEqual(old.namelist(), new.namelist())
                for left, right in zip(old.infolist(), new.infolist()):
                    for attribute in ('filename', 'compress_type', 'header_offset', 'file_size',
                                      'compress_size', 'flag_bits', 'date_time', 'extra', 'comment',
                                      'external_attr', 'internal_attr'):
                        self.assertEqual(getattr(left, attribute), getattr(right, attribute))
                    if left.filename != rule['member']:
                        self.assertEqual(old.read(left), new.read(right))
                dex = new.read(rule['member'])
            self.assertEqual(dex[12:32], hashlib.sha1(dex[32:]).digest())
            self.assertEqual(struct.unpack_from('<I', dex, 8)[0], zlib.adler32(dex[12:]) & 0xffffffff)

    def test_tampered_signed_and_partial_inputs_fail_closed(self):
        for original in self.artifacts():
            _, rule, _ = thermal.select_recipe(original)
            for position in (0, 14, rule['dex_offset'] + 8,
                             rule['dex_offset'] + rule['code_offset'] + 16, len(original) - 1):
                corrupt = bytearray(original)
                corrupt[position] ^= 1
                with self.subTest(position=position), self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                    thermal.patch_bytes(corrupt)
            with self.assertRaises(RuntimeError):
                thermal.patch_bytes(original + b'APK Sig Block 42')
            partial = bytearray(original)
            start = rule['dex_offset'] + rule['code_offset'] + 16
            partial[start:start + 4] = thermal.RETURN_VOID
            with self.assertRaises(RuntimeError):
                thermal.patch_bytes(partial)

    def test_atomic_output_preserves_factory_customized_content_and_aliases(self):
        original = self.artifacts()[0]
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source, output = folder / 'source.jar', folder / 'out.jar'
            source.write_bytes(original)
            thermal.patch(source, output)
            inode = output.stat().st_ino
            thermal.patch(source, output)
            self.assertEqual(output.stat().st_ino, inode)
            self.assertEqual(source.read_bytes(), original)
            with self.assertRaises(RuntimeError):
                thermal.patch(source, source)
            alias = folder / 'alias.jar'
            alias.symlink_to(output)
            with self.assertRaises(RuntimeError):
                thermal.patch(source, alias)
            output.write_bytes(b'customized')
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                thermal.patch(source, output)
            self.assertEqual(output.read_bytes(), b'customized')
            self.assertFalse(list(folder.glob('.thermal-*')))

    def test_racing_output_is_preserved_and_temporary_file_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source, output = folder / 'source.jar', folder / 'out.jar'
            source.write_bytes(self.artifacts()[0])

            def race(*_):
                output.write_bytes(b'user content')
                raise FileExistsError()

            with patch.object(thermal.os, 'link', side_effect=race):
                with self.assertRaisesRegex(RuntimeError, 'unknown'):
                    thermal.patch(source, output)
            self.assertEqual(output.read_bytes(), b'user content')
            self.assertFalse(list(folder.glob('.thermal-*')))

    def scene_artifact(self):
        return thermal.patch_bytes(self.artifacts()[1])

    def test_scene_successor_keeps_frozen_monitor_selection_and_receipts(self):
        expected = {
            '3f7182f39f7c3d40af9d706cba3087e08c87c9e6dec32802ef296192c4707e40':
                'd936fe7a0ae7ab91aacf54011dbdf6fca6bcd3e1484bdb1326a17b4da9d27ffe',
            '9817dbd23cda60edc72c9dfac9c586d44fd9932c2cce95900a8531d6c1fff817':
                '3fe9549794c29da738574f9b17da496f95e7a6408dcf5db5a82d5499872075a6',
        }
        self.assertEqual({before: row['after'] for before, row in thermal.RECIPES.items()}, expected)
        prior = self.scene_artifact()
        before, rule, patched = thermal.select_recipe(prior)
        self.assertTrue(patched)
        self.assertEqual(thermal.patch_bytes(prior), prior)
        self.assertEqual(thermal.receipt(prior), thermal.recipe_receipt(before))
        # The same whole JAR is the historical final output and the distinct
        # new producer's initial input; never reinterpret the old operation.
        source, successor, patched = thermal.select_scene_recipe(prior)
        self.assertFalse(patched)
        self.assertEqual(source, rule['after'])
        self.assertNotEqual(successor['after'], source)
        self.assertEqual(thermal.catalog_recipes(),
                         tuple(thermal.recipe_receipt(key) for key in thermal.RECIPES) +
                         tuple(thermal.scene_recipe_receipt(key) for key in thermal.SCENE_RECIPES))

    def test_real_scene_successor_is_exact_idempotent_and_only_changes_four_sites(self):
        original = self.scene_artifact()
        before, rule, _ = thermal.select_scene_recipe(original)
        result = thermal.scene_patch_bytes(original)
        self.assertFalse(thermal.scene_audit(original))
        self.assertTrue(thermal.scene_audit(result))
        self.assertEqual(hashlib.sha256(result).hexdigest(), rule['after'])
        self.assertEqual(thermal.scene_patch_bytes(result), result)
        self.assertEqual(thermal.scene_receipt(result), thermal.scene_recipe_receipt(before))
        self.assertEqual(thermal.scene_receipt(original), thermal.scene_receipt(result))
        self.assertEqual(len(result), len(original))
        self.assertEqual(len(rule['sites']), 4)
        self.assertEqual(sum(len(bytes.fromhex(old)) for _, old, _ in rule['sites']), 44)
        allowed = {offset + index for offset, old, _ in rule['sites']
                   for index in range(len(bytes.fromhex(old)))}
        actual = {index for index, (old, new) in enumerate(zip(original, result)) if old != new}
        self.assertLessEqual(actual, allowed)

    def test_scene_failure_sentinel_preserves_optional_zone_read_and_other_dex(self):
        original = self.scene_artifact()
        _, rule, _ = thermal.select_scene_recipe(original)
        result = thermal.scene_patch_bytes(original)
        with zipfile.ZipFile(io.BytesIO(original)) as old, zipfile.ZipFile(io.BytesIO(result)) as new:
            self.assertIsNone(new.testzip())
            self.assertEqual(old.namelist(), new.namelist())
            for left, right in zip(old.infolist(), new.infolist()):
                for attribute in ('filename', 'compress_type', 'header_offset', 'file_size',
                                  'compress_size', 'flag_bits', 'date_time', 'extra', 'comment',
                                  'external_attr', 'internal_attr'):
                    self.assertEqual(getattr(left, attribute), getattr(right, attribute))
                if left.filename != rule['member']:
                    self.assertEqual(old.read(left), new.read(right))
            before, after = old.read(rule['member']), new.read(rule['member'])
            self.assertEqual(hashlib.sha256(new.read(rule['preserved_member'])).hexdigest(), rule['preserved_sha256'])
        code = thermal._method(after, rule, scene=True)
        self.assertEqual(struct.unpack_from('<4H2I', after, code), rule['code_header'])
        self.assertEqual(after[code + 16:code + 28], thermal.UNAVAILABLE_BOARD)
        self.assertEqual(after[32:code + 16], before[32:code + 16])
        self.assertEqual(after[code + 28:], before[code + 28:])
        # Retain IF_LTZ, fallback field read, optional readTempFromPath call,
        # and final original -1. Generic file and ambient/SoC reads survive.
        self.assertEqual(after[code + 28:code + 32], bytes.fromhex('3a000300'))
        self.assertEqual(after[code + 56:code + 60], bytes.fromhex('12f10f01'))
        self.assertEqual(after[12:32], hashlib.sha1(after[32:]).digest())
        self.assertEqual(struct.unpack_from('<I', after, 8)[0], zlib.adler32(after[12:]) & 0xffffffff)

    def test_scene_successor_receipt_keeps_the_same_real_hardware_absence_gate(self):
        for before, rule in thermal.SCENE_RECIPES.items():
            row = thermal.scene_recipe_receipt(before)
            self.assertEqual(row['requires'], 'ranchu-without-board-temperature-node')
            self.assertEqual(row['absent_node'], thermal.NODE)
            self.assertEqual(row['path'], thermal.PATH)
            self.assertEqual(row['methods'], [thermal.SCENE_METHOD])
            self.assertEqual(row['before'], before)
            self.assertEqual(row['after'], rule['after'])
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            thermal.scene_recipe_receipt('unknown')

    def test_scene_rejects_tampered_signed_partial_and_wrong_predecessor_inputs(self):
        original = self.scene_artifact()
        _, rule, _ = thermal.select_scene_recipe(original)
        for position in (0, 14, rule['dex_offset'] + 8, rule['dex_offset'] + rule['code_offset'] + 16,
                         len(original) - 1):
            corrupt = bytearray(original)
            corrupt[position] ^= 1
            with self.subTest(position=position), self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                thermal.scene_patch_bytes(corrupt)
        partial = bytearray(original)
        start = rule['dex_offset'] + rule['code_offset'] + 16
        partial[start:start + 12] = thermal.UNAVAILABLE_BOARD
        for value in (partial, original + b'APK Sig Block 42', b'unknown', None, self.artifacts()[1]):
            with self.subTest(value_type=type(value)), self.assertRaises(RuntimeError):
                thermal.scene_patch_bytes(value)

    def test_scene_atomic_output_retains_original_unknown_and_alias_content(self):
        original = self.scene_artifact()
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source, output = folder / 'source.jar', folder / 'out.jar'
            source.write_bytes(original)
            thermal.patch(source, output, scene=True)
            inode = output.stat().st_ino
            thermal.patch(source, output, scene=True)
            self.assertEqual(output.stat().st_ino, inode)
            self.assertEqual(source.read_bytes(), original)
            with self.assertRaises(RuntimeError):
                thermal.patch(source, source, scene=True)
            alias = folder / 'alias.jar'
            alias.symlink_to(output)
            with self.assertRaises(RuntimeError):
                thermal.patch(source, alias, scene=True)
            output.write_bytes(b'customized')
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                thermal.patch(source, output, scene=True)
            self.assertEqual(output.read_bytes(), b'customized')
            self.assertFalse(list(folder.glob('.thermal-*')))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_uniperf_patch.py ---

"""Keep the missing physical Uniperf HAL out of one unsigned-JAR capability."""

class UniperfPatchTests(unittest.TestCase):
    def artifact(self):
        path = Path(os.environ.get('HYPEROS_AVD_UNIPERF_ARTIFACT', str(
            REPO / 'work/feedback-investigation-20261013/phone-perf-callers/UniperfClient.jar')))
        if not path.is_file():
            self.skipTest('Audited proprietary unsigned Uniperf JAR is not distributed in Git.')
        return path.read_bytes()

    def test_real_derivative_is_exact_idempotent_and_only_changes_four_sites(self):
        original = self.artifact()
        output = uniperf.patch_bytes(original)
        self.assertEqual(hashlib.sha256(output).hexdigest(), uniperf.AFTER)
        self.assertFalse(uniperf.audit(original))
        self.assertTrue(uniperf.audit(output))
        self.assertEqual(uniperf.patch_bytes(output), output)
        self.assertEqual(len(original), len(output))
        allowed = {offset + index for offset, before, _ in uniperf.SITES
                   for index in range(len(bytes.fromhex(before)))}
        changed = {index for index, (old, new) in enumerate(zip(original, output)) if old != new}
        self.assertLessEqual(changed, allowed)
        self.assertEqual(len(uniperf.SITES), 4)
        self.assertEqual(sum(len(bytes.fromhex(row[1])) for row in uniperf.SITES), 38)

    def test_false_return_covers_complete_instructions_before_any_lock(self):
        original = self.artifact()
        start = uniperf.DEX_OFFSET + uniperf.CODE_OFFSET + 16
        self.assertEqual(original[start:start + 6], bytes.fromhex('120062010900'))
        result = uniperf.patch_bytes(original)
        self.assertEqual(result[start:start + 6], bytes.fromhex('12000f000000'))
        # CONST/4 is one code unit; SGET_OBJECT is two. A four-byte patch
        # would strand operand0009 as a different multi-unit instruction.
        self.assertEqual(uniperf.ORIGINAL[2] & 0xff, 0x62)
        self.assertEqual(uniperf.ORIGINAL[4:6], b'\x09\0')
        self.assertEqual(list(struct.unpack('<3H', result[start:start + 6])), [0x12, 0xf, 0])
        self.assertEqual(original[start + 6:start + 16], result[start + 6:start + 16])

    def test_entire_following_code_try_handlers_debug_and_dex_tables_survive(self):
        original = self.artifact()
        output = uniperf.patch_bytes(original)
        offset = uniperf.DEX_OFFSET
        old = original[offset:offset + uniperf.DEX_SIZE]
        new = output[offset:offset + uniperf.DEX_SIZE]
        code = uniperf._method(old)
        self.assertEqual(code, uniperf.CODE_OFFSET)
        self.assertEqual(uniperf._method(new), code)
        self.assertEqual(struct.unpack_from('<4H2I', new, code), uniperf.CODE_HEADER)
        self.assertEqual(old[32:code + 16], new[32:code + 16])
        self.assertEqual(old[code + 22:], new[code + 22:])
        # There are seven unchanged try_item records after the 151-unit body.
        tries = code + 16 + 2 * uniperf.CODE_HEADER[5]
        tries += tries % 4
        self.assertEqual(old[tries:tries + 7 * 8], new[tries:tries + 7 * 8])
        self.assertIn(uniperf.HAL.encode() + b'\0', new)

    def test_dex_and_zip_checksums_are_valid_without_archive_repacking(self):
        original = self.artifact()
        output = uniperf.patch_bytes(original)
        with zipfile.ZipFile(io.BytesIO(original)) as before, zipfile.ZipFile(io.BytesIO(output)) as after:
            self.assertIsNone(after.testzip())
            self.assertEqual(before.namelist(), after.namelist())
            self.assertEqual(before.read('META-INF/MANIFEST.MF'), after.read('META-INF/MANIFEST.MF'))
            for old, new in zip(before.infolist(), after.infolist()):
                for attribute in ('filename', 'compress_type', 'header_offset', 'file_size',
                                  'compress_size', 'flag_bits', 'date_time', 'extra', 'comment',
                                  'external_attr', 'internal_attr'):
                    self.assertEqual(getattr(old, attribute), getattr(new, attribute))
            dex = after.read('classes.dex')
        self.assertEqual(hashlib.sha256(dex).hexdigest(), uniperf.DEX_AFTER)
        self.assertEqual(dex[12:32], hashlib.sha1(dex[32:]).digest())
        self.assertEqual(struct.unpack_from('<I', dex, 8)[0], zlib.adler32(dex[12:]) & 0xffffffff)
        self.assertNotIn(b'APK Sig Block 42', output)

    def test_catalog_is_one_source_for_both_hal_free_device_forms(self):
        data = self.artifact()
        recipe = uniperf.recipe_receipt()
        self.assertEqual(uniperf.catalog_recipes()[0], recipe)
        self.assertEqual(uniperf.receipt(data), recipe)
        self.assertEqual(recipe['path'], uniperf.PATH)
        self.assertEqual(recipe['absent_hal'], uniperf.HAL)
        output = bytearray(data)
        for site in recipe['sites']:
            offset = site['offset']
            before, after = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
            self.assertEqual(len(before), len(after))
            self.assertEqual(output[offset:offset + len(before)], before)
            output[offset:offset + len(after)] = after
        self.assertEqual(hashlib.sha256(output).hexdigest(), uniperf.AFTER)
        self.assertEqual(uniperf.receipt(output), recipe)
        self.assertEqual(recipe['methods'], [uniperf.METHOD])

    def test_unknown_tampered_signed_or_partial_content_is_never_patched(self):
        data = self.artifact()
        for position in (0, 14, uniperf.DEX_OFFSET + 8, uniperf.DEX_OFFSET + uniperf.CODE_OFFSET + 16,
                         len(data) - 1):
            modified = bytearray(data)
            modified[position] ^= 1
            with self.subTest(position=position), self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                uniperf.patch_bytes(modified)
        with self.assertRaises(RuntimeError):
            uniperf.patch_bytes(data + b'APK Sig Block 42')
        offset, _, after = uniperf.SITES[2]
        partial = bytearray(data)
        partial[offset:offset + 6] = bytes.fromhex(after)
        with self.assertRaises(RuntimeError):
            uniperf.patch_bytes(partial)
        with self.assertRaises(RuntimeError):
            uniperf.recipe_receipt('unknown input')

    def test_atomic_output_preserves_factory_unknown_content_and_aliases(self):
        data = self.artifact()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'factory.jar', root / 'gated.jar'
            source.write_bytes(data)
            uniperf.patch(source, output)
            inode = output.stat().st_ino
            uniperf.patch(source, output)
            self.assertEqual(output.stat().st_ino, inode)
            self.assertEqual(source.read_bytes(), data)
            with self.assertRaises(RuntimeError):
                uniperf.patch(source, source)
            alias = root / 'alias.jar'
            alias.symlink_to(output)
            with self.assertRaises(RuntimeError):
                uniperf.patch(source, alias)
            output.write_bytes(b'custom state')
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                uniperf.patch(source, output)
            self.assertEqual(output.read_bytes(), b'custom state')
            self.assertFalse(list(root.glob('.uniperf-*')))

    def test_racing_output_is_preserved_without_partial_temporary_leaves(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'factory.jar', root / 'gated.jar'
            source.write_bytes(self.artifact())

            def race(*_):
                output.write_bytes(b'user content')
                raise FileExistsError()

            with patch.object(uniperf.os, 'link', side_effect=race), self.assertRaises(RuntimeError):
                uniperf.patch(source, output)
            self.assertEqual(output.read_bytes(), b'user content')
            self.assertFalse(list(root.glob('.uniperf-*')))

class SystemServerUniperfPatchTests(unittest.TestCase):
    def artifacts(self):
        result = []
        for form in ('phone', 'pad'):
            default = (REPO / 'work/feedback-investigation-20261013' /
                       (form + '-uniperf-loaded-caller') / 'miui-services.jar')
            path = Path(os.environ.get('HYPEROS_AVD_' + form.upper() + '_UNIPERF_SERVICES', str(default)))
            if not path.is_file():
                self.skipTest('Audited proprietary system-server JARs are not distributed in Git.')
            data = path.read_bytes()
            before, rule, patched = uniperf.select_recipe(data)
            self.assertFalse(patched)
            self.assertEqual(rule['path'], uniperf.MIUI_SERVICES)
            result.append((form, before, rule, data))
        return result

    def test_loaded_copies_patch_exactly_and_repeat_without_touching_other_archive_bytes(self):
        for form, before, rule, data in self.artifacts():
            with self.subTest(form=form):
                output = uniperf.patch_bytes(data)
                self.assertEqual(hashlib.sha256(output).hexdigest(), rule['after'])
                self.assertEqual(uniperf.patch_bytes(output), output)
                self.assertFalse(uniperf.audit(data))
                self.assertTrue(uniperf.audit(output))
                self.assertEqual(len(output), len(data))
                start = 0
                for offset, old, new in rule['sites']:
                    self.assertEqual(data[start:offset], output[start:offset])
                    self.assertEqual(data[offset:offset + len(bytes.fromhex(old))], bytes.fromhex(old))
                    self.assertEqual(output[offset:offset + len(bytes.fromhex(new))], bytes.fromhex(new))
                    start = offset + len(bytes.fromhex(old))
                self.assertEqual(data[start:], output[start:])
                self.assertEqual(sum(len(bytes.fromhex(site[1])) for site in rule['sites']), 38)
                self.assertEqual(uniperf.receipt(output), uniperf.recipe_receipt(before))

    def test_embedded_public_static_boolean_stops_before_lock_preserving_try_debug_and_all_other_code(self):
        for form, _, rule, data in self.artifacts():
            with self.subTest(form=form):
                output = uniperf.patch_bytes(data)
                offset, size = rule['dex_offset'], rule['dex_size']
                old, new = data[offset:offset + size], output[offset:offset + size]
                code = uniperf._method(old, rule['code_offset'])
                self.assertEqual(uniperf._method(new, code), code)
                self.assertEqual(struct.unpack_from('<4H2I', new, code), rule['code_header'])
                self.assertEqual(old[32:code + 16], new[32:code + 16])
                self.assertEqual(old[code + 22:], new[code + 22:])
                self.assertEqual(old[code + 16:code + 22].hex(), rule['original'])
                self.assertEqual(struct.unpack_from('<3H', new, code + 16), (0x12, 0xf, 0))
                self.assertEqual(old[code + 22:code + 26], new[code + 22:code + 26])
                self.assertEqual(new[12:32], hashlib.sha1(new[32:]).digest())
                self.assertEqual(struct.unpack_from('<I', new, 8)[0], zlib.adler32(new[12:]) & 0xffffffff)
                self.assertIn(uniperf.HAL.encode() + b'\0', new)

    def test_multidex_and_compressed_metadata_are_preserved_with_valid_selected_member_crc(self):
        for form, _, rule, data in self.artifacts():
            with self.subTest(form=form):
                output = uniperf.patch_bytes(data)
                with zipfile.ZipFile(io.BytesIO(data)) as before, zipfile.ZipFile(io.BytesIO(output)) as after:
                    self.assertIsNone(after.testzip())
                    self.assertEqual(before.namelist(), after.namelist())
                    self.assertEqual(len(before.infolist()), rule['count'])
                    self.assertEqual(before.getinfo(rule['member']).compress_type, zipfile.ZIP_STORED)
                    self.assertTrue(any(item.compress_type == zipfile.ZIP_DEFLATED for item in before.infolist()))
                    for old, new in zip(before.infolist(), after.infolist()):
                        for attribute in ('filename', 'compress_type', 'header_offset', 'file_size',
                                          'compress_size', 'flag_bits', 'date_time', 'extra', 'comment',
                                          'external_attr', 'internal_attr'):
                            self.assertEqual(getattr(old, attribute), getattr(new, attribute))
                        if old.filename != rule['member']:
                            self.assertEqual(old.CRC, new.CRC)
                            self.assertEqual(before.read(old.filename), after.read(new.filename))
                    self.assertEqual(hashlib.sha256(after.read(rule['member'])).hexdigest(), rule['dex_after'])

    def test_canonical_offline_sites_cover_both_boot_artifacts_without_changing_legacy_receipt(self):
        from patch_boot_services import AFTER as boot_after
        self.assertIn(boot_after['miui-services'], uniperf.RECIPES)
        rows = uniperf.catalog_recipes()
        self.assertEqual(len(rows), 3)
        legacy = uniperf.recipe_receipt()
        self.assertEqual(legacy['before'], uniperf.BEFORE)
        self.assertEqual(legacy['after'], uniperf.AFTER)
        self.assertEqual(legacy['sites'], [
            {'offset': offset, 'before': old, 'after': new,
             **({'method': uniperf.METHOD} if index == 2 else {})}
            for index, (offset, old, new) in enumerate(uniperf.SITES)])
        # Frozen Core 10 authenticates this complete standalone recipe.
        fixture = json.loads((REPO / 'tests/fixtures/native-compat-v10-final-manifest.json').read_text())
        for index, site in enumerate(legacy['sites']):
            for state in ('before', 'after'):
                key = 'sites/uniperf-d002c55e9b66/%03d.%s' % (index, state)
                self.assertEqual(hashlib.sha256(bytes.fromhex(site[state])).hexdigest(),
                                 fixture['files_sha256'][key])
        for form, digest, _, data in self.artifacts():
            with self.subTest(form=form):
                recipe = uniperf.recipe_receipt(digest)
                output = bytearray(data)
                for site in recipe['sites']:
                    offset = site['offset']
                    old, new = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
                    self.assertEqual(len(old), len(new))
                    self.assertEqual(output[offset:offset + len(old)], old)
                    output[offset:offset + len(new)] = new
                self.assertEqual(hashlib.sha256(output).hexdigest(), recipe['after'])
                self.assertEqual(recipe['methods'], [uniperf.METHOD])

    def test_unknown_partial_checksum_or_boot_derivatives_are_retained(self):
        for form, _, rule, data in self.artifacts():
            with self.subTest(form=form):
                for site in rule['sites']:
                    offset, _, new = site
                    partial = bytearray(data)
                    partial[offset:offset + len(bytes.fromhex(new))] = bytes.fromhex(new)
                    with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                        uniperf.patch_bytes(partial)
                # An unrelated boot-services edit must not be treated as this known input.
                unknown = bytearray(data)
                unknown[45] ^= 1
                with self.assertRaises(RuntimeError):
                    uniperf.patch_bytes(unknown)
                with self.assertRaises(RuntimeError):
                    uniperf.patch_bytes(data + b'APK Sig Block 42')

    def test_layout_explicitly_refuses_compressed_signed_or_descriptor_selected_dex(self):
        for compression, name in ((zipfile.ZIP_DEFLATED, 'README.txt'),
                                  (zipfile.ZIP_STORED, 'META-INF/factory.RSA')):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, 'w') as archive:
                archive.writestr('classes2.dex', b'dex placeholder', compress_type=compression)
                archive.writestr(name, b'unchanged metadata')
            with self.assertRaises(RuntimeError):
                uniperf._stored_dex_layout(stream.getvalue(), 'classes2.dex', 2)
        for form, _, rule, data in self.artifacts():
            with self.subTest(form=form):
                altered = bytearray(data)
                local = rule['sites'][0][0] - 14
                directory = rule['sites'][3][0] - 16
                struct.pack_into('<H', altered, local + 6, 8)
                struct.pack_into('<H', altered, directory + 8, 8)
                with self.assertRaisesRegex(RuntimeError, 'storage'):
                    uniperf._stored_dex_layout(altered, rule['member'], rule['count'])

if __name__ == '__main__':
    unittest.main()


# --- tests/test_wifi_capabilities_patch.py ---

"""Content and byte-preservation checks for the physical WLAN capability gates."""

SOURCES = (
    ROOT / 'work/feedback-investigation-20261013/phone-wifi-service.jar',
    ROOT / 'work/feedback-investigation-20261013/pad-producer-audit/miui-wifi-service.jar',
)

def actual_sources():
    found = {}
    for path in SOURCES:
        if path.is_file():
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest in wifi.RECIPES:
                found[digest] = data
    return found

class WifiCapabilitiesCatalogTests(unittest.TestCase):
    def test_canonical_receipts_have_only_audited_capability_methods(self):
        receipts = wifi.catalog_recipes()
        self.assertEqual(len(receipts), 2)
        for receipt in receipts:
            self.assertEqual(receipt['path'], wifi.PATH)
            self.assertEqual(receipt['format'], 'framework-jar')
            self.assertEqual(receipt['methods'], list(wifi.METHODS))
            self.assertNotIn('isWifiSarNeeded', '\n'.join(receipt['methods']))
            self.assertEqual(receipt['requires'], 'ranchu-without-proprietary-wlan-sar')
            self.assertEqual(len(receipt['sites']), 6)
            previous = 0
            for site in receipt['sites']:
                self.assertGreaterEqual(site['offset'], previous)
                original, changed = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
                self.assertEqual(len(original), len(changed))
                self.assertNotEqual(original, changed)
                previous = site['offset'] + len(original)
                self.assertLessEqual(previous, receipt['size'])
                if 'method' in site:
                    self.assertEqual(changed[:4], wifi.FALSE_RETURN)
                    self.assertEqual(set(changed[4:]), {0})

    def test_receipts_are_independent_and_do_not_mutate_constants(self):
        first = wifi.catalog_recipes()
        first[0]['sites'][0]['before'] = '00'
        first[0]['methods'].clear()
        second = wifi.catalog_recipes()
        self.assertNotEqual(second[0]['sites'][0]['before'], '00')
        self.assertEqual(second[0]['methods'], list(wifi.METHODS))

    def test_unknown_or_tampered_input_refuses_before_output_creation(self):
        for data in (b'', b'PK\x03\x04', b'fake framework.jar'):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                wifi.patch_bytes(data)
        for value in (None, True, 1, [], 'unknown'):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                wifi.select_recipe(value)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'factory.jar'
            target = Path(directory) / 'absent/output.jar'
            source.write_bytes(b'unknown custom content')
            with self.assertRaises(RuntimeError):
                wifi.patch(source, target)
            self.assertEqual(source.read_bytes(), b'unknown custom content')
            self.assertFalse(target.parent.exists())

    def test_unknown_receipt_cannot_reuse_an_output_identity(self):
        for recipe in wifi.RECIPES.values():
            with self.assertRaises(RuntimeError):
                wifi.recipe_receipt(recipe['after'])

class WifiCapabilitiesAuditedInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = actual_sources()
        if not cls.sources:
            raise unittest.SkipTest('Audited private JAR inputs unavailable; no download attempted.')

    def test_repeat_is_exact_and_byte_sites_reproduce_derivative(self):
        for before, data in self.sources.items():
            with self.subTest(before=before):
                receipt = wifi.receipt(data)
                output = wifi.patch_bytes(data)
                self.assertEqual(hashlib.sha256(output).hexdigest(), receipt['after'])
                self.assertEqual(wifi.patch_bytes(output), output)
                self.assertEqual(wifi.patch_bytes(data), output)
                replay = bytearray(data)
                for site in receipt['sites']:
                    offset = site['offset']
                    original, changed = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
                    self.assertEqual(replay[offset:offset + len(original)], original)
                    replay[offset:offset + len(changed)] = changed
                self.assertEqual(bytes(replay), output)
                with self.assertRaisesRegex(RuntimeError, 'original input'):
                    wifi.receipt(output)

    def test_every_other_byte_and_zip_entry_remains_unchanged(self):
        for before, data in self.sources.items():
            with self.subTest(before=before):
                output = wifi.patch_bytes(data)
                sites = wifi.recipe_receipt(before)['sites']
                cursor = 0
                for site in sites:
                    self.assertEqual(data[cursor:site['offset']], output[cursor:site['offset']])
                    cursor = site['offset'] + len(bytes.fromhex(site['before']))
                self.assertEqual(data[cursor:], output[cursor:])
                self.assertEqual(len(data), len(output))
                with zipfile.ZipFile(io.BytesIO(data)) as original, zipfile.ZipFile(io.BytesIO(output)) as changed:
                    self.assertIsNone(changed.testzip())
                    self.assertEqual(original.namelist(), ['classes.dex', 'META-INF/MANIFEST.MF'])
                    self.assertEqual(original.namelist(), changed.namelist())
                    self.assertEqual(original.read('META-INF/MANIFEST.MF'), changed.read('META-INF/MANIFEST.MF'))
                    for a, b in zip(original.infolist(), changed.infolist()):
                        for attribute in ('filename', 'date_time', 'compress_type', 'flag_bits', 'extra',
                                          'comment', 'file_size', 'compress_size', 'external_attr',
                                          'internal_attr', 'header_offset', 'create_system', 'create_version'):
                            self.assertEqual(getattr(a, attribute), getattr(b, attribute), attribute)

    def test_dex_checksums_tables_headers_and_only_three_bodies(self):
        for before, data in self.sources.items():
            with self.subTest(before=before):
                output = wifi.patch_bytes(data)
                recipe = wifi.RECIPES[before]
                start, length, _, _ = wifi._zip_layout(data)
                original, changed = data[start:start + length], output[start:start + length]
                self.assertEqual(wifi._dex_methods(original), wifi._dex_methods(changed))
                self.assertEqual(changed[:8], original[:8])
                self.assertEqual(changed[12:32], hashlib.sha1(changed[32:]).digest())
                self.assertEqual(struct.unpack_from('<I', changed, 8)[0], zlib.adler32(changed[12:]) & 0xffffffff)
                cursor = 32
                for code, _, header, _ in recipe['methods']:
                    self.assertEqual(original[cursor:code + 16], changed[cursor:code + 16])
                    size = 2 * header[5]
                    self.assertEqual(changed[code + 16:code + 20], wifi.FALSE_RETURN)
                    self.assertEqual(changed[code + 20:code + 16 + size], b'\0' * (size - 4))
                    cursor = code + 16 + size
                self.assertEqual(original[cursor:], changed[cursor:])

    def test_target_method_guard_rejects_code_header_or_body_tampering(self):
        for before, data in self.sources.items():
            recipe = wifi.RECIPES[before]
            start, length, local_crc, central_crc = wifi._zip_layout(data)
            for relative in (recipe['methods'][0][0], recipe['methods'][0][0] + 16):
                altered = bytearray(data)
                altered[start + relative] ^= 1
                dex = bytearray(altered[start:start + length])
                dex[12:32] = hashlib.sha1(dex[32:]).digest()
                struct.pack_into('<I', dex, 8, zlib.adler32(dex[12:]) & 0xffffffff)
                altered[start:start + length] = dex
                for offset in (local_crc, central_crc):
                    struct.pack_into('<I', altered, offset, zlib.crc32(dex) & 0xffffffff)
                with self.assertRaises(RuntimeError):
                    wifi.patch_bytes(bytes(altered))
                with self.assertRaisesRegex(RuntimeError, 'DEX content'):
                    wifi._rewrite(bytes(altered), recipe)

    def test_repeated_output_preserves_inode_and_factory_input(self):
        before, data = next(iter(self.sources.items()))
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'factory.jar', Path(directory) / 'patched.jar'
            source.write_bytes(data)
            wifi.patch(source, target)
            initial = target.stat()
            wifi.patch(source, target)
            self.assertEqual((target.stat().st_ino, target.stat().st_mtime_ns),
                             (initial.st_ino, initial.st_mtime_ns))
            self.assertEqual(source.read_bytes(), data)
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), wifi.RECIPES[before]['after'])
            with self.assertRaisesRegex(RuntimeError, 'separate'):
                wifi.patch(source, source)

    def test_unknown_existing_output_symlink_and_hardlink_are_preserved(self):
        data = next(iter(self.sources.values()))
        with tempfile.TemporaryDirectory() as directory:
            source, target, other = [Path(directory) / name for name in ('factory.jar', 'patched.jar', 'other')]
            source.write_bytes(data)
            target.write_bytes(b'custom output')
            with self.assertRaises(RuntimeError):
                wifi.patch(source, target)
            self.assertEqual(target.read_bytes(), b'custom output')
            target.unlink()
            other.write_bytes(wifi.patch_bytes(data))
            target.symlink_to(other)
            with self.assertRaises(RuntimeError):
                wifi.patch(source, target)
            self.assertTrue(target.is_symlink())
            target.unlink()
            os.link(other, target)
            with self.assertRaises(RuntimeError):
                wifi.patch(source, target)
            self.assertEqual(target.stat().st_nlink, 2)

    def test_racing_unknown_output_is_not_overwritten(self):
        data = next(iter(self.sources.values()))
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'factory.jar', Path(directory) / 'patched.jar'
            source.write_bytes(data)

            def occupied(_source, destination):
                Path(destination).write_bytes(b'new user output')
                raise FileExistsError()

            with mock.patch.object(wifi.os, 'link', side_effect=occupied):
                with self.assertRaises(RuntimeError):
                    wifi.patch(source, target)
            self.assertEqual(target.read_bytes(), b'new user output')
            self.assertFalse(list(Path(directory).glob('.wifi-capabilities-*')))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_xiaomi_ims_patch.py ---

"""Guard the vendor-only IMS entry and preserve the remaining unsigned JAR."""

def actual_input():
    path = Path(os.environ.get('HYPEROS_AVD_IMS_FRAMEWORK_ARTIFACT', str(
        ROOT / 'work/feedback-investigation-20261013/vendor-ims-caller-audit/pad-xiaomi-opt-ims.jar')))
    if path.is_file():
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() == ims.BEFORE:
            return data
    return None

class XiaomiImsReceiptTests(unittest.TestCase):
    def test_one_vendor_only_void_entry_has_four_equal_length_sites(self):
        receipt = ims.recipe_receipt()
        self.assertEqual(ims.catalog_recipes(), (receipt,))
        self.assertEqual(receipt['path'], '/system_ext/framework/xiaomi-opt-ims.jar')
        self.assertEqual(receipt['methods'], ['Lcom/xiaomi/ims/internal/XmImsConnector;->connect()V'])
        self.assertEqual(receipt['format'], 'framework-jar')
        self.assertEqual(receipt['requires'], 'ranchu-without-proprietary-ims')
        self.assertEqual(len(receipt['sites']), 4)
        entry = next(site for site in receipt['sites'] if 'method' in site)
        self.assertEqual(entry, {'offset': ims.ENTRY[0], 'before': ims.ENTRY[1],
                                 'after': '0e000000', 'method': ims.METHOD})
        previous = 0
        for site in receipt['sites']:
            self.assertGreaterEqual(site['offset'], previous)
            self.assertEqual(len(site['before']), len(site['after']))
            self.assertNotEqual(site['before'], site['after'])
            previous = site['offset'] + len(bytes.fromhex(site['before']))
            self.assertLessEqual(previous, receipt['size'])
        receipt['sites'].clear()
        self.assertEqual(len(ims.recipe_receipt()['sites']), 4)

    def test_unknown_or_signed_content_never_creates_an_output(self):
        for data in (b'', b'PK\x03\x04', b'unknown signed APK'):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                ims.patch_bytes(data)
        with self.assertRaises(RuntimeError):
            ims.recipe_receipt(ims.AFTER)
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'unknown.jar', Path(directory) / 'absent/derivative.jar'
            source.write_bytes(b'unknown customized framework')
            with self.assertRaises(RuntimeError):
                ims.patch(source, output)
            self.assertFalse(output.parent.exists())
            self.assertEqual(source.read_bytes(), b'unknown customized framework')

class XiaomiImsAuditedInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = actual_input()
        if cls.original is None:
            raise unittest.SkipTest('Private audited IMS JAR unavailable; no download attempted.')

    def test_full_audit_idempotence_and_canonical_sites_agree(self):
        original = self.original
        self.assertFalse(ims.audit(original))
        output = ims.patch_bytes(original)
        self.assertTrue(ims.audit(output))
        self.assertEqual(hashlib.sha256(output).hexdigest(), ims.AFTER)
        self.assertEqual(ims.patch_bytes(output), output)
        self.assertEqual(ims.patch_bytes(original), output)
        self.assertEqual(ims.receipt(original), ims.recipe_receipt())
        with self.assertRaisesRegex(RuntimeError, 'original input'):
            ims.receipt(output)
        replay = bytearray(original)
        for site in ims.recipe_receipt()['sites']:
            offset = site['offset']
            before, after = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
            self.assertEqual(replay[offset:offset + len(before)], before)
            replay[offset:offset + len(after)] = after
        self.assertEqual(bytes(replay), output)

    def test_every_other_byte_zip_entry_and_method_instruction_is_preserved(self):
        original, output = self.original, ims.patch_bytes(self.original)
        cursor = 0
        for site in ims.recipe_receipt()['sites']:
            self.assertEqual(original[cursor:site['offset']], output[cursor:site['offset']])
            cursor = site['offset'] + len(bytes.fromhex(site['before']))
        self.assertEqual(original[cursor:], output[cursor:])
        self.assertEqual(len(original), len(output))
        with zipfile.ZipFile(io.BytesIO(original)) as a, zipfile.ZipFile(io.BytesIO(output)) as b:
            self.assertIsNone(b.testzip())
            self.assertEqual(a.namelist(), ['classes.dex', 'META-INF/MANIFEST.MF'])
            self.assertEqual(a.namelist(), b.namelist())
            self.assertEqual(a.read('META-INF/MANIFEST.MF'), b.read('META-INF/MANIFEST.MF'))
            first, changed = a.read('classes.dex'), b.read('classes.dex')
            self.assertEqual(ims._method(first), ims._method(changed))
            self.assertEqual(first[:8], changed[:8])
            self.assertEqual(first[32:ims.CODE_OFFSET + 16], changed[32:ims.CODE_OFFSET + 16])
            self.assertEqual(changed[ims.CODE_OFFSET + 16:ims.CODE_OFFSET + 20], bytes.fromhex('0e000000'))
            self.assertEqual(first[ims.CODE_OFFSET + 20:], changed[ims.CODE_OFFSET + 20:])
            self.assertEqual(changed[12:32], hashlib.sha1(changed[32:]).digest())
            self.assertEqual(struct.unpack_from('<I', changed, 8)[0], zlib.adler32(changed[12:]) & 0xffffffff)
            for x, y in zip(a.infolist(), b.infolist()):
                for attribute in ('filename', 'date_time', 'compress_type', 'flag_bits', 'extra',
                                  'comment', 'file_size', 'compress_size', 'external_attr',
                                  'header_offset', 'create_system', 'create_version'):
                    self.assertEqual(getattr(x, attribute), getattr(y, attribute))

    def test_tampered_code_tables_headers_and_signed_archives_are_rejected(self):
        for offset in (ims.ENTRY[0], ims.DEX_OFFSET + ims.CODE_OFFSET,
                       ims.DEX_OFFSET + 96, len(self.original) - 1):
            data = bytearray(self.original); data[offset] ^= 1
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                ims.patch_bytes(bytes(data))
        with zipfile.ZipFile(io.BytesIO(self.original)) as archive:
            signed = io.BytesIO()
            with zipfile.ZipFile(signed, 'w') as output:
                for name in archive.namelist():
                    output.writestr(name, archive.read(name))
                output.writestr('META-INF/CERT.SF', b'signed archive')
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            ims.patch_bytes(signed.getvalue())

    def test_existing_output_keeps_inodes_and_unknown_aliases_or_races_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output, other = [Path(directory) / name for name in ('original.jar', 'derived.jar', 'other')]
            source.write_bytes(self.original)
            ims.patch(source, output); identity = output.stat().st_ino, output.stat().st_mtime_ns
            ims.patch(source, output)
            self.assertEqual((output.stat().st_ino, output.stat().st_mtime_ns), identity)
            self.assertEqual(source.read_bytes(), self.original)
            with self.assertRaises(RuntimeError):
                ims.patch(source, source)
            output.write_bytes(b'custom derivative')
            with self.assertRaises(RuntimeError):
                ims.patch(source, output)
            self.assertEqual(output.read_bytes(), b'custom derivative')
            output.unlink(); other.write_bytes(ims.patch_bytes(self.original)); output.symlink_to(other)
            with self.assertRaises(RuntimeError):
                ims.patch(source, output)
            self.assertTrue(output.is_symlink())
            output.unlink(); os.link(other, output)
            with self.assertRaises(RuntimeError):
                ims.patch(source, output)
            self.assertEqual(output.stat().st_nlink, 2)
            output.unlink()

            def occupied(_source, destination):
                Path(destination).write_bytes(b'new user output')
                raise FileExistsError()

            with mock.patch.object(ims.os, 'link', side_effect=occupied), self.assertRaises(RuntimeError):
                ims.patch(source, output)
            self.assertEqual(output.read_bytes(), b'new user output')
            self.assertFalse(list(Path(directory).glob('.ims-connector-*')))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_xqos_patch.py ---

"""Audit the narrow physical XQos failure paths with optional donor ELFs."""

class XQosPatchTests(unittest.TestCase):
    def artifacts(self):
        paths = [Path(os.environ.get('HYPEROS_AVD_XQOS_' + name.upper(), str(
            REPO / 'work/feedback-investigation-20261013' / (name + '-libxqos.so'))))
                 for name in ('phone', 'pad')]
        if not all(path.is_file() for path in paths):
            self.skipTest('Audited proprietary XQos ELFs are not distributed in Git.')
        return [path.read_bytes() for path in paths]

    def test_both_real_derivatives_change_only_seven_local_initialize_calls(self):
        for data in self.artifacts():
            before, recipe, already = xqos.audit(data)
            with self.subTest(before=before):
                self.assertFalse(already)
                result = xqos.patch_bytes(data)
                self.assertEqual(hashlib.sha256(result).hexdigest(), recipe['after'])
                self.assertEqual(xqos.patch_bytes(result), result)
                self.assertTrue(xqos.audit(result)[2])
                self.assertEqual(len(result), len(data))
                positions = {f['site'] + index for f in recipe['functions'] for index in range(4)}
                self.assertEqual(len(positions), 28)
                changed = {index for index, (old, new) in enumerate(zip(data, result)) if old != new}
                self.assertEqual(len(changed), 26)
                self.assertLessEqual(changed, positions)
                for function in recipe['functions']:
                    site = function['site']
                    old, = struct.unpack_from('<I', data, site)
                    new, = struct.unpack_from('<I', result, site)
                    self.assertEqual(old >> 26, 0x25)  # BL local initialize.
                    self.assertEqual(new >> 26, 0x05)  # B existing failure tail.
                    self.assertEqual(xqos._branch_target(old, site), recipe['initialize'][0])
                    self.assertEqual(xqos._branch_target(new, site), function['target'])
                    start, end = function['address'], function['address'] + function['size']
                    self.assertEqual(data[start:site], result[start:site])
                    self.assertEqual(data[site + 4:end], result[site + 4:end])

    def test_original_failure_values_frames_canaries_and_pac_are_preserved(self):
        for data in self.artifacts():
            _, recipe, _ = xqos.audit(data)
            result = xqos.patch_bytes(data)
            for function in recipe['functions']:
                with self.subTest(symbol=function['symbol'], pac=recipe['pac']):
                    value = -1 if function['symbol'].startswith('get') else 0
                    self.assertEqual(function['return'], value)
                    target = function['target']
                    expected = bytes.fromhex('00008012' if value == -1 else 'e0031f2a')
                    self.assertEqual(result[target:target + 4], expected)
                    epilogue = bytes.fromhex(function['epilogue'])
                    self.assertEqual(result[target:target + len(epilogue)], epilogue)
                    self.assertTrue(epilogue.endswith(bytes.fromhex('c0035fd6')))
                    if recipe['pac']:
                        start = function['address']
                        self.assertEqual(result[start:start + 4], bytes.fromhex('3f2303d5'))
                        self.assertTrue(epilogue.endswith(bytes.fromhex('bf2303d5c0035fd6')))
                    else:
                        # All Pad failure tails keep their TLS stack-cookie check.
                        self.assertIn(bytes.fromhex('e90740f9'), epilogue)
                        self.assertIn(bytes.fromhex('1f0109eb'), epilogue)

    def test_all_elf_metadata_relocations_logs_and_initializer_are_unchanged(self):
        for data in self.artifacts():
            _, recipe, _ = xqos.audit(data)
            result = xqos.patch_bytes(data)
            _, sections = _sections(data)
            for name, section in sections.items():
                if name == b'.text' or section[1] == 8:
                    continue
                with self.subTest(section=name):
                    offset, size = section[4:6]
                    self.assertEqual(data[offset:offset + size], result[offset:offset + size])
            address, size, digest = recipe['initialize']
            self.assertEqual(hashlib.sha256(result[address:address + size]).hexdigest(), digest)
            self.assertIn(b'__android_log_print\0', result)
            self.assertIn(b'ioctl\0', result)
            for node in xqos.ABSENT_NODES:
                self.assertIn(node.encode() + b'\0', result)

    def test_offline_catalog_sites_reproduce_exact_derivatives(self):
        self.assertEqual(len(xqos.catalog_recipes()), 2)
        for data in self.artifacts():
            receipt = xqos.receipt(data)
            self.assertEqual(receipt, xqos.recipe_receipt(hashlib.sha256(data).hexdigest()))
            self.assertIn(receipt, xqos.catalog_recipes())
            self.assertEqual(receipt['path'], '/system/lib64/libxqos.so')
            self.assertEqual(receipt['requires'], xqos.REQUIRES)
            self.assertEqual(receipt['absent_nodes'], list(xqos.ABSENT_NODES))
            output = bytearray(data)
            for site in receipt['sites']:
                offset = site['offset']
                original, replacement = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
                self.assertEqual(len(original), 4)
                self.assertEqual(len(replacement), 4)
                self.assertEqual(output[offset:offset + 4], original)
                output[offset:offset + 4] = replacement
            self.assertEqual(hashlib.sha256(output).hexdigest(), receipt['after'])
            self.assertEqual(xqos.receipt(output), receipt)

    def test_unknown_tampered_or_partially_patched_files_are_refused(self):
        for data in self.artifacts():
            _, recipe, _ = xqos.audit(data)
            for position in (4, 40, recipe['functions'][0]['site'], len(data) - 1):
                modified = bytearray(data)
                modified[position] ^= 1
                with self.subTest(position=position), self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                    xqos.patch_bytes(modified)
            function = recipe['functions'][0]
            partial = bytearray(data)
            partial[function['site']:function['site'] + 4] = xqos._replacement(function)
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                xqos.patch_bytes(partial)
        with self.assertRaises(RuntimeError):
            xqos.patch_bytes(b'not an ELF')
        with self.assertRaises(RuntimeError):
            xqos.recipe_receipt('0' * 64)

    def test_explicit_structure_guards_reject_wrong_functions_failure_paths_and_pac(self):
        for data in self.artifacts():
            selected = xqos.select_recipe(data)
            _, recipe, _ = selected
            function = recipe['functions'][0]
            positions = (40, function['address'], function['site'] + 4,
                         function['target'], recipe['initialize'][0])
            for position in positions:
                modified = bytearray(data)
                modified[position] ^= 1
                # Bypass only the whole-file pin to exercise deeper guards.
                with self.subTest(position=position), patch.object(xqos, 'select_recipe', return_value=selected):
                    with self.assertRaises(RuntimeError):
                        xqos.audit(modified)

    def test_atomic_publication_is_separate_idempotent_and_preserves_unknowns(self):
        data = self.artifacts()[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'factory.so', root / 'derivative.so'
            source.write_bytes(data)
            xqos.patch(source, output)
            info = output.stat()
            self.assertEqual(info.st_mode & 0o777, 0o644)
            self.assertEqual(info.st_nlink, 1)
            xqos.patch(source, output)
            self.assertEqual(output.stat().st_ino, info.st_ino)
            self.assertEqual(source.read_bytes(), data)
            with self.assertRaises(RuntimeError):
                xqos.patch(source, source)
            alias = root / 'source-alias.so'
            alias.symlink_to(source)
            with self.assertRaises(RuntimeError):
                xqos.patch(source, alias)
            output.write_bytes(b'custom output')
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                xqos.patch(source, output)
            self.assertEqual(output.read_bytes(), b'custom output')
            self.assertFalse(list(root.glob('.xqos-*')))

    def test_racing_unknown_output_is_not_replaced(self):
        data = self.artifacts()[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'factory.so', root / 'result.so'
            source.write_bytes(data)

            def race(*_):
                output.write_bytes(b'user content')
                raise FileExistsError()

            with patch.object(xqos.os, 'link', side_effect=race), self.assertRaisesRegex(RuntimeError, 'unknown'):
                xqos.patch(source, output)
            self.assertEqual(output.read_bytes(), b'user content')
            self.assertFalse(list(root.glob('.xqos-*')))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_tcm_capability.py ---

"""Verify the narrow OEM TCM opt-out without changing any real property."""

class TcmCapabilityAssetsTests(unittest.TestCase):
    def test_offline_recipe_is_exact_and_packaged_with_feature(self):
        files = tcm_producer.files()
        self.assertEqual(set(files), {'tcm-capability.tsv'})
        self.assertEqual(files['tcm-capability.tsv'].decode().splitlines(), [
            'schema|1', *('file|' + path + '|' + checksum for path, checksum in tcm_producer.PINS),
            'property|' + tcm_producer.PROPERTY + '|1', 'policy|unset-current-boot-only'])
        packaged = package_native_module.module_files()
        self.assertEqual(packaged['tcm-capability.tsv'], files['tcm-capability.tsv'])
        self.assertEqual(packaged['tcm-capability.sh'], (REPO / 'modules/native-compat/tcm-capability.sh').read_bytes())
        self.assertIn(b'network-tcm\n', packaged['features.tsv'])
        self.assertIn('network-tcm', json.loads(packaged['manifest.json'])['features'])

    def test_hook_is_early_only_and_never_persists_or_restarts(self):
        source = (REPO / 'modules/native-compat/platform.sh').read_text()
        early = source.split('core_early() {', 1)[1].split('\n}', 1)[0]
        late = source.split('core_late() {', 1)[1].split('\n}', 1)[0]
        self.assertIn('core_network_tcm', early)
        self.assertNotIn('core_network_tcm', late)
        script = (REPO / 'modules/native-compat/tcm-capability.sh').read_text()
        self.assertIn('"$CORE_RESETPROP" -n persist.vendor.dpm.tcm 1', script)
        self.assertNotIn('setprop ', script)
        self.assertNotIn('--persistent', script)
        self.assertNotIn('ctl.', script)

class TcmCapabilityShellTests(unittest.TestCase):
    profile = fixture.NativeModuleRuntimeTests.profile
    file_metadata = fixture.NativeModuleRuntimeTests.file_metadata

    def setUp(self):
        fixture.NativeModuleRuntimeTests.setUp(self)
        self.state = self.root / 'persistent'
        self.state.mkdir()
        self.pinned = {}
        body = tcm_producer.files()['tcm-capability.tsv'].decode()
        for path, checksum in tcm_producer.PINS:
            target = self.root.resolve() / path.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(('Audited TCM content fixture: ' + path).encode())
            self.pinned[path] = target
            body = body.replace(path, str(target)).replace(checksum, hashlib.sha256(target.read_bytes()).hexdigest())
        self.client = self.pinned[tcm_producer.CLIENT_PATH]
        (self.module / 'tcm-capability.tsv').write_text(body)
        script = (self.module / 'tcm-capability.sh').read_text()
        script = re.sub(r'/(system_ext|system|vendor)(?=/)',
                        lambda match: str(self.root.resolve() / match[1]), script)
        (self.module / 'tcm-capability.sh').write_text(script)
        self.props = self.root / 'properties.json'
        self.base = {'ro.boot.hardware': 'ranchu', 'ro.mi.os.version.incremental': 'OS4.99.TEST',
                     'sys.boot_completed': '0', 'ro.kernel.qemu': '1', 'ro.boot.qemu': '1'}
        self.props.write_text(json.dumps(self.base))
        self.trace = self.root / 'effects'
        (self.bin / 'getprop').write_text('#!' + sys.executable + '\n' + '''import json,os,sys
state=json.load(open(os.environ['TCM_TEST_PROPERTIES']))
if len(sys.argv)==1:
    for key,value in sorted(state.items()): print('['+key+']: ['+value+']')
else: print(state.get(sys.argv[1],''))
''')
        resetprop = self.bin / 'resetprop'
        resetprop.write_text('#!' + sys.executable + '\n' + '''import json,os,sys
args=sys.argv[1:]
with open(os.environ['TCM_TEST_TRACE'],'a') as output: output.write(' '.join(args)+'\\n')
if args != ['-n','persist.vendor.dpm.tcm','1']: sys.exit(1)
path=os.environ['TCM_TEST_PROPERTIES']
state=json.load(open(path));state[args[1]]=args[2]
with open(path,'w') as output: json.dump(state,output)
''')
        resetprop.chmod(0o755)
        self.environment.update(HYPEROS_CORE_STATE=str(self.state), HYPEROS_CORE_PENDING=str(self.root / 'pending'),
            HYPEROS_CORE_RESETPROP=str(resetprop), HYPEROS_NATIVE_TEST_OWNER='0:0',
            TCM_TEST_PROPERTIES=str(self.props), TCM_TEST_TRACE=str(self.trace), TCM_TEST_VENDOR='1')
        fixture.NativeModuleRuntimeTests.checksums(self)

    def run_tcm(self, overrides='', body='core_network_tcm', interpreter='/bin/sh'):
        source = ("MODDIR=" + shlex.quote(str(self.module)) + '\n. "$MODDIR/runtime.sh"\n'
                  '. "$MODDIR/platform.sh"\n'
                  'native_privacy_eligible() { [ "$TCM_TEST_VENDOR" = 1 ]; }\n'
                  'native_assets() { (cd "$MODDIR" && "$BB" sha256sum -c SHA256SUMS >/dev/null); }\n'
                  'native_ns() { shift; "$@"; }\n' + overrides + '\n' + body)
        if interpreter == '/bin/ksh':
            source = 'alias local=typeset\n' + source
        result = subprocess.run([interpreter, '-c', source], env=self.environment,
                                text=True, capture_output=True)
        effects = self.trace.read_text() if self.trace.exists() else ''
        return result, effects

    def status(self):
        path = self.module / 'state/status.tsv'
        return path.read_text() if path.exists() else ''

    def set_properties(self, **updates):
        self.props.write_text(json.dumps(dict(self.base, **updates)))

    def test_verified_unset_boot_property_uses_only_the_oem_nonpersistent_switch(self):
        result, effects = self.run_tcm()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(effects, '-n persist.vendor.dpm.tcm 1\n')
        self.assertIn('ready|verified-oem-runtime-opt-out', self.status())

    def test_all_existing_values_including_empty_are_preserved(self):
        for value in ('', '0', '1', '2', 'custom'):
            with self.subTest(value=value):
                self.set_properties(**{tcm_producer.PROPERTY: value})
                result, effects = self.run_tcm()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(effects, '')
                self.assertEqual(json.loads(self.props.read_text())[tcm_producer.PROPERTY], value)
                self.assertIn('property-present-or-inventory-unavailable', self.status())

    def test_reconcile_after_boot_or_zygote_start_never_changes_properties(self):
        self.set_properties(sys_boot_completed='0')
        state = dict(self.base); state['sys.boot_completed'] = '1'; self.props.write_text(json.dumps(state))
        self.assertEqual(self.run_tcm()[1], '')
        self.props.write_text(json.dumps(self.base))
        self.assertEqual(self.run_tcm('pidof() { echo 88; }')[1], '')

    def test_nonranchu_or_unverified_complete_inventory_has_no_effect(self):
        self.environment['TCM_TEST_VENDOR'] = '0'
        self.assertEqual(self.run_tcm()[1], '')
        self.assertIn('unaudited-ranchu-vendor', self.status())
        self.environment['TCM_TEST_VENDOR'] = '1'
        state = dict(self.base); state['ro.boot.hardware'] = 'physical'; self.props.write_text(json.dumps(state))
        self.assertEqual(self.run_tcm()[1], '')

    def test_feature_disable_module_disable_remove_and_pending_are_preserved(self):
        for flag in ('features.disabled', 'disable', 'remove'):
            with self.subTest(flag=flag):
                path = self.module / flag
                path.write_text('network-tcm\n' if flag == 'features.disabled' else '')
                self.assertEqual(self.run_tcm()[1], '')
                path.unlink()
        (self.root / 'pending').mkdir()
        self.assertEqual(self.run_tcm()[1], '')

    def test_absent_unknown_aliased_or_nonroot_client_is_retained(self):
        original = self.client.read_bytes()
        self.client.write_bytes(b'Customized client')
        self.assertEqual(self.run_tcm()[1], '')
        self.assertIn('unsupported-tcm-content', self.status())
        self.client.unlink()
        self.assertEqual(self.run_tcm()[1], '')
        donor = self.client.with_name('donor.jar'); donor.write_bytes(original)
        self.client.symlink_to(donor)
        self.assertEqual(self.run_tcm()[1], '')
        self.client.unlink(); self.client.write_bytes(original)
        self.file_metadata(self.client, owner='1000:1000')
        self.assertEqual(self.run_tcm()[1], '')

    def test_each_server_and_policy_file_is_required_exactly(self):
        for original, path in self.pinned.items():
            with self.subTest(path=original):
                body = path.read_bytes()
                path.write_bytes(body + b'custom')
                self.assertEqual(self.run_tcm()[1], '')
                path.write_bytes(body)

    def test_extra_tampered_or_arbitrary_property_recipe_never_writes(self):
        recipe = self.module / 'tcm-capability.tsv'
        original = recipe.read_text()
        for changed in (original + 'extra|data\n', original.replace('|1\npolicy|', '|2\npolicy|'),
                        original.replace(tcm_producer.PROPERTY, 'persist.unsafe.property')):
            with self.subTest(changed=changed):
                recipe.write_text(changed)
                fixture.NativeModuleRuntimeTests.checksums(self)
                self.assertEqual(self.run_tcm()[1], '')
        recipe.write_text(original + 'unverified')
        self.assertEqual(self.run_tcm()[1], '')

    def test_property_inventory_failure_is_not_absence(self):
        result, effects = self.run_tcm('getprop() { return 1; }')
        self.assertEqual(effects, '')

    def test_empty_or_incomplete_successful_inventory_is_not_absence(self):
        for output in ('', '[ro.boot.hardware]: [ranchu]'):
            with self.subTest(output=output):
                command = 'getprop() { if [ "$#" = 0 ]; then printf "%s\\n" ' + shlex.quote(output) + '; else command getprop "$@"; fi; }'
                self.assertEqual(self.run_tcm(command)[1], '')

    def test_property_choice_during_revalidation_is_preserved(self):
        overrides = '''checks=0
core_tcm_file_matches() {
    checks=$((checks + 1))
    if [ "$checks" = 2 ]; then
        printf '%s' '{"persist.vendor.dpm.tcm":"2"}' > "$TCM_TEST_PROPERTIES"
    fi
    return 0
}'''
        self.assertEqual(self.run_tcm(overrides)[1], '')
        self.assertEqual(json.loads(self.props.read_text())[tcm_producer.PROPERTY], '2')

    @unittest.skipUnless(Path('/bin/ksh').is_file(), 'Korn shell is unavailable')
    def test_korn_shell_reads_same_audited_recipe(self):
        result, _ = self.run_tcm(body='core_tcm_recipe', interpreter='/bin/ksh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip().splitlines(), [str(path) + '|' + hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.pinned.values()])
