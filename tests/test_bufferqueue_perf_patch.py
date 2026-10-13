"""Verify the physical hint return without changing BufferQueue behavior."""
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
import patch_bufferqueue_perf as perf
import patch_xqos
from patch_rear_display import _sections


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
