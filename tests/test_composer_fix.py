"""Consolidated unit tests for Ranchu graphics HAL: hwcomposer and goldfish sync IRQ patches."""
from collections import deque
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

from patch_composer import AFTER, MANIFEST, NATIVE, patch
import patch_goldfish_sync as patcher



# --- tests/test_composer_fix.py ---

'Guard the physical display alpha fix against unrelated vendor updates.'

SOURCE = REPO / 'work/os4-official/work/activity-dim/android.hardware.graphics.composer3-service.ranchu'

class ComposerGuardTest(unittest.TestCase):

    def test_unknown_vendor_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Unsupported ranchu composer'):
            patch(b'unknown vendor update')

    @unittest.skipUnless(SOURCE.is_file(), 'Verified vendor ELF is not bundled')
    def test_pinned_elf_has_only_one_byte_changed(self):
        original = SOURCE.read_bytes()
        result = patch(original)
        self.assertEqual(hashlib.sha256(result).hexdigest(), AFTER)
        self.assertEqual(len(result), len(original))
        self.assertEqual([i for i, (a, b) in enumerate(zip(original, result)) if a != b], [237946])
        self.assertEqual(patch(result), result)
        tampered = bytearray(original)
        tampered[-1] ^= 1
        with self.assertRaisesRegex(RuntimeError, 'Unsupported ranchu composer'):
            patch(tampered)
        self.assertEqual((MANIFEST['native'], MANIFEST['native_sha256']), (NATIVE, AFTER))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_goldfish_sync.py ---

'Verify the pinned ELF transformation and execute its IRQ instructions.'

SOURCE = REPO / 'work/os4-r3-build/work/vendor-alpha-tree/extract-system-71c777c3f8ac437b/lib/modules/goldfish_sync.ko'

COMPILERS = sorted((Path.home() / 'Library/Android/sdk/ndk').glob('*/toolchains/llvm/prebuilt/darwin-*/bin/aarch64-linux-android36-clang'))

def sections(data):
    """Independent ELF section reader, also used for assembler output."""
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, names_index = struct.unpack_from('<HHH', data, 58)
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * size) for i in range(count)]
    names = headers[names_index]
    strings = data[names[4]:names[4] + names[5]]
    return {strings[h[0]:strings.index(b'\x00', h[0])].decode(): h for h in headers}

def relocations(data):
    section = sections(data)['.rela.text']
    return [struct.unpack_from('<QQq', data, p) for p in range(section[4], section[4] + section[5], section[9])]

def signed(value, bits):
    return value - (1 << bits) if value & 1 << bits - 1 else value

class IRQMachine:
    """Small ARM64 executor for the actual replacement instruction stream.

    Kernel helpers are modeled at the ELF relocation/local-call targets.
    Worker semantics follow the unchanged module: copy at most 32 entries,
    reset the count under its spinlock, then execute each copied command.
    This is machine-code/queue proof, not guest or host transport acceptance.
    """
    STATE = 1048576
    STACK = 2097152
    FOPS = 4194864
    MMIO = 5242960

    def __init__(self, module, commands=(), prefilled=(), ready=True, during_worker=None, after_empty=None):
        self.code = module[4096:8752]
        self.relocs = {r[0]: r[1:] for r in relocations(module)}
        self.heap = bytearray(1032)
        self.stack = {}
        self.pending = deque(commands)
        self.consumed = []
        self.processed = []
        self.batch_sizes = []
        self.max_count = 0
        self.reads = 0
        self.held = False
        self.during_worker = during_worker
        self.after_empty = after_empty
        self.store(self.STATE + 16, self.FOPS if ready else 0, 8)
        self.store(self.STATE + 80, self.MMIO, 8)
        for i, cmd in enumerate(prefilled):
            self.heap[152 + i * 24:152 + (i + 1) * 24] = struct.pack('<QQII', *cmd)
        self.store(self.STATE + 920, len(prefilled), 4)

    def load(self, address, width):
        if self.STATE <= address < self.STATE + len(self.heap):
            offset = address - self.STATE
            assert offset + width <= len(self.heap), 'Heap read exceeds state'
            return int.from_bytes(self.heap[offset:offset + width], 'little')
        return int.from_bytes(bytes((self.stack.get(address + i, 0) for i in range(width))), 'little')

    def store(self, address, value, width):
        data = (value & (1 << width * 8) - 1).to_bytes(width, 'little')
        if self.STATE <= address < self.STATE + len(self.heap):
            offset = address - self.STATE
            assert offset + width <= len(self.heap), 'Heap write exceeds state'
            self.heap[offset:offset + width] = data
            if offset == 920:
                assert value <= 32, 'Queue count exceeds its 32-entry capacity'
                self.max_count = max(self.max_count, value)
        else:
            for i, byte in enumerate(data):
                self.stack[address + i] = byte

    def helper(self, pc, target):
        info, _ = self.relocs.get(pc, (0, 0))
        symbol = info >> 32
        if symbol == 201:
            assert self.reg[0] == self.STATE + 924
            assert not self.held
            self.held = True
        elif symbol == 202:
            assert self.reg[0] == self.STATE + 924
            assert self.held
            self.held = False
        elif target == 4508:
            assert self.held and self.reg[0] == self.MMIO
            assert self.load(self.STATE + 920, 4) < 32, 'Consumed MMIO with a full queue'
            self.reads += 1
            if self.pending:
                cmd = self.pending.popleft()
                self.consumed.append(cmd)
                self.heap[928:952] = struct.pack('<QQII', *cmd)
            else:
                self.store(self.STATE + 944, 0, 4)
                if self.after_empty:
                    callback, self.after_empty = (self.after_empty, None)
                    callback(self)
        elif target == 2860:
            assert not self.held, 'Worker called while holding the producer spinlock'
            assert self.reg[0] == self.STATE + 984
            count = self.load(self.STATE + 920, 4)
            assert count <= 32
            batch = [struct.unpack_from('<QQII', self.heap, 152 + i * 24) for i in range(count)]
            self.store(self.STATE + 920, 0, 4)
            self.batch_sizes.append(count)
            if self.during_worker:
                callback, self.during_worker = (self.during_worker, None)
                callback(self)
            self.processed.extend(batch)
        else:
            raise AssertionError(f'Unexpected helper at {pc:x}, target {target:x}, symbol {symbol}')
        for i in range(19):
            self.reg[i] = 3134193664 + i

    def run(self):
        self.reg = [2881486848 + i for i in range(31)]
        self.reg[0], self.reg[1] = (21, self.STATE)
        saved = self.reg[:]
        self.sp = self.STACK
        self.pc = 3188
        self.eq = self.hs = False

        def get(index, stack=False):
            return self.sp if index == 31 and stack else 0 if index == 31 else self.reg[index]

        def put(index, value, width=64, stack=False):
            value &= (1 << width) - 1
            if index == 31 and stack:
                self.sp = value
            elif index != 31:
                self.reg[index] = value
        for _ in range(2000000):
            pc = self.pc
            word = struct.unpack_from('<I', self.code, pc)[0]
            self.pc += 4
            rd, rn, rm = (word & 31, word >> 5 & 31, word >> 16 & 31)
            width = 64 if word >> 31 else 32
            if word in (3573752639, 3573752767, 3573751839):
                continue
            if word == 3596551104:
                assert not self.held and self.sp == self.STACK
                for index in (19, 20, 21, 29, 30):
                    assert self.reg[index] == saved[index], f'Callee-saved x{index} changed'
                return self.reg[0]
            if word & 973078528 == 671088640:
                unit = 8 if word >> 31 else 4
                delta = signed(word >> 15 & 127, 7) * unit
                mode = word >> 23 & 3
                base = get(rn, stack=True)
                address = base + delta if mode in (2, 3) else base
                if mode == 3:
                    put(rn, address, stack=True)
                rt2 = word >> 10 & 31
                if word & 1 << 22:
                    put(rd, self.load(address, unit), unit * 8)
                    put(rt2, self.load(address + unit, unit), unit * 8)
                else:
                    if rn == 12:
                        assert self.STATE + 152 <= address
                        assert address + 2 * unit <= self.STATE + 920, 'Queue write exceeds entry 31'
                    self.store(address, get(rd), unit)
                    self.store(address + unit, get(rt2), unit)
                if mode == 1:
                    put(rn, base + delta, stack=True)
            elif word & 989855744 == 956301312:
                unit = 1 << (word >> 30)
                address = get(rn, stack=True) + (word >> 10 & 4095) * unit
                if word & 1 << 22:
                    put(rd, self.load(address, unit), unit * 8)
                else:
                    self.store(address, get(rd), unit)
            elif word & 2667577344 == 2415919104:
                assert self.relocs[pc] == (532575944979, 560)
                put(rd, self.FOPS & ~4095)
            elif word & 2130706432 == 285212672:
                value = get(rn, stack=True) + ((word >> 10 & 4095) << (12 if word & 1 << 22 else 0))
                if pc in self.relocs:
                    assert self.relocs[pc] == (532575944981, 560)
                    value += self.FOPS & 4095
                put(rd, value, width, stack=True)
            elif word & 2130706432 == 1895825408:
                value = get(rn) & (1 << width) - 1
                immediate = word >> 10 & 4095
                self.eq, self.hs = (value == immediate, value >= immediate)
            elif word & 4280287263 == 3942645791:
                self.eq, self.hs = (get(rn) == get(rm), get(rn) >= get(rm))
            elif word & 4292935648 in (2852127712, 704644064):
                put(rd, get(rm), width)
            elif word & 2139095040 == 1384120320:
                put(rd, (word >> 5 & 65535) << (word >> 21 & 3) * 16, width)
            elif word & 4292902912 == 2610954240:
                put(rd, (get(rn) & 4294967295) * (get(rm) & 4294967295) + get(word >> 10 & 31))
            elif word & 4227858432 == 2483027968:
                self.helper(pc, pc + signed(word & 67108863, 26) * 4)
            elif word & 4227858432 == 335544320:
                self.pc = pc + signed(word & 67108863, 26) * 4
            elif word & 4278190096 == 1409286144:
                condition = {0: self.eq, 1: not self.eq, 2: self.hs, 3: not self.hs}[word & 15]
                if condition:
                    self.pc = pc + signed(word >> 5 & 524287, 19) * 4
            elif word & 2113929216 == 872415232:
                nonzero = bool(get(rd) & (1 << width) - 1)
                if nonzero == bool(word & 1 << 24):
                    self.pc = pc + signed(word >> 5 & 524287, 19) * 4
            else:
                raise AssertionError(f'Unmodeled instruction {word:08x} at {pc:x}')
        raise AssertionError('IRQ handler failed to reach a return')

def commands(count, start=0):
    return [(4294967296 + i, 8589934592 + i, i % 4 + 1, i * 17) for i in range(start, start + count)]

class GoldfishSyncGuardTest(unittest.TestCase):

    def test_unknown_module_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Unsupported goldfish sync SHA-256'):
            patcher.patch(b'unknown kernel module')

    @unittest.skipUnless(SOURCE.is_file(), 'Pinned vendor module is not bundled')
    def test_pinned_hash_idempotence_and_only_allowed_changes(self):
        original = SOURCE.read_bytes()
        result = patcher.patch(original)
        self.assertEqual(hashlib.sha256(original).hexdigest(), patcher.BEFORE)
        self.assertEqual(hashlib.sha256(result).hexdigest(), patcher.AFTER)
        self.assertEqual(patcher.patch(result), result)
        self.assertEqual(len(result), len(original))
        allowed = set(range(7284, 7516)) | set(range(6476, 6496))
        for index in range(107, 112):
            allowed.update(range(15368 + index * 24, 15368 + (index + 1) * 24))
        changed = {i for i, (a, b) in enumerate(zip(original, result)) if a != b}
        self.assertTrue(changed <= allowed)
        for name, section in sections(original).items():
            if name not in ('.text', '.rela.text') and section[1] != 8:
                start, size = section[4:6]
                self.assertEqual(result[start:start + size], original[start:start + size], name)
        self.assertEqual(result[6956:7284], original[6956:7284])
        self.assertEqual(result[7496:7520], original[7496:7520])
        self.assertEqual(result[7284:7304], original[7284:7304])

    @unittest.skipUnless(SOURCE.is_file(), 'Pinned vendor module is not bundled')
    def test_tampered_and_signed_modules_are_rejected(self):
        data = bytearray(SOURCE.read_bytes())
        data[7284] ^= 1
        with self.assertRaisesRegex(RuntimeError, 'Unsupported goldfish sync SHA-256'):
            patcher.patch(data)
        with self.assertRaisesRegex(RuntimeError, 'Signed goldfish sync modules'):
            patcher.patch(SOURCE.read_bytes() + patcher.SIGNATURE_MAGIC)

    @unittest.skipUnless(SOURCE.is_file(), 'Pinned vendor module is not bundled')
    def test_instructions_and_relocations_match_threaded_irq_contract(self):
        original = SOURCE.read_bytes()
        result = patcher.patch(original)
        old, new = (relocations(original), relocations(result))
        self.assertEqual(new[:107], old[:107])
        self.assertEqual(new[112:], old[112:])
        self.assertEqual(new[107:112], [(3240, 863288426779, 0), (3332, 867583394075, 0), (3376, 256, 0), (3388, 256, 0), (3392, 256, 0)])
        probe = struct.unpack_from('<IIIII', result, 6476)
        self.assertEqual(probe[0] & 31, 3)
        self.assertEqual((probe[1] & 31, probe[1] >> 5 & 31), (3, 3))
        self.assertEqual(probe[3], 2854159330)
        self.assertEqual((probe[4] & 31, probe[4] >> 5 & 65535), (4, 8320))
        for pc, target in ((3264, 4508), (3340, 2860)):
            word = struct.unpack_from('<I', result, 4096 + pc)[0]
            self.assertEqual(word & 4227858432, 2483027968)
            self.assertEqual(pc + signed(word & 67108863, 26) * 4, target)
        words = struct.unpack_from('<58I', result, 7284)
        self.assertFalse(any((w & 4292870175 == 3558866944 for w in words)))
        self.assertEqual(result[7452:7492], struct.pack('<I', 3573751839) * 10)

    @unittest.skipUnless(COMPILERS, 'Android AArch64 assembler is not installed')
    def test_embedded_assembly_reproduces_handler_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            source, output = (Path(temp) / 'handler.S', Path(temp) / 'handler.o')
            source.write_text(patcher.ASSEMBLY)
            subprocess.run([str(COMPILERS[-1]), '-c', str(source), '-o', str(output)], check=True, capture_output=True)
            obj = output.read_bytes()
            section = sections(obj)['.text']
            self.assertEqual(obj[section[4] + 3188:section[4] + 3420], patcher.CODE)

    @unittest.skipUnless(SOURCE.is_file(), 'Pinned vendor module is not bundled')
    def test_actual_handler_instructions_preserve_every_burst_command(self):
        result = patcher.patch(SOURCE.read_bytes())
        for count in (0, 1, 31, 32, 33, 63, 64, 65, 4097):
            with self.subTest(count=count):
                batch = commands(count)
                machine = IRQMachine(result, batch)
                self.assertEqual(machine.run(), 1)
                self.assertEqual(machine.consumed, batch)
                self.assertEqual(machine.processed, batch)
                self.assertEqual(machine.reads, count + 1)
                self.assertEqual(machine.max_count, min(count, 32))
                self.assertTrue(all((size <= 32 for size in machine.batch_sizes)))
                self.assertEqual(machine.load(machine.STATE + 920, 4), 0)

    @unittest.skipUnless(SOURCE.is_file(), 'Pinned vendor module is not bundled')
    def test_executor_detects_a_removed_capacity_check(self):
        result = bytearray(patcher.patch(SOURCE.read_bytes()))
        struct.pack_into('<I', result, 7352, 3573751839)
        with self.assertRaisesRegex(AssertionError, 'Consumed MMIO with a full queue'):
            IRQMachine(result, commands(33)).run()

    @unittest.skipUnless(SOURCE.is_file(), 'Pinned vendor module is not bundled')
    def test_full_queue_is_processed_before_consuming_more_mmio(self):
        result = patcher.patch(SOURCE.read_bytes())
        initial, incoming = (commands(32), commands(67, 32))
        machine = IRQMachine(result, incoming, prefilled=initial)
        self.assertEqual(machine.run(), 1)
        self.assertEqual(machine.processed, initial + incoming)
        self.assertEqual(machine.batch_sizes[0], 32)

    @unittest.skipUnless(SOURCE.is_file(), 'Pinned vendor module is not bundled')
    def test_commands_arriving_during_worker_and_after_empty_are_retained(self):
        result = patcher.patch(SOURCE.read_bytes())
        first, during, later = (commands(33), commands(61, 33), commands(35, 94))
        machine = IRQMachine(result, first, during_worker=lambda m: m.pending.extend(during), after_empty=lambda m: m.pending.extend(later))
        self.assertEqual(machine.run(), 1)
        self.assertEqual(machine.processed, first + during)
        self.assertEqual(list(machine.pending), later)
        self.assertEqual(machine.run(), 1)
        self.assertEqual(machine.processed, first + during + later)

    @unittest.skipUnless(SOURCE.is_file(), 'Pinned vendor module is not bundled')
    def test_not_ready_guard_returns_none_without_consuming_commands(self):
        machine = IRQMachine(patcher.patch(SOURCE.read_bytes()), commands(33), ready=False)
        self.assertEqual(machine.run(), 0)
        self.assertEqual(machine.reads, 0)
        self.assertEqual(machine.processed, [])

if __name__ == '__main__':
    unittest.main()
