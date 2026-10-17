"""Discover the ARM64 emulator's independent-window rotation capabilities.

The recipe is derived from Mach-O symbols and instruction relationships, never
from an SDK version, UUID, or a pinned file offset. Unsupported layouts fail
closed. This module only reads the executable; it does not patch SDK files.
"""

import hashlib
from pathlib import Path
import struct


SCHEMA = 1
FUNCTIONS = {
    'combined': '_ZN7android12MultiDisplay22getCombinedDisplaySizeEPjS1_',
    'pose': '_ZN7android12MultiDisplay14getDisplayPoseEjPiS1_PjS2_',
    'separate_windows': '_ZN7android12MultiDisplay20isMultiDisplayWindowEv',
    'next_display': '_ZN7android12MultiDisplay19getNextMultiDisplayEiPjPiS2_S1_S1_S1_S1_S1_',
    'display_info': '_ZN7android12MultiDisplay15getMultiDisplayEjPiS1_PjS2_S2_S2_S2_Pb',
    'perform_rotation': '_ZN7android12MultiDisplay15performRotationEi',
    'instance': '_ZN7android12MultiDisplay11getInstanceEv',
    'rotate': '_ZN16EmulatorQtWindow10rotateSkinE12SkinRotation',
    'resize': '_ZN16EmulatorQtWindow26resizeAndChangeAspectRatioEiiiib',
    'event': 'skin_event_add',
    'create_event': 'createSkinEvent',
    'add_window': '_ZN16EmulatorQtWindow21addMultiDisplayWindowEjbjj',
    'queue_event': '_ZN16EmulatorQtWindow14queueSkinEventE9SkinEvent',
}
AGENT_GLOBAL = 'gQAndroidMultiDisplayAgent'
UI_AGENT_GLOBAL = '_ZN10ToolWindow11sUiEmuAgentE'
AGENT_SIGNATURES = {
    'combined': '8__invokeEPjS0_',
    'pose': '8__invokeEjPiS0_PjS1_',
    'separate_windows': '8__invokeEv',
    'next_display': '8__invokeEiPjPiS1_S0_S0_S0_S0_S0_',
    'display_info': '8__invokeEjPiS0_PjS1_S1_S1_Pb',
    'perform_rotation': '8__invokeEi',
}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _branch(word, pc):
    if word & 0x7C000000 == 0x14000000:
        return pc + _signed(word & 0x03FFFFFF, 26) * 4
    return None


def _is_bl(word):
    return word & 0xFC000000 == 0x94000000


def _mov(word):
    if word & 0xFFE0FFE0 in (0xAA0003E0, 0x2A0003E0):
        return word & 31, (word >> 16) & 31
    return None


def _immediate(word):
    if word & 0x7F800000 == 0x52800000:
        return word & 31, ((word >> 5) & 65535) << (((word >> 21) & 3) * 16)
    return None


def _memory(word):
    """Return (load, width, register, base, offset) for scalar immediate I/O."""
    kind = word & 0xFFC00000
    if kind in (0xF9400000, 0xF9000000, 0xB9400000, 0xB9000000):
        width = 8 if kind & 0x40000000 else 4
        return bool(kind & 0x00400000), width, word & 31, (word >> 5) & 31, ((word >> 10) & 4095) * width
    kind = word & 0xFFE00C00
    if kind in (0xF8400000, 0xF8000000, 0xB8400000, 0xB8000000):
        width = 8 if kind & 0x40000000 else 4
        return bool(kind & 0x00400000), width, word & 31, (word >> 5) & 31, _signed((word >> 12) & 511, 9)
    return None


def _pair(word):
    """Decode ordinary 32/64-bit GPR pairs, including frame pre/post indexing."""
    if word & 0x3E000000 != 0x28000000 or word & 0x04000000:
        return None
    size = (word >> 30) & 3
    if size not in (0, 2):
        return None
    width = 8 if size == 2 else 4
    mode = (word >> 23) & 3
    if mode == 0:
        return None
    return bool(word & 0x00400000), width, word & 31, (word >> 10) & 31, (word >> 5) & 31, _signed((word >> 15) & 127, 7) * width, mode


class _Image:
    def __init__(self, data):
        self.data = data
        _require(len(data) >= 32, 'Truncated Mach-O header')
        magic, cpu, _, filetype, commands, length, _, _ = struct.unpack_from('<8I', data)
        _require(magic == 0xFEEDFACF and cpu == 0x0100000C and filetype == 2,
                 'Expected an ARM64 Mach-O executable')
        _require(0 < commands <= 512 and 32 + length <= len(data), 'Invalid Mach-O command bounds')
        self.segments, self.sections, self.symbols = [], [None], []
        symtab = None
        cursor, end = 32, 32 + length
        for _ in range(commands):
            _require(cursor + 8 <= end, 'Truncated load command')
            command, size = struct.unpack_from('<II', data, cursor)
            _require(size >= 8 and size % 8 == 0 and cursor + size <= end, 'Invalid load command')
            if command == 0x80000034:
                raise ValueError('Chained fixups are not supported by this capability reader')
            if command == 0x19:
                _require(size >= 72, 'Truncated segment command')
                _, _, name, address, vm_size, offset, file_size, _, protection, count, _ = struct.unpack_from('<II16sQQQQiiII', data, cursor)
                _require(size == 72 + 80 * count and offset + file_size <= len(data)
                         and file_size <= vm_size, 'Invalid segment bounds')
                segment = dict(name=name.rstrip(b'\0'), address=address, size=vm_size,
                               offset=offset, file_size=file_size, protection=protection)
                self.segments.append(segment)
                for index in range(count):
                    values = struct.unpack_from('<16s16sQQIIIIIIII', data, cursor + 72 + 80 * index)
                    section_name, segment_name, address, section_size, file_offset = values[:5]
                    _require(segment_name.rstrip(b'\0') == segment['name'] and address >= segment['address']
                             and address + section_size <= segment['address'] + vm_size,
                             'Section exceeds its segment')
                    # The capabilities below require file-backed code or const data.
                    backed = file_offset >= offset and file_offset + section_size <= offset + file_size
                    _require(not backed or file_offset - offset == address - segment['address'],
                             'Section file/VM mapping is inconsistent')
                    self.sections.append(dict(name=section_name.rstrip(b'\0'), segment=segment_name.rstrip(b'\0'),
                                              address=address, size=section_size, offset=file_offset,
                                              backed=backed, protection=protection))
            elif command == 2:
                _require(symtab is None and size == 24, 'Invalid symbol table command')
                symtab = struct.unpack_from('<IIII', data, cursor + 8)
            cursor += size
        _require(cursor == end and symtab is not None, 'Missing symbol table')
        occupied = sorted((item['address'], item['address'] + item['size'])
                          for item in self.segments if item['size'])
        _require(all(first[1] <= second[0] for first, second in zip(occupied, occupied[1:])),
                 'Overlapping virtual segments')
        text = [item for item in self.segments if item['name'] == b'__TEXT' and item['offset'] == 0]
        _require(len(text) == 1, 'Ambiguous image base')
        self.base = text[0]['address']
        sym_offset, sym_count, strings_offset, strings_size = symtab
        _require(0 < sym_count <= len(data) // 16 and sym_offset + sym_count * 16 <= len(data)
                 and strings_offset + strings_size <= len(data), 'Invalid symbol/string bounds')
        linkedit = [item for item in self.segments if item['name'] == b'__LINKEDIT']
        _require(len(linkedit) == 1 and all(linkedit[0]['offset'] <= start <= stop
                 <= linkedit[0]['offset'] + linkedit[0]['file_size']
                 for start, stop in ((sym_offset, sym_offset + sym_count * 16),
                                     (strings_offset, strings_offset + strings_size))),
                 'Symbol tables exceed LINKEDIT')
        strings = data[strings_offset:strings_offset + strings_size]
        for index in range(sym_count):
            name_offset, kind, section_index, _, address = struct.unpack_from('<IBBHQ', data, sym_offset + 16 * index)
            if kind & 0xE0 or kind & 0x0E != 0x0E:
                continue
            _require(0 < section_index < len(self.sections) and name_offset < strings_size, 'Invalid defined symbol')
            stop = strings.find(b'\0', name_offset)
            _require(stop >= 0, 'Unterminated symbol name')
            name = strings[name_offset:stop].decode('ascii', errors='strict')
            section = self.sections[section_index]
            if name == '__mh_execute_header' and address == self.base:
                continue
            _require(section['address'] <= address <= section['address'] + section['size'], 'Symbol exceeds its section')
            self.symbols.append(dict(name=name[1:] if name.startswith('_') else name,
                                     address=address, section_index=section_index, external=bool(kind & 1)))
        _require(self.symbols, 'No defined symbols')

    def named(self, name, code=False, external=False):
        matches = [item for item in self.symbols if item['name'] == name]
        _require(len(matches) == 1, 'Missing or ambiguous symbol: ' + name)
        symbol = matches[0]
        if external:
            _require(symbol['external'], 'Required dynamic symbol is local: ' + name)
        if code:
            self.extent(symbol, True)
        return symbol

    def at(self, address, code=False):
        matches = [item for item in self.symbols if item['address'] == address]
        _require(matches, 'Pointer does not address a defined symbol')
        # Aliases must share the same complete section extent.
        _require(len({item['section_index'] for item in matches}) == 1, 'Ambiguous symbol address')
        symbol = matches[0]
        self.extent(symbol, code)
        return symbol

    def extent(self, symbol, code=False):
        section = self.sections[symbol['section_index']]
        start = symbol['address']
        stop = min((item['address'] for item in self.symbols
                    if item['section_index'] == symbol['section_index'] and item['address'] > start),
                   default=section['address'] + section['size'])
        _require(section['backed'] and stop > start, 'Symbol has no file-backed extent')
        _require(not code or (section['protection'] & 4 and start % 4 == 0 and (stop - start) % 4 == 0),
                 'Expected executable ARM64 instructions')
        offset = section['offset'] + start - section['address']
        _require(offset + stop - start <= len(self.data), 'Symbol exceeds executable bytes')
        return offset, stop - start

    def bytes(self, symbol, code=False):
        offset, size = self.extent(symbol, code)
        return self.data[offset:offset + size]

    def instructions(self, symbol):
        raw = self.bytes(symbol, True)
        _require(4 <= len(raw) <= 1 << 20, 'Unreasonable function extent')
        return [(symbol['address'] + index, struct.unpack_from('<I', raw, index)[0])
                for index in range(0, len(raw), 4)]

    def record(self, symbol):
        raw = self.bytes(symbol, True)
        return dict(offset=symbol['address'] - self.base, size=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def _add(value, offset):
    if isinstance(value, int):
        return value + offset
    if isinstance(value, tuple) and len(value) == 2 and value[0] == 'stack':
        return ('stack', value[1] + offset)
    return None


class _State:
    """Small, deliberately bounded register/stack provenance tracker."""
    def __init__(self):
        self.registers = [('arg', index) for index in range(31)] + [('stack', 0)]
        self.stack = {8 * index: ('arg', 8 + index) for index in range(8)}

    def value(self, register):
        return 0 if register == 31 else self.registers[register]

    def load(self, base, offset):
        address = _add(base, offset)
        if isinstance(address, tuple) and address[0] == 'stack':
            return self.stack.get(address[1])
        return ('load', base, offset) if base is not None else None

    def store(self, base, offset, value):
        address = _add(base, offset)
        if isinstance(address, tuple) and address[0] == 'stack':
            self.stack[address[1]] = value

    def call(self, result=None):
        for index in range(19):
            self.registers[index] = None
        self.registers[0] = result

    def step(self, word, pc, strict=False):
        move = _mov(word)
        immediate = _immediate(word)
        memory = _memory(word)
        pair = _pair(word)
        if move:
            destination, source = move
            if destination != 31:
                self.registers[destination] = self.value(source)
        elif immediate:
            destination, value = immediate
            if destination != 31:
                self.registers[destination] = value
        elif word & 0x9F000000 == 0x90000000:  # ADRP
            immediate = _signed(((word >> 5) & 0x7FFFF) << 2 | ((word >> 29) & 3), 21) << 12
            self.registers[word & 31] = (pc & ~4095) + immediate
        elif word & 0xFF000000 in (0x91000000, 0xD1000000):
            destination, source = word & 31, (word >> 5) & 31
            offset = ((word >> 10) & 4095) << (12 if word & (1 << 22) else 0)
            self.registers[destination] = _add(self.registers[source], -offset if word & (1 << 30) else offset)
        elif memory:
            load, _, target, base, offset = memory
            if load:
                if target != 31:
                    self.registers[target] = self.load(self.registers[base], offset)
            else:
                self.store(self.registers[base], offset, self.value(target))
        elif pair:
            load, width, first, second, base, offset, mode = pair
            origin = self.registers[base]
            address = origin if mode == 1 else _add(origin, offset)
            for register, delta in ((first, 0), (second, width)):
                if load:
                    if register != 31:
                        self.registers[register] = self.load(address, delta)
                else:
                    self.store(address, delta, self.value(register))
            if mode != 2:
                self.registers[base] = _add(origin, offset)
        elif word & 0x7E000000 == 0x34000000:  # CBZ/CBNZ, nonnull continuation
            pass
        elif word in (0xD503201F, 0xD503245F, 0xD503233F, 0xD50323BF):
            pass
        elif strict:
            raise ValueError('Unsupported agent argument-transfer instruction')
        else:
            # Preserve callee-saved identities only for instructions known not
            # to write a GPR. Unknown arithmetic invalidates its destination.
            if (word & 0x7C000000 != 0x14000000 and word & 0xFF000010 != 0x54000000
                    and word & 0x7E000000 != 0x36000000 and word & 0x1E000000 != 0x0C000000):
                destination = word & 31
                if destination != 31:
                    self.registers[destination] = None


def _agent_entry(image, symbol, role, functions):
    """Prove the C-agent signature and the argument shift to its C++ method."""
    _require(symbol['name'].endswith(AGENT_SIGNATURES[role]), 'Unsupported agent wrapper signature')
    state = _State()
    instance_calls, member_calls = 0, 0
    for pc, word in image.instructions(symbol):
        target = _branch(word, pc)
        if target == functions['instance']['address'] and _is_bl(word):
            instance_calls += 1
            state.call(('instance',))
            continue
        if target == functions[role]['address']:
            member_calls += 1
            _require(instance_calls == 1 and state.registers[0] == ('instance',), 'Unproven MultiDisplay instance')
            count = {'combined': 2, 'pose': 5, 'separate_windows': 0,
                     'next_display': 9, 'display_info': 8, 'perform_rotation': 1}[role]
            for index in range(min(count, 7)):
                _require(state.registers[index + 1] == ('arg', index), 'Unsupported agent register ABI')
            if role == 'display_info':
                _require(state.load(state.registers[31], 0) == 0
                         and state.load(state.registers[31], 8) == ('arg', 7), 'Unsupported display-info stack ABI')
            if role == 'next_display':
                _require(state.load(state.registers[31], 0) == ('arg', 7)
                         and state.load(state.registers[31], 8) == ('arg', 8), 'Unsupported enumeration stack ABI')
            break
        _require(target is None, 'Unexpected branch in agent wrapper')
        move = _mov(word)
        if move and not word & 0x80000000:
            value = state.value(move[1])
            _require(isinstance(value, int) or (value == ('arg', 0) and role != 'combined'),
                     'Agent pointer argument is narrowed to 32 bits')
        state.step(word, pc, strict=True)
    _require(member_calls == 1, 'Missing agent member call')
    calls = [(pc, word) for pc, word in image.instructions(symbol)
             if _branch(word, pc) == functions[role]['address']]
    _require(len(calls) == 1, 'Ambiguous agent member call')


def _find_agent(image, functions):
    exported = image.named(AGENT_GLOBAL, external=True)
    export_section = image.sections[exported['section_index']]
    _require(not export_section['protection'] & 4, 'Agent export is executable')
    pointer = image.bytes(exported)
    _require(len(pointer) == 8, 'Agent export is not one pointer')
    table_address = struct.unpack('<Q', pointer)[0]
    table_symbol = image.at(table_address)
    section = image.sections[table_symbol['section_index']]
    _require(section['segment'] == b'__DATA_CONST' and not section['protection'] & 4,
             'Agent table is not immutable data')
    raw = image.bytes(table_symbol)
    _require(0 < len(raw) <= 4096 and len(raw) % 8 == 0, 'Invalid full agent-table extent')
    roles = tuple(AGENT_SIGNATURES)
    found = {role: [] for role in roles}
    for index in range(len(raw) // 8):
        address = struct.unpack_from('<Q', raw, index * 8)[0]
        if not address:
            continue
        entry = image.at(address, True)
        targets = {_branch(word, pc) for pc, word in image.instructions(entry)}
        for role in roles:
            if functions[role]['address'] in targets:
                _agent_entry(image, entry, role, functions)
                found[role].append((index, entry))
    _require(all(len(items) == 1 for items in found.values()), 'Missing or ambiguous agent capability')
    _require(len({items[0][0] for items in found.values()}) == len(found), 'Overlapping agent capabilities')
    return dict(global_offset=exported['address'] - image.base,
                table_offset=table_address - image.base, table_size=len(raw),
                slots={role: items[0][0] for role, items in found.items()},
                entry_offsets={role: items[0][1]['address'] - image.base for role, items in found.items()},
                entries={role: image.record(items[0][1]) for role, items in found.items()})


def _rotation(image, functions, agent):
    symbol = functions['rotate']
    ui_global = image.named(UI_AGENT_GLOBAL, external=True)['address']
    state = _State()
    combined, rotation, sizes = [], [], []
    current_size = None
    chain = None
    for pc, word in image.instructions(symbol):
        target = _branch(word, pc)
        if word & 0xFFFFFC1F == 0xD63F0000:
            value = state.registers[(word >> 5) & 31]
            if (isinstance(value, tuple) and len(value) == 3 and value[0] == 'load'
                    and isinstance(value[1], tuple) and len(value[1]) == 3 and value[1][0] == 'load'
                    and value[1][1] == ('load', ui_global, 0)):
                slot = value[2] // 8
                _require(value[2] % 8 == 0, 'Unaligned agent slot')
                if slot in (agent['slots']['combined'], agent['slots']['perform_rotation']):
                    if chain is None:
                        chain = value[1]
                    _require(chain == value[1], 'Inconsistent rotation agent provenance')
                    if slot == agent['slots']['combined']:
                        _require(all(isinstance(state.registers[i], tuple) and state.registers[i][0] == 'stack'
                                     for i in (0, 1)) and state.registers[0] != state.registers[1],
                                 'Unproven rotation dimensions')
                        combined.append(pc)
                        current_size = len(combined) - 1
                        for index in (0, 1):
                            state.store(state.registers[index], 0, ('dimension', current_size, index))
                    else:
                        rotation.append(pc)
            state.call()
        elif target is not None and _is_bl(word):
            if target == functions['resize']['address'] and current_size is not None:
                _require(state.registers[0] == ('arg', 0) and state.registers[1:3] == [0, 0]
                         and state.registers[3] == ('dimension', current_size, 0)
                         and state.registers[4] == ('dimension', current_size, 1)
                         and state.registers[5] == current_size, 'Unsupported primary-window resize sequence')
                sizes.append((current_size, pc))
                current_size = None
            state.call()
        else:
            state.step(word, pc)
    _require(len(combined) == 2 and len(rotation) == 1 and len(sizes) == 2
             and [item[0] for item in sizes] == [0, 1]
             and combined[0] < sizes[0][1] < rotation[0] < combined[1] < sizes[1][1],
             'Missing or ambiguous rotation/resize relationship')
    return [address + 4 - symbol['address'] for address in combined]


def _vector_memory(word):
    kind = word & 0xFFC00000
    if kind in (0xAD400000, 0xAD000000):
        offset = _signed((word >> 15) & 127, 7) * 16
        return [(kind == 0xAD400000, 16, register, (word >> 5) & 31, position)
                for register, position in ((word & 31, offset), ((word >> 10) & 31, offset + 16))]
    if kind in (0x3DC00000, 0x3D800000):
        return [(kind == 0x3DC00000, 16, word & 31, (word >> 5) & 31, ((word >> 10) & 4095) * 16)]
    kind = word & 0xFFE00C00
    if kind in (0x3CC00000, 0x3C800000):
        return [(kind == 0x3CC00000, 16, word & 31, (word >> 5) & 31, _signed((word >> 12) & 511, 9))]
    return None


def _successors(pc, word, code):
    following = pc + 4
    target = _branch(word, pc)
    if target is not None and not _is_bl(word):
        return [target] if target in code else []
    if word & 0x7E000000 == 0x34000000 or word & 0xFF000010 == 0x54000000:
        target = pc + _signed((word >> 5) & 0x7FFFF, 19) * 4
        return [address for address in (following, target) if address in code]
    if word & 0x7E000000 == 0x36000000:
        target = pc + _signed((word >> 5) & 0x3FFF, 14) * 4
        return [address for address in (following, target) if address in code]
    if word & 0xFFFFFC1F in (0xD65F0000, 0xD61F0000):
        return []
    return [following] if following in code else []


def _argument_states(instructions):
    """Meet stack/register identities over all local control-flow paths."""
    code = dict(instructions)
    states, work, steps = {instructions[0][0]: _State()}, [instructions[0][0]], 0
    while work:
        pc = work.pop()
        steps += 1
        _require(steps <= len(code) * 64, 'Display-event control flow did not converge')
        prior = states[pc]
        state = _State()
        state.registers, state.stack = prior.registers.copy(), prior.stack.copy()
        word = code[pc]
        if (_is_bl(word) and _branch(word, pc) is not None) or word & 0xFFFFFC1F == 0xD63F0000:
            state.call()
        else:
            state.step(word, pc)
        # Only frame addresses, constants and argument identities matter here.
        # Do not grow symbolic heap-load expressions around a native loop.
        state.registers = [None if isinstance(value, tuple) and value[0] == 'load' else value
                           for value in state.registers]
        state.stack = {key: value for key, value in state.stack.items()
                       if not (isinstance(value, tuple) and value[0] == 'load')}
        for address in _successors(pc, word, code):
            old = states.get(address)
            if old is None:
                updated = state
            else:
                updated = _State()
                updated.registers = [a if a == b else None for a, b in zip(old.registers, state.registers)]
                updated.stack = {key: value for key, value in old.stack.items() if state.stack.get(key) == value}
                if updated.registers == old.registers and updated.stack == old.stack:
                    continue
            states[address] = updated
            work.append(address)
    return states


def _prove_event_type_copy(instructions, states, constructor_pc, functions, event_size, type_offset):
    """Follow all four discriminator bytes from constructor sret to queue.

    Qt may copy the tail of an event through a temporary stack object while
    filling its display fields. Track the actual load/store bytes rather than
    assuming the constructor and queue always use one stack address.
    """
    code = dict(instructions)
    origin = states[constructor_pc].registers[8]
    _require(isinstance(origin, tuple) and origin[0] == 'stack', 'Constructor has no proven event output object')
    memory = {origin[1] + type_offset + index: index for index in range(4)}
    initial = constructor_pc + 4
    pending, work, steps, observed = {initial: (memory, {})}, [initial], 0, False
    while work:
        pc = work.pop()
        steps += 1
        _require(steps <= len(code) * 64, 'Display-event byte flow did not converge')
        memory, registers = pending[pc]
        memory, registers = memory.copy(), registers.copy()
        word, state = code[pc], states[pc]
        target = _branch(word, pc)
        if target == functions['queue_event']['address'] and _is_bl(word):
            destination = state.registers[1]
            _require(isinstance(destination, tuple) and destination[0] == 'stack'
                     and all(memory.get(destination[1] + type_offset + index) == index for index in range(4)),
                     'Constructor discriminator does not reach the queued event object')
            observed = True
            continue
        move, memory_op, pair, vector = _mov(word), _memory(word), _pair(word), _vector_memory(word)
        transfers = []
        if move:
            destination, source = move
            value = registers.pop(('x', destination), None)
            value = registers.get(('x', source)) if destination != source else value
            if value is not None:
                registers[('x', destination)] = value if word & 0x80000000 else value[:4]
        elif vector:
            transfers = [('q', *item) for item in vector]
        elif memory_op:
            transfers = [('x', *memory_op)]
        elif pair:
            load, width, first, second, base, offset, mode = pair
            if mode == 2:
                transfers = [('x', load, width, first, base, offset),
                             ('x', load, width, second, base, offset + width)]
            else:
                registers.clear()
        elif (_is_bl(word) and target is not None) or word & 0xFFFFFC1F == 0xD63F0000:
            registers.clear()
            if target == functions['create_event']['address']:
                other = state.registers[8]
                if isinstance(other, tuple) and other[0] == 'stack':
                    for offset in range(event_size):
                        memory.pop(other[1] + offset, None)
        elif len(_successors(pc, word, code)) == 1 and target is None and word & 0x7E000000 not in (0x34000000, 0x36000000):
            registers.clear()
        for family, load, width, register, base, offset in transfers:
            address = _add(state.registers[base], offset)
            key = (family, register)
            if load:
                registers.pop(key, None)
                if isinstance(address, tuple) and address[0] == 'stack':
                    value = tuple(memory.get(address[1] + index) for index in range(width))
                    if any(item is not None for item in value):
                        registers[key] = value
            elif isinstance(address, tuple) and address[0] == 'stack':
                value = registers.get(key, ())
                for index in range(width):
                    byte = value[index] if index < len(value) else None
                    memory.pop(address[1] + index, None)
                    if byte is not None:
                        memory[address[1] + index] = byte
        for address in _successors(pc, word, code):
            old = pending.get(address)
            if old is None:
                updated = (memory, registers)
            else:
                old_memory, old_registers = old
                updated = ({key: value for key, value in old_memory.items() if memory.get(key) == value},
                           {key: value for key, value in old_registers.items() if registers.get(key) == value})
                if updated == old:
                    continue
            pending[address] = updated
            work.append(address)
    _require(observed, 'Constructor has no verified event queue path')


def _event(image, functions):
    # The C entry receives an ARM64 indirect large aggregate in x0. Prove its
    # complete copy into the queue's x1 argument before using a pointer ABI.
    state = _State()
    stores, pending = [], {}
    queue_count = 0
    for pc, word in image.instructions(functions['event']):
        move = _mov(word)
        if move:
            destination, source = move
            value = pending.get(('x', source))
            pending.pop(('x', destination), None)
            state.step(word, pc)
            if value is not None and (word & 0x80000000 or value[1] <= 4):
                pending[('x', destination)] = value
            continue
        memory = _memory(word)
        if memory:
            load, width, register, base, offset = memory
            if load:
                pending.pop(('x', register), None)
                if state.registers[base] == ('arg', 0):
                    pending[('x', register)] = (offset, width)
            elif not load and ('x', register) in pending:
                _require(width == pending[('x', register)][1], 'Event copy changes scalar width')
                address = _add(state.registers[base], offset)
                stores.append((address, *pending[('x', register)]))
            state.step(word, pc)
            continue
        # Ordinary offset SIMD Q loads/stores, including an LDP/STP pair.
        vector = word & 0xFFC00000
        if vector in (0xAD400000, 0xAD000000, 0x3DC00000, 0x3D800000):
            pair = vector in (0xAD400000, 0xAD000000)
            load = vector in (0xAD400000, 0x3DC00000)
            base, first = (word >> 5) & 31, word & 31
            offset = _signed((word >> 15) & 127, 7) * 16 if pair else ((word >> 10) & 4095) * 16
            registers = [(first, offset)]
            if pair:
                registers.append(((word >> 10) & 31, offset + 16))
            for register, offset in registers:
                if load:
                    pending.pop(('q', register), None)
                    if state.registers[base] == ('arg', 0):
                        pending[('q', register)] = (offset, 16)
                elif not load and ('q', register) in pending:
                    stores.append((_add(state.registers[base], offset), *pending[('q', register)]))
            continue
        target = _branch(word, pc)
        if target is not None and _is_bl(word):
            if target == functions['queue_event']['address']:
                queue_count += 1
                destination = state.registers[1]
                _require(isinstance(destination, tuple) and destination[0] == 'stack', 'Unproven event-copy destination')
                copied = sorted((address[1] - destination[1], source, width)
                                for address, source, width in stores
                                if isinstance(address, tuple) and address[0] == 'stack')
                cursor = 0
                for relative, source, width in copied:
                    _require(relative == cursor == source, 'Event payload is not a complete identity copy')
                    cursor += width
                _require(16 < cursor <= 512, 'Invalid indirect event size')
                event_size = cursor
            state.call()
            pending.clear()
        else:
            # A copy may span a recognized MOV or load/store. Any other
            # instruction can redefine a GPR or SIMD register; do not retain
            # a stale byte origin across an unknown instruction.
            pending.clear()
            state.step(word, pc)
    _require(queue_count == 1, 'Missing or ambiguous indirect event queue')
    types = []
    constructor = _State()
    for pc, word in image.instructions(functions['create_event']):
        if word & 0xFFC003FF == 0xB9000100:  # STR W0, [X8, #imm]
            _require(constructor.registers[0] == ('arg', 0)
                     and constructor.registers[8] == ('arg', 8), 'Unproven constructor type/sret arguments')
            types.append(((word >> 10) & 4095) * 4)
        if _branch(word, pc) is not None and _is_bl(word):
            constructor.call()
        else:
            constructor.step(word, pc)
    _require(len(types) == 1 and types[0] % 4 == 0 and types[0] + 4 <= event_size,
             'Missing or ambiguous event discriminator ABI')
    type_offset = types[0]

    instructions = image.instructions(functions['add_window'])
    state = _State()
    event_calls = []
    parameters = {}
    queued = []
    # Find the two constructor calls, their immediate enum arguments, and the
    # shared queue epilogue's three scalar display fields. The method signature
    # supplies id/add/width/height; saved register identities supply their ABI.
    for index, (pc, word) in enumerate(instructions):
        target = _branch(word, pc)
        if target == functions['create_event']['address'] and _is_bl(word):
            immediate = _immediate(instructions[index - 1][1]) if index else None
            _require(immediate and immediate[0] == 0 and 0 < immediate[1] < 65536,
                     'Unproven display-event discriminator')
            event_calls.append((pc, immediate[1]))
            if len(event_calls) == 1:
                for argument in (1, 3, 4):
                    registers = [i for i in range(19, 29) if state.registers[i] == ('arg', argument)]
                    _require(len(registers) == 1, 'Unproven saved display argument')
                    parameters[argument] = registers[0]
        if target == functions['queue_event']['address'] and _is_bl(word):
            # An offset GPR pair followed by one scalar store defines id/w/h.
            for start in range(max(0, index - 12), index - 1):
                first = _pair(instructions[start][1])
                second = _memory(instructions[start + 1][1])
                if first and second:
                    load, width, a, b, base, offset, mode = first
                    load2, width2, c, base2, offset2 = second
                    if (not load and width == 4 and mode == 2 and not load2 and width2 == 4
                            and a == parameters.get(1) and b == parameters.get(3)
                            and c == parameters.get(4) and base == base2 == 31 and offset2 >= offset + 8):
                        # The actual queue argument must point at these stores.
                        pointer = None
                        for _, item in instructions[start + 2:index]:
                            if item & 0xFFC003FF == 0x910003E1:
                                pointer = (item >> 10) & 4095
                        _require(pointer is not None and pointer <= offset, 'Display payload precedes queue argument')
                        queued.append((offset - pointer, offset + width - pointer, offset2 - pointer))
        if target is not None and _is_bl(word):
            state.call()
        else:
            state.step(word, pc)
    _require(len(event_calls) == 2 and event_calls[0][1] != event_calls[1][1]
             and len(queued) == 1, 'Missing or ambiguous display add/remove events')
    # The original add flag must branch over the first constructor into the
    # remove block. This identifies semantics without ordering enum values.
    add, remove = event_calls
    flag_branches = [(pc, word) for pc, word in instructions if pc < add[0]
                     and word & 0xFF00001F == 0x34000002]
    _require(len(flag_branches) == 1, 'Unproven display add/remove branch')
    branch_pc, branch_word = flag_branches[0]
    remove_block = branch_pc + _signed((branch_word >> 5) & 0x7FFFF, 19) * 4
    _require(add[0] < remove_block <= remove[0], 'Inconsistent display add/remove paths')
    id_offset, width_offset, height_offset = queued[0]
    _require(type_offset >= height_offset + 4, 'Event discriminator overlaps display fields')
    states = _argument_states(instructions)
    for pc, _ in event_calls:
        _require(pc in states, 'Unreachable display-event constructor')
        _prove_event_type_copy(instructions, states, pc, functions, event_size, type_offset)
    return dict(size=event_size, type_offset=type_offset, add_type=add[1], remove_type=remove[1],
                id_offset=id_offset, width_offset=width_offset, height_offset=height_offset)


def analyze(data: bytes) -> dict:
    """Return a verified capability recipe, or raise ValueError for unknown ABI."""
    image = _Image(data)
    functions = {role: image.named(name, code=True, external=True) for role, name in FUNCTIONS.items()}
    agent = _find_agent(image, functions)
    callers = _rotation(image, functions, agent)
    event = _event(image, functions)
    bindings = {role: FUNCTIONS[role] for role in (*AGENT_SIGNATURES, 'rotate', 'event')}
    return dict(schema=SCHEMA, binary_sha256=hashlib.sha256(data).hexdigest(),
                image_preferred_base=image.base, bindings=bindings,
                symbols={FUNCTIONS[role]: image.record(symbol) for role, symbol in functions.items()},
                agent=agent, rotation_callers=callers, event=event)


def prepare(executable: Path) -> Path | None:
    """Cache only the exact discovered recipe in private, owned host storage."""
    import json
    import sys
    from host_launch import job_directory, owned_directory, owned_file, write_private
    try:
        data = Path(executable).read_bytes()
        recipe = analyze(data)
        checksum = hashlib.sha256(data).hexdigest()
        if recipe.get('binary_sha256') != checksum:
            raise ValueError('Capability recipe does not match the executable bytes.')
        encoded = (json.dumps(recipe, sort_keys=True, indent=2) + '\n').encode()
        parent = job_directory().parent / 'host-display'
        owned_directory(parent, private=True)
        directory = parent / checksum
        owned_directory(directory, private=True)
        target = directory / 'recipe.json'
        if target.exists() or target.is_symlink():
            owned_file(target)
            if target.read_bytes() != encoded:
                raise RuntimeError('Owned display capability recipe was modified; it was preserved.')
        else:
            write_private(target, encoded)
        return target
    except (OSError, ValueError, UnicodeError, struct.error, RuntimeError) as error:
        print('HyperOSAVDDisplay: capability discovery skipped: ' + str(error), file=sys.stderr)
        return None
