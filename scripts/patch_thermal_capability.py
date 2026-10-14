#!/usr/bin/env python3
"""Leave an audited board-temperature monitor stopped without its physical node.

Core must separately prove ranchu and absence of NODE before selecting a rule.
Only start()'s first complete IGET_OBJECT becomes RETURN_VOID/NOP. The audited
SceneContextCollector also skips its fixed board-node read, continuing its OEM
thermal-zone fallback with the original -1 failure sentinel. Keep the original
sampler, parsing, handlers and all ZIP metadata.
The two inputs are existing verified Uniperf derivatives, never factory APKs.
"""
import argparse
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import zlib

from patch_boot_services import AFTER as BOOT_AFTER
from patch_uniperf import RECIPES as UNIPERF_RECIPES, _stored_dex_layout
from patch_wifi_capabilities import _unpack, _uleb

PATH = '/system_ext/framework/miui-services.jar'
NODE = '/sys/class/thermal/thermal_message/board_sensor_temp'
CLASS = 'Lcom/miui/server/mirim/scenario/customscenario/resourceredline/ThermalResourceMonitor;'
METHOD = CLASS + '->start(Landroid/content/Context;Landroid/os/Handler;)V'
RETURN_VOID = bytes.fromhex('0e000000')
SCENE_CLASS = 'Lcom/miui/server/SceneContextCollector;'
SCENE_METHOD = SCENE_CLASS + '->readBackShellTemp()I'
UNAVAILABLE_BOARD = bytes.fromhex('12f0' + '0000' * 5)
MULTIDEX_SOURCE = 'a15133a28eb0d336832957908aa3461f76dab679c7be2ed0809dabdd789dc941'

# Share input identities and archive layout with the prerequisite producer.
# Keep its frozen receipts unchanged; register only these new derivatives.
RECIPES = {}
for _source, _extra in (
    (BOOT_AFTER['miui-services'], {
        'after': 'd936fe7a0ae7ab91aacf54011dbdf6fca6bcd3e1484bdb1326a17b4da9d27ffe',
        'dex_after': '768e0092c0ced0d4878205f599e33b249dd6423714e68617a18e26e0c12de2eb',
        'code_offset': 6177720, 'code_header': (6, 3, 2, 1, 4462479, 68),
        'method_id': 14008,
        'body_before': 'd827ad6075f4ee0242ee3effd9efe4fa36e8cfb8ba03bc9e35b8fc04b17e4792',
        'body_after': '5fe54e363bf7c51c546d54d8d396f457fc3641d05d22f740cfa4038819ec4514',
        'original': '5430c121',
        'scene': {'code_offset': 5164768, 'code_header': (3, 1, 1, 0, 4242197, 22),
                  'method_id': 4106,
                  'body_before': 'bf70cef70f95df3de459d3d10ec4bf37caabe2940c69a4fc5426640e651e1311',
                  'body_after': '51acbfed0953a40718a96c061a68d9bd32c13e131729ee048200f516be5dc904',
                  'original': '1a00b32e7110111000000a00'},
        'sites': ((12019627, 'e2e43050', '12ac5110'),
                  (12019663, 'f7bafafde6f85cd525a35c90f0e44592776079df2a3487be',
                   'efb7f4161f6a9c856b45f64561789ada72a44de061727ebf'),
                  (18197391, '5430c121', '0e000000'),
                  (17184439, '1a00b32e7110111000000a00', '12f000000000000000000000'),
                  (20737164, 'e2e43050', '12ac5110')),
    }),
    (MULTIDEX_SOURCE, {
        'after': '3fe9549794c29da738574f9b17da496f95e7a6408dcf5db5a82d5499872075a6',
        'dex_after': '525e189c7bca1df00fc3e6b6e250f3b39ba69878f6e29c82469b77c7fc3fde4d',
        'code_offset': 1818852, 'code_header': (6, 3, 2, 1, 4056019, 68),
        'method_id': 10203,
        'body_before': '4a883c94764911316dbeb94513b685a64258bd63dfb1153efa6a20fd7c361f39',
        'body_after': 'f4a074d9acb32ce4f2684865df7502a3fb541521bea069a4f217360f8644dee9',
        'original': '5430c417',
        'sites': ((12063470, '0d88e7a9', '7f88d422'),
                  (12063508, '3ded6f17a9491004dbcb3b7257bebdacc3f51ddcac2024c6',
                   '34ea3ffac05e4eef410cf2235f1f80a6269fc558431b5c89'),
                  (13882368, '5430c417', '0e000000'),
                  (19634723, '0d88e7a9', '7f88d422')),
    }),
):
    _input = UNIPERF_RECIPES[_source]
    RECIPES[_input['after']] = {
        **{name: _input[name] for name in ('size', 'member', 'count', 'dex_offset', 'dex_size', 'dex_magic')},
        'dex_before': _input['dex_after'], **_extra,
    }
del _source, _extra, _input

# Core15's classes2 monitor result remains a frozen producer output. The
# independent scene collector is in classes.dex on this audited archive;
# register a successor edge instead of reinterpreting the old producer.
_monitor = RECIPES[UNIPERF_RECIPES[MULTIDEX_SOURCE]['after']]
SCENE_RECIPES = {
    _monitor['after']: {
        'after': 'd756234045b02391c94a3eaa22c9a836a9781760994c17a54a97d6e4d7f05505',
        'size': _monitor['size'], 'count': _monitor['count'], 'member': 'classes.dex',
        'dex_magic': b'dex\n039\0', 'dex_offset': 44, 'dex_size': 12063412,
        'dex_before': '45396ae38e9cae4dbf44581826895d621765814914d9d3fe5a517b8c31d08172',
        'dex_after': '34c6e1cacf10da9f5b28b63c55aa7f378a80ce08de867774a18592a8e9c66799',
        'preserved_member': _monitor['member'], 'preserved_sha256': _monitor['dex_after'],
        'code_offset': 6686008, 'code_header': (3, 1, 1, 0, 7878545, 22), 'method_id': 60553,
        'body_before': '233fe4e13a30fc3e45f1df2ede714dcd5085f71bf6446ad65ae7329c99317556',
        'body_after': 'deb6cf074ab8b395abe9eb2b9d09d7fe624689f1224660e5a094429bf8ee16a8',
        'original': '1a00d630711090ec00000a00',
        'sites': ((14, '0459774a', '04424150'),
                  (52, '40385ac937c62e7479bf93124188b5e6755c363c2160d7a6',
                   '76375ba3bd92428fd79ab1d10ab1a91b977090ef6a560c98'),
                  (6686068, '1a00d630711090ec00000a00', '12f000000000000000000000'),
                  (19634666, '0459774a', '04424150')),
    },
}
del _monitor


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def select_recipe(data):
    digest = _sha(data) if isinstance(data, (bytes, bytearray)) else data
    for before, rule in RECIPES.items():
        if digest in (before, rule['after']):
            return before, rule, digest != before
    raise RuntimeError('Unsupported thermal framework JAR SHA-256: ' + str(digest))


def _method(dex, rule, scene=False):
    """Authenticate one exact instance-method DEX ABI, not an instruction scan."""
    class_name, method_name, signature, access_flags = (
        (SCENE_CLASS, 'readBackShellTemp', SCENE_METHOD, 2) if scene else (CLASS, 'start', METHOD, 1))
    def table(offset, width):
        count, start = _unpack(dex, offset, '<II')
        if count > len(dex) // width or start + count * width > len(dex):
            raise RuntimeError('Invalid thermal DEX table.')
        return count, start

    strings, string_start = table(56, 4)
    types, type_start = table(64, 4)
    protos, proto_start = table(72, 12)
    methods, method_start = table(88, 8)
    classes, class_start = table(96, 32)

    def string(index):
        if index >= strings:
            raise RuntimeError('Invalid thermal string index.')
        offset, = _unpack(dex, string_start + index * 4, '<I')
        _, offset = _uleb(dex, offset)
        end = dex.find(b'\0', offset)
        if end < 0:
            raise RuntimeError('Unterminated thermal DEX string.')
        return dex[offset:end].decode('ascii', errors='replace')

    def typename(index):
        if index >= types:
            raise RuntimeError('Invalid thermal type index.')
        return string(_unpack(dex, type_start + index * 4, '<I')[0])

    result = []
    for index in range(classes):
        class_id, _, _, _, _, _, offset, _ = _unpack(dex, class_start + index * 32, '<8I')
        if typename(class_id) != class_name:
            continue
        counts = []
        for _ in range(4):
            value, offset = _uleb(dex, offset)
            counts.append(value)
        if sum(counts) > len(dex):
            raise RuntimeError('Invalid thermal class-data counts.')
        for _ in range(counts[0] + counts[1]):
            _, offset = _uleb(dex, offset)
            _, offset = _uleb(dex, offset)
        for count in counts[2:]:
            method_id = 0
            for _ in range(count):
                delta, offset = _uleb(dex, offset)
                method_id += delta
                access, offset = _uleb(dex, offset)
                code, offset = _uleb(dex, offset)
                if method_id >= methods:
                    raise RuntimeError('Invalid thermal method index.')
                owner, proto, name = _unpack(dex, method_start + method_id * 8, '<HHI')
                if string(name) != method_name:
                    continue
                if owner != class_id or proto >= protos:
                    raise RuntimeError('Invalid thermal method owner/prototype.')
                _, return_type, parameters = _unpack(dex, proto_start + proto * 12, '<III')
                size = _unpack(dex, parameters, '<I')[0] if parameters else 0
                if size > len(dex) // 2:
                    raise RuntimeError('Invalid thermal parameter list.')
                args = ''.join(typename(_unpack(dex, parameters + 4 + item * 2, '<H')[0])
                               for item in range(size))
                descriptor = class_name + '->' + method_name + '(' + args + ')' + typename(return_type)
                result.append((descriptor, code, access, method_id))
    if result != [(signature, rule['code_offset'], access_flags, rule['method_id'])]:
        raise RuntimeError('Missing or ambiguous audited thermal method.')
    return rule['code_offset']


def audit(data):
    if not isinstance(data, (bytes, bytearray)):
        raise RuntimeError('Unsupported thermal framework JAR input.')
    data = bytes(data)
    _, rule, patched = select_recipe(data)
    if (len(data) != rule['size'] or _stored_dex_layout(data, rule['member'], rule['count']) !=
            (rule['dex_offset'], rule['dex_size'], rule['sites'][0][0], rule['sites'][-1][0])):
        raise RuntimeError('Unexpected thermal unsigned ZIP layout.')
    dex = data[rule['dex_offset']:rule['dex_offset'] + rule['dex_size']]
    if (dex[:8] != rule['dex_magic']
            or _unpack(dex, 32, '<III') != (rule['dex_size'], 112, 0x12345678)
            or _sha(dex) != rule['dex_after' if patched else 'dex_before']
            or dex[12:32] != hashlib.sha1(dex[32:]).digest()
            or _unpack(dex, 8, '<I')[0] != zlib.adler32(dex[12:]) & 0xffffffff):
        raise RuntimeError('Unexpected thermal DEX checksum/header.')
    code = _method(dex, rule)
    body = dex[code + 16:code + 16 + rule['code_header'][5] * 2]
    if (_unpack(dex, code, '<4H2I') != rule['code_header']
            or _sha(body) != rule['body_after' if patched else 'body_before']
            or body[:4] != (RETURN_VOID if patched else bytes.fromhex(rule['original']))):
        raise RuntimeError('Unexpected thermal start body/try layout.')
    if 'scene' in rule:
        scene = rule['scene']
        code = _method(dex, scene, scene=True)
        body = dex[code + 16:code + 16 + scene['code_header'][5] * 2]
        if (_unpack(dex, code, '<4H2I') != scene['code_header']
                or _sha(body) != scene['body_after' if patched else 'body_before']
                or body[:12] != (UNAVAILABLE_BOARD if patched else bytes.fromhex(scene['original']))):
            raise RuntimeError('Unexpected thermal scene fallback body.')
    for offset, original, replacement in rule['sites']:
        expected = bytes.fromhex(replacement if patched else original)
        if data[offset:offset + len(expected)] != expected:
            raise RuntimeError('Unexpected thermal canonical patch site.')
    return patched


def patch_bytes(data):
    if audit(data):
        return bytes(data)
    _, rule, _ = select_recipe(data)
    output = bytearray(data)
    for offset, _, replacement in rule['sites']:
        value = bytes.fromhex(replacement)
        output[offset:offset + len(value)] = value
    result = bytes(output)
    if len(result) != len(data) or _sha(result) != rule['after'] or not audit(result):
        raise RuntimeError('Thermal deterministic derivative mismatch.')
    return result


def recipe_receipt(before):
    if before not in RECIPES:
        raise RuntimeError('Unsupported thermal receipt source.')
    rule = RECIPES[before]
    methods = [METHOD] + ([SCENE_METHOD] if 'scene' in rule else [])
    sites = []
    for offset, original, replacement in rule['sites']:
        method = None
        if offset == rule['dex_offset'] + rule['code_offset'] + 16:
            method = METHOD
        elif 'scene' in rule and offset == rule['dex_offset'] + rule['scene']['code_offset'] + 16:
            method = SCENE_METHOD
        sites.append({'offset': offset, 'before': original, 'after': replacement,
                      **({'method': method} if method else {})})
    return {'schema': 1, 'id': 'thermal-board-capability-v1', 'path': PATH,
            'format': 'framework-jar', 'before': before, 'after': rule['after'], 'size': rule['size'],
            'dex_before': rule['dex_before'], 'dex_after': rule['dex_after'], 'methods': methods,
            'requires': 'ranchu-without-board-temperature-node', 'absent_node': NODE,
            'sites': sites}


def catalog_recipes():
    return (tuple(recipe_receipt(before) for before in RECIPES) +
            tuple(scene_recipe_receipt(before) for before in SCENE_RECIPES))


def receipt(data):
    audit(data)
    return recipe_receipt(select_recipe(data)[0])


def select_scene_recipe(data):
    """Keep successor selection distinct from the frozen monitor producer."""
    digest = _sha(data) if isinstance(data, (bytes, bytearray)) else data
    for before, rule in SCENE_RECIPES.items():
        if digest in (before, rule['after']):
            return before, rule, digest != before
    raise RuntimeError('Unsupported thermal scene framework JAR SHA-256: ' + str(digest))


def scene_audit(data):
    if not isinstance(data, (bytes, bytearray)):
        raise RuntimeError('Unsupported thermal scene framework JAR input.')
    data = bytes(data)
    _, rule, patched = select_scene_recipe(data)
    if (len(data) != rule['size'] or _stored_dex_layout(data, rule['member'], rule['count']) !=
            (rule['dex_offset'], rule['dex_size'], rule['sites'][0][0], rule['sites'][-1][0])):
        raise RuntimeError('Unexpected thermal scene unsigned ZIP layout.')
    dex = data[rule['dex_offset']:rule['dex_offset'] + rule['dex_size']]
    if (dex[:8] != rule['dex_magic']
            or _unpack(dex, 32, '<III') != (rule['dex_size'], 112, 0x12345678)
            or _sha(dex) != rule['dex_after' if patched else 'dex_before']
            or dex[12:32] != hashlib.sha1(dex[32:]).digest()
            or _unpack(dex, 8, '<I')[0] != zlib.adler32(dex[12:]) & 0xffffffff):
        raise RuntimeError('Unexpected thermal scene DEX checksum/header.')
    code = _method(dex, rule, scene=True)
    body = dex[code + 16:code + 16 + rule['code_header'][5] * 2]
    if (_unpack(dex, code, '<4H2I') != rule['code_header']
            or _sha(body) != rule['body_after' if patched else 'body_before']
            or body[:12] != (UNAVAILABLE_BOARD if patched else bytes.fromhex(rule['original']))):
        raise RuntimeError('Unexpected thermal scene fallback body.')
    # Prove the already-audited monitor and Uniperf DEX stays intact through
    # this separate member edit, not merely that the JAR has a known path.
    offset, size, _, _ = _stored_dex_layout(data, rule['preserved_member'], rule['count'])
    if _sha(data[offset:offset + size]) != rule['preserved_sha256']:
        raise RuntimeError('Thermal scene successor changed its prerequisite DEX.')
    for offset, original, replacement in rule['sites']:
        expected = bytes.fromhex(replacement if patched else original)
        if data[offset:offset + len(expected)] != expected:
            raise RuntimeError('Unexpected thermal scene canonical patch site.')
    return patched


def scene_patch_bytes(data):
    if scene_audit(data):
        return bytes(data)
    _, rule, _ = select_scene_recipe(data)
    output = bytearray(data)
    for offset, _, replacement in rule['sites']:
        value = bytes.fromhex(replacement)
        output[offset:offset + len(value)] = value
    result = bytes(output)
    if len(result) != len(data) or _sha(result) != rule['after'] or not scene_audit(result):
        raise RuntimeError('Thermal scene deterministic derivative mismatch.')
    return result


def scene_recipe_receipt(before):
    if before not in SCENE_RECIPES:
        raise RuntimeError('Unsupported thermal scene receipt source.')
    rule = SCENE_RECIPES[before]
    return {'schema': 1, 'id': 'thermal-board-scene-capability-v1', 'path': PATH,
            'format': 'framework-jar', 'before': before, 'after': rule['after'], 'size': rule['size'],
            'dex_before': rule['dex_before'], 'dex_after': rule['dex_after'], 'methods': [SCENE_METHOD],
            'requires': 'ranchu-without-board-temperature-node', 'absent_node': NODE,
            'sites': [{'offset': offset, 'before': original, 'after': replacement,
                       **({'method': SCENE_METHOD} if offset == rule['dex_offset'] + rule['code_offset'] + 16 else {})}
                      for offset, original, replacement in rule['sites']]}


def scene_receipt(data):
    scene_audit(data)
    return scene_recipe_receipt(select_scene_recipe(data)[0])


def patch(source, destination, scene=False):
    """Publish exclusively without replacing factory or customized content."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise RuntimeError('Keep the factory thermal JAR and derivative separate.')
    output = (scene_patch_bytes if scene else patch_bytes)(source.read_bytes())

    def verify_existing():
        info = destination.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or destination.read_bytes() != output:
            raise RuntimeError('Preserving an unknown thermal derivative output.')

    if destination.exists() or destination.is_symlink():
        verify_existing()
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.thermal-', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
        try:
            os.link(temporary, destination)
        except FileExistsError:
            verify_existing()
    finally:
        Path(temporary).unlink(missing_ok=True)
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--scene', action='store_true', help='Apply only the independent audited scene successor.')
    args = parser.parse_args()
    print(patch(args.source, args.destination, scene=args.scene))
