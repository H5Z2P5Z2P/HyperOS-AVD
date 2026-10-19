"""Bake the pinned ARM64 Dolby audio decoders into a private vendor service."""
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = ROOT / 'native/dolby-codecs-arm64.payload'
PAYLOAD_SHA256 = 'b18d8607ddaaf64ae7cdf02670288b15b6b11f7f1aef075097f9ea413d241088'
SOURCE_SERVICE = 'bin/hw/android.hardware.media.c2@1.0-service-goldfish'
SERVICE_PATH = '/vendor/bin/hw/hyperos-audio-codecs'
LIBRARY_PATH = '/vendor/lib64/hyperos-audio-codecs'
CODEC_PATH = '/vendor/etc/media_codecs_dolby.xml'
MAIN_CODEC_PATH = '/vendor/etc/media_codecs.xml'
INIT_PATH = '/vendor/etc/init/hyperos-audio-codecs.rc'
VINTF_PATH = '/vendor/etc/vintf/manifest/hyperos-audio-codecs.xml'
SERVICE_BEFORE = '4c98f9c2fb855c09b87e584b13dd33fe27ba35551bcda7a833c972c7dd1d35fa'
SERVICE_AFTER = '70d846bddac710c96d1356361415ed72d999e48d82e1c6e248691e809a8bd768'
SERVICE_SITES = (
    (0x4624, bytes.fromhex('c8018052'), bytes.fromhex('48018052')),
    (0x4628, bytes.fromhex('89ac8c52'), bytes.fromhex('89ec8d52')),
    (0x4634, bytes.fromhex('28ac8e52'), bytes.fromhex('482c8f52')),
    (0x4638, bytes.fromhex('c92cac72'), bytes.fromhex('894dac72')),
    (0x463c, bytes.fromhex('888dae72'), bytes.fromhex('0800a072')),
)


STORE_SOURCE = 'lib64/libcodec2_store_mi.so'
STORE_BEFORE = '092c6ed7c699563fb8cf92b0daba7a70e5f94651d8428ea202906a2499f2b174'
STORE_AFTER = 'ed83dcdc269c3002232a6f88a450db272d278f1ca443c7f9b83cf2fbfeadb128'
STORE_SITES = ((0x9ee0, '8f070094'), (0x9efc, '88070094'), (0x9f18, '81070094'),
               (0x9f34, '7a070094'), (0x9f50, '73070094'), (0x9f6c, '6c070094'))
CODEC_BEFORE = 'b56b6b15a049407775eb87bf2238588718765565675642f507717161173aee18'
CODEC_AFTER = 'de166ccaecdc2f4efb2961d66883a283f1e7dcac0c599c8415c79e8b7026f8e0'

INIT_RC = b'''service hyperos-audio-codecs /vendor/bin/hw/hyperos-audio-codecs
    class hal
    user mediacodec
    group mediadrm drmrpc
    seclabel u:r:mediacodec:s0
    setenv LD_LIBRARY_PATH /vendor/lib64/hyperos-audio-codecs
    task_profiles ProcessCapacityHigh
'''

VINTF_XML = b'''<?xml version="1.0" encoding="utf-8"?>
<manifest version="9.0" type="device">
    <hal format="hidl">
        <name>android.hardware.media.c2</name>
        <transport>hwbinder</transport>
        <version>1.0</version>
        <interface>
            <name>IComponentStore</name>
            <instance>dolby</instance>
        </interface>
    </hal>
</manifest>
'''
VINTF_SHA256 = 'f8a5f0803e3011fe08fad3a89d786bf96f04878bb3f3d544b895772548d2de37'

# Retain the source decoder capabilities without advertising unavailable Mi
# speech codecs or encoders from the original mixed audio catalog.
CODEC_XML = b'''<?xml version="1.0" encoding="utf-8"?>
<Included>
    <Decoders>
        <MediaCodec name="c2.dolby.eac3.decoder">
            <Type name="audio/ac3">
                <Alias name="OMX.dolby.ac3.decoder" />
                <Limit name="channel-count" max="6" />
                <Limit name="sample-rate" ranges="32000,44100,48000" />
                <Limit name="bitrate" range="32000-640000" />
            </Type>
            <Type name="audio/eac3">
                <Alias name="OMX.dolby.eac3.decoder" />
                <Limit name="channel-count" max="8" />
                <Limit name="sample-rate" ranges="32000,44100,48000" />
                <Limit name="bitrate" range="32000-6144000" />
            </Type>
            <Type name="audio/eac3-joc">
                <Alias name="OMX.dolby.eac3-joc.decoder" />
                <Limit name="channel-count" max="16" />
                <Limit name="sample-rate" ranges="48000" />
                <Limit name="bitrate" range="32000-6144000" />
            </Type>
            <Attribute name="software-codec" />
        </MediaCodec>
        <MediaCodec name="c2.dolby.ac4.decoder" type="audio/ac4">
            <Alias name="OMX.dolby.ac4.decoder" />
            <Limit name="channel-count" max="21" />
            <Limit name="sample-rate" ranges="48000" />
            <Limit name="bitrate" range="16000-2688000" />
            <Attribute name="software-codec" />
        </MediaCodec>
    </Decoders>
</Included>
'''


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _elf(data):
    if (len(data) < 64 or data[:6] != b'\x7fELF\x02\x01'
            or struct.unpack_from('<H', data, 18)[0] != 183):
        raise RuntimeError('Dolby codec payload requires little-endian AArch64 ELF64.')


def patch_service(data):
    """Keep goldfish's HIDL 1.0 entry, replacing only its store and instance.

    The two factories return the same two-word std::shared_ptr through x8.
    The source allocation of 0x120 bytes also fits the pinned Mi HIDL store.
    The five MOVZ/MOVK changes construct the short string "dolby", length 5.
    Compact only the four unused HIDL 1.1/1.2 DT_NEEDED entries, preserving
    the dynamic table size, every other tag/value and all ELF load metadata.
    """
    data = bytes(data)
    checksum = hashlib.sha256(data).hexdigest()
    if checksum == SERVICE_AFTER:
        return data
    if checksum != SERVICE_BEFORE:
        raise RuntimeError('Unsupported HIDL Codec2 entry SHA-256: ' + checksum)
    if (len(data) != 51464 or data[:6] != b'\x7fELF\x02\x01'
            or struct.unpack_from('<H', data, 18)[0] != 183):
        raise RuntimeError('Expected the pinned AArch64 ELF64 HIDL Codec2 entry.')
    result = bytearray(data)
    for offset, before, after in SERVICE_SITES:
        if data[offset:offset + 4] != before:
            raise RuntimeError('Unexpected HIDL Codec2 instruction at ' + hex(offset))
        result[offset:offset + 4] = after
    replacements = (
        (0x63b, b'_ZN7android22GoldfishComponentStore6CreateEv\0',
         b'_ZN7android25GetCodec2MiComponentStoreEv\0'),
        (0x97e, b'libgoldfish_codec2_store.so\0', b'libcodec2_store_mi.so\0'),
    )
    for offset, before, after in replacements:
        if data[offset:offset + len(before)] != before or data.count(before) != 1:
            raise RuntimeError('Unexpected HIDL Codec2 dynamic string layout.')
        result[offset:offset + len(before)] = after + bytes(len(before) - len(after))
    start, end = 0x8010, 0x82c0
    entries = [struct.unpack_from('<QQ', data, offset)
               for offset in range(start, end, 16)]
    removed = {(1, 0x36c), (1, 0x38d), (1, 0x3c4), (1, 0x3da)}
    expected_names = {
        0x36c: b'android.hardware.media.c2@1.1.so\0',
        0x38d: b'android.hardware.media.c2@1.2.so\0',
        0x3c4: b'libcodec2_hidl@1.1.so\0',
        0x3da: b'libcodec2_hidl@1.2.so\0',
    }
    for index, name in expected_names.items():
        if data[0x57c + index:0x57c + index + len(name)] != name:
            raise RuntimeError('Unexpected unused HIDL Codec2 dependency.')
    if entries[-1] != (0, 0) or any(entries.count(entry) != 1 for entry in removed):
        raise RuntimeError('Unexpected HIDL Codec2 dynamic table layout.')
    kept = [entry for entry in entries if entry not in removed]
    body = b''.join(struct.pack('<QQ', *entry) for entry in kept)
    result[start:end] = body + bytes(end - start - len(body))
    if len(result) != len(data):
        raise RuntimeError('HIDL Codec2 entry size changed.')
    if hashlib.sha256(result).hexdigest() != SERVICE_AFTER:
        raise RuntimeError('HIDL Codec2 entry patch SHA-256 mismatch.')
    return bytes(result)


def patch_store(data):
    """Register only the bundled DDP and AC-4 decoder libraries.

    The constructor ends with eight independent map insertions. Each block
    supplies one library literal and calls the same node-building helper.
    Skip only the first six calls, before any node or string is allocated.
    Keep the final DDP/AC-4 calls and the complete constructor cleanup path.
    """
    checksum = _sha256(data)
    if checksum == STORE_AFTER:
        return bytes(data)
    if checksum != STORE_BEFORE:
        raise RuntimeError('Unsupported Dolby component store SHA-256: ' + checksum)
    _elf(data)
    result = bytearray(data)
    for offset, before in STORE_SITES:
        if data[offset:offset + 4] != bytes.fromhex(before):
            raise RuntimeError('Unexpected Dolby component registration call.')
        result[offset:offset + 4] = bytes.fromhex('1f2003d5')
    if len(result) != len(data) or _sha256(result) != STORE_AFTER:
        raise RuntimeError('Dolby component store patch checksum mismatch.')
    return bytes(result)


def with_runpath(data, runpath):
    """Add private dynamic strings without moving the original dynamic table.

    The pinned sources declare BIND_NOW twice: DT_FLAGS and DT_FLAGS_1.
    Reuse the entry containing only BIND_NOW while retaining the other flag
    entry, including SYMBOLIC or PIE. Replace a NOTE with a read-only LOAD;
    the original note bytes and GNU property segment stay in place.
    """
    _elf(data)
    if runpath not in ('$ORIGIN', '$ORIGIN/../../lib64/hyperos-audio-codecs'):
        raise RuntimeError('Unsupported private Dolby codec RUNPATH.')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, count = struct.unpack_from('<HH', data, 54)
    if phsize != 56 or not 1 <= count <= 128 or phoff + count * phsize > len(data):
        raise RuntimeError('Unexpected Dolby codec program headers.')
    headers = [struct.unpack_from('<IIQQQQQQ', data, phoff + index * phsize)
               for index in range(count)]
    loads = [header for header in headers if header[0] == 1]
    dynamic = [header for header in headers if header[0] == 2]
    properties = [header for header in headers if header[0] == 0x6474e553]
    notes = [index for index, header in enumerate(headers) if header[0] == 4
             and not any(header[2] < item[2] + item[5] and item[2] < header[2] + header[5]
                         for item in properties)]
    if len(dynamic) != 1 or not notes or not loads:
        raise RuntimeError('Unexpected Dolby codec dynamic or NOTE layout.')
    table = dynamic[0]
    if table[2] + table[5] > len(data) or table[5] % 16:
        raise RuntimeError('Unexpected Dolby codec dynamic table bounds.')
    entries = []
    for offset in range(table[2], table[2] + table[5], 16):
        tag, value = struct.unpack_from('<QQ', data, offset)
        if tag == 0:
            break
        entries.append((tag, value, offset))
    else:
        raise RuntimeError('Unterminated Dolby codec dynamic table.')
    values = {tag: value for tag, value, _ in entries}
    if values.get(30) == 8 and values.get(0x6ffffffb, 0) & 1:
        redundant = 30
    elif values.get(0x6ffffffb) == 1 and values.get(30, 0) & 8:
        redundant = 0x6ffffffb
    else:
        raise RuntimeError('Unexpected Dolby codec BIND_NOW flags.')
    if 5 not in values or 10 not in values or 15 in values or 29 in values:
        raise RuntimeError('Unexpected Dolby codec strings or BIND_NOW flags.')
    segments = [header for header in loads
                if header[3] <= values[5] and values[5] + values[10] <= header[3] + header[5]]
    if len(segments) != 1 or values[10] > 1024 * 1024:
        raise RuntimeError('Unexpected Dolby codec dynamic string table bounds.')
    segment = segments[0]
    string_offset = segment[2] + values[5] - segment[3]
    strings = data[string_offset:string_offset + values[10]]
    if len(strings) != values[10] or not strings.endswith(bytes(1)):
        raise RuntimeError('Invalid Dolby codec dynamic strings.')
    align = lambda value: (value + 16383) // 16384 * 16384
    file_offset = align(len(data))
    address = align(max(header[3] + header[6] for header in loads))
    new_strings = strings + runpath.encode() + bytes(1)
    result = bytearray(data)
    struct.pack_into('<IIQQQQQQ', result, phoff + notes[0] * phsize,
                     1, 4, file_offset, address, address,
                     len(new_strings), len(new_strings), 16384)
    for tag, value, offset in entries:
        if tag == 5:
            struct.pack_into('<Q', result, offset + 8, address)
        elif tag == 10:
            struct.pack_into('<Q', result, offset + 8, len(new_strings))
        elif tag == redundant:
            struct.pack_into('<QQ', result, offset, 29, len(strings))
    shoff = struct.unpack_from('<Q', data, 40)[0]
    shsize, shcount = struct.unpack_from('<HH', data, 58)
    if shsize != 64 or shoff + shcount * shsize > len(data):
        raise RuntimeError('Unexpected Dolby codec section headers.')
    for index in range(shcount):
        offset = shoff + index * shsize
        kind = struct.unpack_from('<I', data, offset + 4)[0]
        if kind == 3 and struct.unpack_from('<Q', data, offset + 16)[0] == values[5]:
            struct.pack_into('<QQQ', result, offset + 16, address, file_offset, len(new_strings))
    result.extend(bytes(file_offset - len(result)))
    result.extend(new_strings)
    return bytes(result)


def _read_payload(data):
    """Authenticate and read the bounded source archive without extracting it."""
    if len(data) > 16 * 1024 * 1024 or _sha256(data) != PAYLOAD_SHA256:
        raise RuntimeError('Dolby codec asset SHA-256 mismatch.')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if (not 3 <= len(entries) <= 64 or len(names) != len(set(names))
                or sum(entry.file_size for entry in entries) > 32 * 1024 * 1024):
            raise RuntimeError('Invalid Dolby codec asset inventory.')
        for entry in entries:
            if (entry.filename not in ('manifest.json', 'etc/media_codecs.xml', SOURCE_SERVICE)
                    and not re.fullmatch(r'lib64/[A-Za-z0-9@_.+-]+\.so', entry.filename)
                    or entry.file_size > 8 * 1024 * 1024
                    or entry.flag_bits & 1
                    or stat.S_ISLNK(entry.external_attr >> 16)
                    or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                raise RuntimeError('Invalid Dolby codec asset member: ' + entry.filename)
        if names.count('manifest.json') != 1 or archive.getinfo('manifest.json').file_size > 65536:
            raise RuntimeError('Missing or oversized Dolby codec source manifest.')
        manifest = json.loads(archive.read('manifest.json'))
        hashes = manifest.get('source_files_sha256')
        outputs = manifest.get('output_files_sha256')
        if (manifest.get('schema') != 'hyperos-audio-codecs-source-v1'
                or manifest.get('abi') != 'arm64-v8a' or not isinstance(hashes, dict)
                or not isinstance(outputs, dict)
                or set(outputs) != set(hashes) - {'etc/media_codecs.xml'}
                or set(hashes) != set(names) - {'manifest.json'}
                or SOURCE_SERVICE not in hashes
                or any(not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value)
                       for value in (*hashes.values(), *outputs.values()))):
            raise RuntimeError('Invalid Dolby codec source manifest.')
        files = {}
        for name, checksum in hashes.items():
            body = archive.read(name)
            if _sha256(body) != checksum:
                raise RuntimeError('Dolby codec source checksum mismatch: ' + name)
            if name == 'etc/media_codecs.xml':
                if checksum != CODEC_BEFORE:
                    raise RuntimeError('Dolby codec source catalog checksum mismatch.')
            else:
                _elf(body)
            files[name] = body
    return files, manifest


def _assets():
    files, manifest = _read_payload(PAYLOAD.read_bytes())
    files.pop('etc/media_codecs.xml')
    for name, body in files.items():
        if name == SOURCE_SERVICE:
            body = patch_service(body)
            runpath = '$ORIGIN/../../lib64/hyperos-audio-codecs'
        else:
            if name == STORE_SOURCE:
                body = patch_store(body)
            runpath = '$ORIGIN'
        files[name] = with_runpath(body, runpath)
        if _sha256(files[name]) != manifest['output_files_sha256'][name]:
            raise RuntimeError('Dolby codec output checksum mismatch: ' + name)
    vendor_file = 'u:object_r:vendor_file:s0'
    vendor_config = 'u:object_r:vendor_configs_file:s0'
    replacements = {
        SERVICE_PATH.removeprefix('/vendor/'): (
            files.pop(SOURCE_SERVICE), 0o755, 'u:object_r:mediacodec_exec:s0'),
        INIT_PATH.removeprefix('/vendor/'): (INIT_RC, 0o644, vendor_config),
        VINTF_PATH.removeprefix('/vendor/'): (VINTF_XML, 0o644, vendor_config),
        CODEC_PATH.removeprefix('/vendor/'): (CODEC_XML, 0o644, vendor_config),
    }
    replacements.update({
        LIBRARY_PATH.removeprefix('/vendor/') + '/' + Path(name).name: (body, 0o644, vendor_file)
        for name, body in files.items()
    })
    return replacements, manifest


def image_replacements(codec_xml):
    """Accept only the original or already updated vendor codec catalog."""
    checksum = _sha256(codec_xml)
    if checksum == CODEC_BEFORE:
        codec_xml = codec_xml.replace(
            b'</MediaCodecs>', b'    <Include href="media_codecs_dolby.xml" />\n</MediaCodecs>')
    elif checksum != CODEC_AFTER:
        raise RuntimeError('Unsupported vendor media codec catalog SHA-256: ' + checksum)
    if _sha256(codec_xml) != CODEC_AFTER:
        raise RuntimeError('Dolby codec catalog checksum mismatch.')
    replacements, _ = _assets()
    replacements[MAIN_CODEC_PATH.removeprefix('/vendor/')] = (
        bytes(codec_xml), 0o644, 'u:object_r:vendor_configs_file:s0')
    return replacements


def image_receipt():
    replacements, source = _assets()
    hashes = {'/vendor/' + name: _sha256(value[0]) for name, value in replacements.items()}
    hashes[MAIN_CODEC_PATH] = CODEC_AFTER
    return {'schema': 'hyperos-audio-codecs-image-v1', 'revision': 1, 'abi': 'arm64-v8a',
            'asset_sha256': PAYLOAD_SHA256,
            'source_files_sha256': source['source_files_sha256'],
            'source_codec_xml_sha256': CODEC_BEFORE,
            'service_instance': 'android.hardware.media.c2@1.0::IComponentStore/dolby',
            'mime_types': ['audio/ac3', 'audio/eac3', 'audio/eac3-joc', 'audio/ac4'],
            'files_sha256': dict(sorted(hashes.items()))}


def files():
    """Ship the same authenticated image assets with the offline Core package."""
    receipt = image_receipt()
    return {'audio-codecs/decoder.payload': PAYLOAD.read_bytes(),
            'audio-codecs/image.json': (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode()}


def build_vendor(source, destination, work):
    """Retain the vendor tree and install the service before VINTF is cached."""
    from build_image import erofs
    from erofs_image import build
    replacements = image_replacements(erofs(source, '/etc/media_codecs.xml'))
    build(destination, [('', source)], work, replacements,
          directory_label='u:object_r:vendor_file:s0')
    receipt = image_receipt()
    for path, checksum in receipt['files_sha256'].items():
        if _sha256(erofs(destination, path.removeprefix('/vendor'))) != checksum:
            raise RuntimeError('Baked Dolby codec verification failed: ' + path)
    return receipt
