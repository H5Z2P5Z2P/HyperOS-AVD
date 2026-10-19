"""Consolidated unit tests for OS4 vendor fixes: XiaoAI assistant and TinyALSA audio playback."""
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from unittest.mock import Mock, patch, patch as mock_patch

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

from patch_audio import AFTER as AUDIO_AFTER, CODE as AUDIO_CODE, patch as patch_audio
from patch_assistant import (APK, APK_SHA256, PAD_APK_SHA256, PHONE_SOURCE, PAD_SOURCE,
                             AFTER, MANIFEST, NATIVE, image_replacements, native_from_apk,
                             patch, profile)
import apply_assistant_fix
from apply_assistant_fix import BOOT_SCRIPT, boot_script
import dolby_codecs

'Guard the bounded PCM recovery patch and retained vendor ELF metadata.'

SOURCE = REPO / 'work/os4-official/work/audio-output/source/libtinyalsav2.so'

class PlaybackGuardTest(unittest.TestCase):

    def test_unknown_vendor_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Unsupported playback tinyalsa'):
            patch_audio(b'unknown vendor update')

    @unittest.skipUnless(SOURCE.is_file(), 'Verified vendor ELF is not bundled')
    def test_elf_retains_abi_and_relro(self):
        original = SOURCE.read_bytes()
        result = patch_audio(original)
        self.assertEqual(hashlib.sha256(result).hexdigest(), AUDIO_AFTER)
        self.assertEqual(patch_audio(result), result)
        changed = {i for i, (a, b) in enumerate(zip(original, result)) if a != b}
        allowed = set(range(50740, 50744)) | set(range(64 + 9 * 56, 64 + 10 * 56))
        self.assertTrue(changed <= allowed)
        self.assertEqual(result[50732:50740], original[50732:50740])
        self.assertEqual(result[64 + 6 * 56:64 + 7 * 56], original[64 + 6 * 56:64 + 7 * 56])
        self.assertEqual(result[66120:67056], original[66120:67056])
        header = struct.unpack_from('<IIQQQQQQ', result, 64 + 9 * 56)
        self.assertEqual(header, (1, 5, 98304, 98304, 98304, len(AUDIO_CODE), len(AUDIO_CODE), 16384))
        self.assertEqual(result[98304:], AUDIO_CODE)

    @unittest.skipUnless(SOURCE.is_file(), 'Verified vendor ELF is not bundled')
    def test_tampered_vendor_is_rejected(self):
        data = bytearray(SOURCE.read_bytes())
        data[-1] ^= 1
        with self.assertRaisesRegex(RuntimeError, 'Unsupported playback tinyalsa'):
            patch_audio(data)

class DolbyCodecGuardTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.payload = dolby_codecs.PAYLOAD.read_bytes()
        cls.sources, cls.manifest = dolby_codecs._read_payload(cls.payload)
        cls.catalog = cls.sources['etc/media_codecs.xml']
        cls.replacements = dolby_codecs.image_replacements(cls.catalog)

    def test_catalog_update_is_exact_and_idempotent(self):
        path = dolby_codecs.MAIN_CODEC_PATH.removeprefix('/vendor/')
        updated = self.replacements[path][0]
        self.assertEqual(dolby_codecs.image_replacements(updated), self.replacements)
        includes = [node.attrib['href'] for node in ET.fromstring(updated).findall('Include')]
        self.assertEqual(includes.count('media_codecs_dolby.xml'), 1)
        for invalid in (b'unknown vendor update', self.catalog + b'\n', updated + b'\n'):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported vendor media codec catalog'):
                dolby_codecs.image_replacements(invalid)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported HIDL Codec2 entry'):
            dolby_codecs.patch_service(b'unknown service')

    def test_service_instance_patch_preserves_the_source_layout(self):
        original = self.sources[dolby_codecs.SOURCE_SERVICE]
        patched = dolby_codecs.patch_service(original)
        self.assertEqual(hashlib.sha256(original).hexdigest(), dolby_codecs.SERVICE_BEFORE)
        self.assertEqual(hashlib.sha256(patched).hexdigest(), dolby_codecs.SERVICE_AFTER)
        self.assertEqual(len(patched), len(original))
        changed = {index for index, pair in enumerate(zip(original, patched)) if pair[0] != pair[1]}
        allowed = set(range(0x63b, 0x668)) | set(range(0x97e, 0x99a)) | set(range(0x8010, 0x82c0))
        allowed.update(index for offset, _, _ in dolby_codecs.SERVICE_SITES
                       for index in range(offset, offset + 4))
        self.assertTrue(changed <= allowed)
        immediate = lambda offset: (struct.unpack_from('<I', patched, offset)[0] >> 5) & 0xffff
        length = immediate(0x4624) // 2
        first = (immediate(0x4628) | immediate(0x4638) << 16).to_bytes(4, 'little')
        second = (immediate(0x4634) | immediate(0x463c) << 16).to_bytes(4, 'little')
        short_string = first[:3] + second
        self.assertEqual(short_string[:length], b'dolby')
        self.assertEqual(short_string[length], 0)
        self.assertIn(b'_ZN7android25GetCodec2MiComponentStoreEv\0', patched)
        self.assertNotIn(b'_ZN7android22GoldfishComponentStore6CreateEv\0', patched)
        needed = []
        for offset in range(0x8010, 0x82c0, 16):
            tag, value = struct.unpack_from('<QQ', patched, offset)
            if tag == 0:
                break
            if tag == 1:
                start = 0x57c + value
                needed.append(patched[start:patched.index(b'\0', start)].decode())
        self.assertIn('libcodec2_store_mi.so', needed)
        self.assertNotIn('libgoldfish_codec2_store.so', needed)
        self.assertTrue(all('@1.1.so' not in name and '@1.2.so' not in name for name in needed))
        self.assertEqual(dolby_codecs.patch_service(patched), patched)

    def test_component_store_registers_only_the_two_bundled_decoders(self):
        original = self.sources[dolby_codecs.STORE_SOURCE]
        patched = dolby_codecs.patch_store(original)
        self.assertEqual(hashlib.sha256(patched).hexdigest(), dolby_codecs.STORE_AFTER)
        self.assertEqual(dolby_codecs.patch_store(patched), patched)
        self.assertEqual(len(patched), len(original))
        changed = {index for index, pair in enumerate(zip(original, patched)) if pair[0] != pair[1]}
        allowed = {index for offset, _ in dolby_codecs.STORE_SITES for index in range(offset, offset + 4)}
        self.assertTrue(changed <= allowed)
        registered = []
        for start in range(0x9ec8, 0x9fa8, 28):
            instruction = struct.unpack_from('<I', patched, start + 24)[0]
            if instruction == 0xd503201f:
                continue
            self.assertEqual(instruction & 0xfc000000, 0x94000000)
            self.assertEqual(start + 24 + (instruction & 0x3ffffff) * 4, 0xbd1c)
            address = 0x3000 + ((struct.unpack_from('<I', patched, start + 4)[0] >> 10) & 0xfff)
            registered.append(patched[address:patched.index(b'\0', address)].decode())
        self.assertEqual(registered, ['libcodec2_soft_ddpdec.so', 'libcodec2_soft_ac4dec.so'])
        damaged = bytearray(original)
        damaged[-1] ^= 1
        for invalid in (b'unknown component store', damaged):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported Dolby component store'):
                dolby_codecs.patch_store(invalid)

    def test_private_elf_inventory_and_receipt_are_complete(self):
        def runpath(data):
            offset = struct.unpack_from('<Q', data, 32)[0]
            size, count = struct.unpack_from('<HH', data, 54)
            headers = [struct.unpack_from('<IIQQQQQQ', data, offset + index * size)
                       for index in range(count)]
            dynamic = next(item for item in headers if item[0] == 2)
            entries = dict(struct.unpack_from('<QQ', data, cursor)
                           for cursor in range(dynamic[2], dynamic[2] + dynamic[5], 16))
            address = entries[5] + entries[29]
            segment = next(item for item in headers
                           if item[0] == 1 and item[3] <= address < item[3] + item[5])
            start = segment[2] + address - segment[3]
            return data[start:data.index(b'\0', start)].decode()

        def loads(data):
            offset = struct.unpack_from('<Q', data, 32)[0]
            size, count = struct.unpack_from('<HH', data, 54)
            return [data[start:start + size] for index in range(count)
                    if struct.unpack_from('<I', data, start := offset + index * size)[0] == 1]

        service = dolby_codecs.SERVICE_PATH.removeprefix('/vendor/')
        libraries = [path for path in self.replacements if path.startswith('lib64/')]
        self.assertEqual(len(libraries), 56)
        self.assertTrue(all(path.startswith('lib64/hyperos-audio-codecs/') for path in libraries))
        self.assertIn('lib64/hyperos-audio-codecs/libcodec2_hidl_plugin.so', libraries)
        self.assertNotIn('lib64/hyperos-audio-codecs/libcodec2_aidl_noisurface.so', libraries)
        for path in [service, *libraries]:
            body, mode, label = self.replacements[path]
            self.assertEqual(body[:6], b'\x7fELF\x02\x01')
            self.assertEqual(struct.unpack_from('<H', body, 18)[0], 183)
            self.assertEqual(mode, 0o755 if path == service else 0o644)
            self.assertEqual(label, 'u:object_r:mediacodec_exec:s0' if path == service
                             else 'u:object_r:vendor_file:s0')
            self.assertEqual(runpath(body), '$ORIGIN/../../lib64/hyperos-audio-codecs'
                             if path == service else '$ORIGIN')
            source_path = dolby_codecs.SOURCE_SERVICE if path == service else 'lib64/' + Path(path).name
            self.assertEqual(loads(body)[:-1], loads(self.sources[source_path]))
            self.assertEqual(struct.unpack('<IIQQQQQQ', loads(body)[-1])[-1], 16384)
        body = self.replacements[service][0]
        self.assertNotIn(b'_ZN7android22GoldfishComponentStore6CreateEv\0', body)
        self.assertIn(b'_ZN7android25GetCodec2MiComponentStoreEv\0', body)
        receipt = dolby_codecs.image_receipt()
        self.assertEqual(receipt['abi'], 'arm64-v8a')
        self.assertEqual(receipt['files_sha256'], {
            '/vendor/' + path: hashlib.sha256(value[0]).hexdigest()
            for path, value in self.replacements.items()})
        package = dolby_codecs.files()
        self.assertEqual(package['audio-codecs/decoder.payload'], self.payload)
        self.assertEqual(json.loads(package['audio-codecs/image.json']), receipt)
        for value in package.values():
            if value.startswith(b'{'):
                self.assertNotIn(b'emulator-', value)
                self.assertNotIn(b'/Volumes/', value)

    def test_dolby_catalog_and_startup_use_the_shared_service(self):
        xml = ET.fromstring(dolby_codecs.CODEC_XML)
        nodes = xml.findall('./Decoders/MediaCodec')
        self.assertEqual({node.attrib['name'] for node in nodes},
                         {'c2.dolby.eac3.decoder', 'c2.dolby.ac4.decoder'})
        mimes = {node.attrib['name'] for node in xml.findall('.//Type')}
        mimes.update(node.attrib['type'] for node in nodes if 'type' in node.attrib)
        self.assertEqual(mimes, {'audio/ac3', 'audio/eac3', 'audio/eac3-joc', 'audio/ac4'})
        self.assertIsNone(xml.find('Encoders'))
        vintf = ET.fromstring(dolby_codecs.VINTF_XML)
        self.assertEqual(vintf.findtext('./hal/name'), 'android.hardware.media.c2')
        self.assertEqual(vintf.find('./hal').attrib['format'], 'hidl')
        self.assertEqual(vintf.findtext('./hal/transport'), 'hwbinder')
        self.assertEqual(vintf.findtext('./hal/version'), '1.0')
        self.assertEqual(vintf.findtext('./hal/interface/name'), 'IComponentStore')
        self.assertEqual(vintf.findtext('./hal/interface/instance'), 'dolby')
        self.assertEqual(hashlib.sha256(dolby_codecs.VINTF_XML).hexdigest(),
                         dolby_codecs.VINTF_SHA256)
        self.assertIn(b'user mediacodec\n', dolby_codecs.INIT_RC)
        self.assertIn(b'seclabel u:r:mediacodec:s0\n', dolby_codecs.INIT_RC)
        self.assertIn(b'/vendor/lib64/hyperos-audio-codecs', dolby_codecs.INIT_RC)
        runpaths = self.manifest['runpaths']
        self.assertEqual(runpaths[dolby_codecs.SOURCE_SERVICE],
                         '$ORIGIN/../../lib64/hyperos-audio-codecs')
        self.assertEqual({value for name, value in runpaths.items() if name.startswith('lib64/')},
                         {'$ORIGIN'})

    def test_modified_asset_and_unsafe_archive_members_are_rejected(self):
        changed = bytearray(self.payload)
        changed[-1] ^= 1
        with self.assertRaisesRegex(RuntimeError, 'asset SHA-256 mismatch'):
            dolby_codecs._read_payload(changed)
        for name in ('../escape.so', '/vendor/lib64/escape.so', 'lib64/nested/escape.so'):
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w') as archive:
                archive.writestr('manifest.json', '{}')
                archive.writestr(name, b'bad')
                archive.writestr('lib64/valid.so', b'bad')
            data = output.getvalue()
            with mock_patch.object(dolby_codecs, 'PAYLOAD_SHA256', hashlib.sha256(data).hexdigest()):
                with self.assertRaisesRegex(RuntimeError, 'Invalid Dolby codec asset member'):
                    dolby_codecs._read_payload(data)

'Guard the XiaoAI native patch and the unchanged signed APK boundary.'

SOURCE = REPO / 'work/os4-official/work/assistant-transition'

PAD_APK = REPO / 'work/os4-pad/work/official-tree/extract-product-c2fede3d9b16b1b5/priv-app/VoiceAssistAndroidT/VoiceAssistAndroidT.apk'

class AssistantGuardTest(unittest.TestCase):

    def test_unknown_engine_and_apk_are_rejected(self):
        for operation in (patch, native_from_apk):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported XiaoAI'):
                operation(b'unknown update')
        for source in (PHONE_SOURCE, PAD_SOURCE):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported XiaoAI APK'):
                native_from_apk(b'unknown update', source=source)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported XiaoAI firmware'):
            profile('unknown-ota')

    def test_profiles_and_default_phone_script_remain_pinned(self):
        self.assertEqual(profile(), MANIFEST)
        self.assertEqual(profile(PHONE_SOURCE), MANIFEST)
        self.assertEqual(profile(PAD_SOURCE), {**MANIFEST, 'apk_sha256': PAD_APK_SHA256})
        self.assertEqual(apply_assistant_fix.legacy_boot_script(), BOOT_SCRIPT)
        self.assertEqual(hashlib.sha256(BOOT_SCRIPT.encode()).hexdigest(), 'a07892d0f08ac8e35c87929c2a7114998ee880bfdcef89137a96d060468ddd1f')
        script = boot_script(PAD_SOURCE)
        self.assertIn('APK_HASH=' + PAD_APK_SHA256, script)
        self.assertNotIn(APK_SHA256, script)
        self.assertIn('getprop ro.boot.hardware', script)
        self.assertIn('= yingtian ]', script)
        self.assertIn('= OS4.0.15.0.XBMCNXM ]', script)
        self.assertIn('LIB_HASH=' + AFTER, script)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported XiaoAI firmware'):
            boot_script('unknown-ota')

    def test_phone_default_refuses_tablet_before_adb(self):
        import apply_flutter_fix
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'local').mkdir()
            (folder / 'local/build.json').write_text(json.dumps({'source': PAD_SOURCE}))
            with mock_patch.object(apply_flutter_fix, 'ROOT', folder), mock_patch.object(apply_flutter_fix, 'adb') as adb:
                with self.assertRaisesRegex(RuntimeError, 'firmware profile'):
                    apply_assistant_fix.install({'name': 'HyperOS_4_Pad9ProMax_API_37', 'port': 5582})
                adb.assert_not_called()

    def test_pad_disabled_module_is_preserved_without_mounts_or_files(self):
        config = {'name': 'HyperOS_4_Pad9ProMax_API_37', 'port': 5582}
        selected = profile(PAD_SOURCE)
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'local').mkdir()
            (folder / 'local/build.json').write_text(json.dumps({'source': PAD_SOURCE}))
            with mock_patch.object(apply_assistant_fix, 'ROOT', folder), mock_patch.object(apply_assistant_fix, 'official') as official, mock_patch.object(apply_assistant_fix, 'root', return_value='disable') as root, mock_patch.object(apply_assistant_fix, 'adb') as adb:
                self.assertEqual(apply_assistant_fix.install(config, sources=(PAD_SOURCE,)), {'preserved': True, 'lifecycle': ['disable']})
                official.assert_called_once_with(config, sources=(PAD_SOURCE,))
                self.assertEqual(root.call_count, 1)
                adb.assert_not_called()
                self.assertFalse((folder / 'work').exists())

    def test_pad_existing_module_checks_script_and_all_namespaces(self):
        config = {'name': 'HyperOS_4_Pad9ProMax_API_37', 'port': 5582}
        selected = profile(PAD_SOURCE)
        script_hash = hashlib.sha256(boot_script(PAD_SOURCE).encode()).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'local').mkdir()
            (folder / 'local/build.json').write_text(json.dumps({'source': PAD_SOURCE}))
            with mock_patch.object(apply_assistant_fix, 'ROOT', folder), mock_patch.object(apply_assistant_fix, 'official'), mock_patch.object(apply_assistant_fix, 'root', side_effect=['', config['name'], 'package:' + APK, PAD_APK_SHA256 + '  ' + APK, json.dumps(selected), AFTER + '  ' + NATIVE, script_hash + '  post-fs-data.sh', script_hash + '  service.sh', script_hash + '  service.sh', '', '']) as root, mock_patch.object(apply_assistant_fix, 'adb') as adb:
                self.assertEqual(apply_assistant_fix.install(config, sources=(PAD_SOURCE,)), selected)
                self.assertTrue(root.call_args_list[-2].args[1].endswith('sh ' + apply_assistant_fix.MODULE + '/service.sh'))
                command = root.call_args_list[-1].args[1]
                self.assertIn('for pid in 1 ', command)
                self.assertIn('init.svc_debug_pid.hyos_spawner', command)
                self.assertIn('pidof zygote64', command)
                self.assertIn(PAD_APK_SHA256, command)
                self.assertIn(AFTER, command)
                subprocess.run(['sh', '-n'], input=command, text=True, check=True, capture_output=True)
                adb.assert_not_called()

    def test_boot_script_is_valid_shell(self):
        for script in (BOOT_SCRIPT, boot_script(PAD_SOURCE)):
            subprocess.run(['sh', '-n'], input=script, text=True, check=True, capture_output=True)

    @unittest.skipUnless((SOURCE / 'libmglnative2.so').is_file(), 'Verified private firmware is not bundled')
    def test_pinned_engine_has_only_two_changes(self):
        original = (SOURCE / 'libmglnative2.so').read_bytes()
        result = patch(original)
        self.assertEqual(hashlib.sha256(result).hexdigest(), AFTER)
        self.assertEqual(len(result), len(original))
        changed = [index for index, (a, b) in enumerate(zip(original, result)) if a != b]
        self.assertEqual(changed, [348799, 655741, 655742, 655743])
        self.assertEqual(patch(result), result)
        tampered = bytearray(original)
        tampered[-1] ^= 1
        with self.assertRaisesRegex(RuntimeError, 'Unsupported XiaoAI'):
            patch(tampered)

    @unittest.skipUnless((SOURCE / 'VoiceAssist.apk').is_file(), 'Verified private firmware is not bundled')
    def test_image_adds_native_library_without_rewriting_apk(self):
        apk = (SOURCE / 'VoiceAssist.apk').read_bytes()
        replacements, manifest = image_replacements(apk)
        self.assertEqual(hashlib.sha256(apk).hexdigest(), APK_SHA256)
        self.assertEqual(set(replacements), {NATIVE.lstrip('/')})
        data, mode, label = replacements[NATIVE.lstrip('/')]
        self.assertEqual(hashlib.sha256(data).hexdigest(), AFTER)
        self.assertEqual((mode, label), (420, 'u:object_r:system_lib_file:s0'))
        self.assertEqual(manifest, MANIFEST)

    @unittest.skipUnless(PAD_APK.is_file(), 'Verified private tablet firmware is not bundled')
    def test_tablet_signed_apk_uses_exact_shared_native_engine(self):
        apk = PAD_APK.read_bytes()
        self.assertEqual(hashlib.sha256(apk).hexdigest(), PAD_APK_SHA256)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported XiaoAI APK'):
            native_from_apk(apk)
        replacements, manifest = image_replacements(apk, source=PAD_SOURCE)
        self.assertEqual(set(replacements), {NATIVE.lstrip('/')})
        data, mode, label = replacements[NATIVE.lstrip('/')]
        self.assertEqual(hashlib.sha256(data).hexdigest(), AFTER)
        self.assertEqual((mode, label), (420, 'u:object_r:system_lib_file:s0'))
        self.assertEqual(manifest, profile(PAD_SOURCE))
        self.assertEqual(hashlib.sha256(apk).hexdigest(), PAD_APK_SHA256)

if __name__ == '__main__':
    unittest.main()
