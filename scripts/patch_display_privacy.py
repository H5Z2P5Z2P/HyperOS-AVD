"""Cache the disabled privacy state only on audited, HAL-free ranchu vendors."""
import hashlib
from pathlib import PurePosixPath
import struct

NATIVE = '/system_ext/lib64/libmisurfaceflinger.so'
BEFORE = 'd62195eaeeaae37bf7e40aafa4d4a163c094a19b9032601e9ee7496208731d14'
AFTER = '183f84087d80c3bab117873f7b7fc3ef1bbd5c027433b96871588358496d194e'
SIZE = 685800
SYMBOL = b'_ZN7android20MiSurfaceFlingerImpl14setPrivacyModeEPKNS_17compositionengine6OutputE'
FUNCTION_ADDRESS = 0x634c4
FUNCTION_SIZE = 0x2c8
FUNCTION_BEFORE = '0f39d8bf497282125e19c36802b423db58b0736b5a23b5b7c824f8b6cb2c21f8'
FUNCTION_AFTER = 'f850bf7e8974c0ee0aa121f3d54a6a76d530828b8400fd78786bfb96d2097a0a'
SITES = ((0x636cc, bytes.fromhex('1f2003d5'), bytes.fromhex('7fba04b9')),)
HAL = 'vendor.xiaomi.hardware.display.mihwcextension.IMiHwcExtension/default'
VINTF_ROOT = '/vendor/etc/vintf'
ABSENT_VINTF = '/odm/etc/vintf'
ODM_COMPAT_LINK = ('/odm/etc', '/vendor/odm/etc')
ODM_APEX_COMPAT_LINK = ('/odm/apex', '/vendor/odm/apex')
ABSENT_DECLARATIONS = (ABSENT_VINTF, '/vendor/manifest.xml', '/odm/manifest.xml',
                       ODM_COMPAT_LINK[1] + '/vintf', ODM_APEX_COMPAT_LINK[1])
ODM_ETC_ENTRIES = ('build.prop', 'group', 'passwd', 'selinux')
# Complete vendor XML inventory, including the matrix and every fragment.
# Hashes prove declared capability absence; a temporarily unavailable service
# on physical/custom hardware never authorizes this rule.
VINTF_FILES = {
    'compatibility_matrix.xml': 'ac5bce978030483ca5de1f141ecd07a2dcb344b59103e54fb6d72f3a706743c3',
    'manifest/android.hardware.audio@7.1-impl.ranchu.xml': '6916d299d7e741199d2bd2f7a89ad66dc804fd56c908b43326a2597723d7db49',
    'manifest/android.hardware.biometrics.fingerprint-service.ranchu.xml': 'c94bb01e634fdb15f1ff78b41ec80ed1bf7a65cef7b2b160685aa1d15877c6e6',
    'manifest/android.hardware.camera.provider.ranchu.xml': '5b8bd9feefa4a490931aa20c482357f070ec9670f16d74a3e9b690f7aada91ab',
    'manifest/android.hardware.camera.provider@2.7-service-google.xml': '4d5ecfc1dd462ee7d6ef279c7f521aa59f65d93a2e4232324d81fe32cf4562f2',
    'manifest/android.hardware.drm-service.clearkey.xml': '61d138658fc2deed1ae0913b20ddb94414a60101ce0bbbbd2e63ab994fe9983a',
    'manifest/android.hardware.gnss-service.ranchu.xml': 'fe8c11dec97c36e6814b3390cecf09313848211be697bd5c793928abe47db6d2',
    'manifest/android.hardware.graphics.gralloc.ranchu.xml': '8fbb0aca4988757ecbd19a066047e504e7d53b2ebb731a1284e2bb040dd926f4',
    'manifest/android.hardware.health-service.example.xml': '6b9d7cc55c693c8ddd00fc1d972c1a878801765b4d13f18eb23e953db4c19f5e',
    'manifest/android.hardware.media.c2@1.0-service-goldfish.xml': '66b625765a215b68be443794c4bc9b1972076b365c931e81cf5a573ce33e5e23',
    'manifest/android.hardware.radio.ranchu.xml': '7952ee9b1f2e643976d4af84d382c070ee0f048406d697ce5f1b4e2eae280aa1',
    'manifest/android.hardware.security.keymint-service.xml': 'e32fd51f82182845253d9cac4539ad0078317c864ad1614f7edf19685138db9b',
    'manifest/android.hardware.security.secureclock-service.xml': 'f46ca5fbae32a642f89d4dfaa4b6623781a3df42d3608d29308c301f18c2c70b',
    'manifest/android.hardware.security.sharedsecret-service.xml': '4a695ea68f735c7501a4ee885a28ed0dee8f533b1975c4d297c896a28766b9ff',
    'manifest/android.hardware.sensors-multihal.xml': 'fcc6446c3f5a1255e423a58305924c094990acbc34c297469a0d52b097108ed3',
    'manifest/android.hardware.usb-service.example.xml': '4443e8d6b6f583d8f100eeae94968de23385ec34ac0ea21b44b386211713377a',
    'manifest/android.hardware.wifi-service.xml': 'b0244c7741b58325669b372154776f5b800f6c19c73f08688ad1aaa45ba596a8',
    'manifest/android.hardware.wifi.hostapd.xml': '2bb8b7148536575a9022ad2bb008a02ed2f0fbcec341b0efbbc5f59e470e8881',
    'manifest/android.hardware.wifi.supplicant.xml': 'caf23fceed52948fa0b76895e181c0245f7d3e4ec62c81cc1236dd24f66b46c2',
    'manifest/bluetooth-service-default.xml': 'eac01f03d104748b5fdf42ed475981b7318aecc358dd189b229f505df5423e62',
    'manifest/bluetooth_audio.xml': '2a0e267800e97c8b18c3482535dfc7ed87ad64b4463e17e4bf6a0376f6e586b8',
    'manifest/health-storage-default.xml': 'b0ef896b1a15c860f0c1eb338891ae93c051041c8fcdc8b9a3c5a2f684c9b371',
    'manifest/hwc3.xml': 'c52fbb9867de90f7aab598b11b78eef4ba93fa3d9161d210e33680d437b88e75',
    'manifest/identity-default.xml': '58375445dd5cb31c9bea43123b7fc85ff56cab185e3809ae5014cb2276ebc938',
    'manifest/lights-default.xml': '1c57b66e61cf14a8470276025540c2ac11d32ee62e2a64b53c2908b115b1495f',
    'manifest.xml': '576892119e981582299110b2f3539082f4cdee3f2005d4ba4dbf3469bfa86daf',
}

# The stock vendor APEX packages and their active device-manifest fragments
# were independently hashed. An unknown or updated APEX cannot establish HAL
# absence even when the base vendor manifest remains identical.
APEX_PACKAGES = {'/vendor/apex/com.android.hardware.authsecret.apex': 'dc1e5a3b283e31ca41c89800e84d672bec2a085be88546452118a9073331e37a',
 '/vendor/apex/com.android.hardware.cas.apex': 'c9507110e72afb923a5c9a3e62a7d46e0bac17d02468c24384876664406dfd09',
 '/vendor/apex/com.android.hardware.contexthub.apex': '6e722c3c52eeb9e2ad387c8ecef9d8f6b208187d0cf4e1abc13d980ad04e11f8',
 '/vendor/apex/com.android.hardware.dumpstate.apex': 'd11a4e45efce78cbacc9159810402fc8d64c3e15661b7144f82c402d7728fdd4',
 '/vendor/apex/com.android.hardware.gatekeeper.nonsecure.apex': '6846f957d09c588a68a011cea50a2176bdc983a6886a2a4f09f0854428cd7fa6',
 '/vendor/apex/com.android.hardware.neuralnetworks.apex': 'ac5ac44066233f72400e63b73732574668bc509373c0881ed331be7a8739be36',
 '/vendor/apex/com.android.hardware.power.apex': '53fdab77d51d74ae005432c5a90b15318eed97c23850c49e4dc9f29a7a3dcc1d',
 '/vendor/apex/com.android.hardware.rebootescrow.apex': '749c7581847a8f7ea6ce079b53446eaf980fac795caaa8b9aff6a7eebc99fbff',
 '/vendor/apex/com.android.hardware.thermal.apex': 'a90a303d5b8ee5a046e754ef0697f56738439fe5490f307230b408185870020c',
 '/vendor/apex/com.android.hardware.threadnetwork-simulation-rcp.apex': '0ad77c52de1e078bf919e7cdb9cf752d9b1df84fb58906319af89cc7e21801e9',
 '/vendor/apex/com.android.hardware.uwb.apex': '6f983e923a6ae40d292da943e4d1adf03685e2673dc30e22add1531cd697e533',
 '/vendor/apex/com.android.hardware.vibrator.apex': '25fc1c13a3ef810584c3e87009492584bf279573c683452f0839472d80539c6f',
 '/vendor/apex/com.google.android.widevine-13130248.apex': 'f5562a6f22eb0720fc62c073479c5ef061e12be10e70dfd905713a63eb98c1ed'}
APEX_FRAGMENTS = {'/apex/com.android.hardware.authsecret/etc/vintf/android.hardware.authsecret-service.example.xml': '2d66c39d747f7868aa121531c20bfb3c0cb8f8891463f327a5a22735a3cbee9f',
 '/apex/com.android.hardware.cas/etc/vintf/android.hardware.cas-service.xml': '6a7da6306427b0b96ecccaafba8cf674dd32c921676e0ea8008b300b32d6d5f4',
 '/apex/com.android.hardware.contexthub/etc/vintf/contexthub-default.xml': '7f16301a2d1c0a1c6dc360e38f17c6a0304cc5c92775ba8106230b9198942dec',
 '/apex/com.android.hardware.dumpstate/etc/vintf/dumpstate-default.xml': '772f0e23f8cae9f211048a573cc6d2fafec9b3e7ccb4cf06055894bb358f0062',
 '/apex/com.android.hardware.gatekeeper/etc/vintf/android.hardware.gatekeeper-service.nonsecure.xml': 'a423c7df569d8a26639076523b04620eb647a6fdab9486844004abb0cd9d8658',
 '/apex/com.android.hardware.gatekeeper/etc/vintf/android.hardware.security.sharedsecret-gatekeeper.xml': '81de8783e8b518e55b7994e97c93f3ee3a8885f653adb7af308012f6428766d0',
 '/apex/com.android.hardware.neuralnetworks/etc/vintf/android.hardware.neuralnetworks-service-sample-all.xml': 'ce3e7890f5d8ee8d522d7b3dd55ea1f396e01576454ff9c55f85c77c4b2e4a97',
 '/apex/com.android.hardware.neuralnetworks/etc/vintf/android.hardware.neuralnetworks-service-sample-limited.xml': 'e9fac9733f4417f4f7299538ffaf9f454fff3bbb7d1aa845a4006f5f9c2a73c9',
 '/apex/com.android.hardware.neuralnetworks/etc/vintf/android.hardware.neuralnetworks-shim-service-sample.xml': 'adcdeac34c9d8a4c4b04ac4672c7a25489ea4f2f539b5f6ab99ca36afa8f76bf',
 '/apex/com.android.hardware.power/etc/vintf/android.hardware.power.stats.xml': '158e30377461be5b80934a6129324df15e82412b8af361bf314d3131138d7054',
 '/apex/com.android.hardware.power/etc/vintf/android.hardware.power.xml': '2f01ab9e0e93a387d65951288fbb6dc306c5606f79595ff8110b539802f2cfa1',
 '/apex/com.android.hardware.rebootescrow/etc/vintf/rebootescrow-default.xml': '9595cde9731b6ab9916d8b7f73264fd2e5721716805041f1a27646f8036c897a',
 '/apex/com.android.hardware.thermal/etc/vintf/android.hardware.thermal.example.xml': '322892b97957220960b06b2090b85902b722e29fef8e00e296980e2e2ded80e8',
 '/apex/com.android.hardware.threadnetwork/etc/vintf/threadnetwork-default.xml': 'b2bfb241e8188c542e2757abeaa8c3e12b0b53672a8a9b7d996e6a92e03ec196',
 '/apex/com.android.hardware.uwb/etc/vintf/uwb-service.xml': '529da6c65992a740e75790e45262a069b09593758de3184ca803b86f3e27f0e4',
 '/apex/com.android.hardware.vibrator/etc/vintf/android.hardware.vibrator.xml': '74bbd6f1c51e8fc87fbf131d4313cb4c214470e74010558041ef09ccf27bb195',
 '/apex/com.google.android.widevine/etc/vintf/com.google.android.widevine.xml': 'dc98d59d89ac79ab822017873c0f21d15f7695b03ecb18f04303f2c8b2a28791'}


def capability_recipe():
    """Export offline data from the same reviewed vendor identities."""
    import dolby_codecs
    import patch_composer
    import patch_rear_display
    rows = ['schema|1', 'root|' + VINTF_ROOT]
    rows.extend('absent|' + path for path in ABSENT_DECLARATIONS)
    rows.append('compat-link|' + '|'.join(ODM_COMPAT_LINK))
    rows.append('compat-link|' + '|'.join(ODM_APEX_COMPAT_LINK))
    rows.append('directory|' + ODM_COMPAT_LINK[1] + '|' + ','.join(ODM_ETC_ENTRIES))
    rows.append('empty|/data/apex/active')
    trees = sorted({str(PurePosixPath(path).parent) for path in APEX_FRAGMENTS})
    rows.append('expected-trees|' + str(len(trees) + 1))
    rows.append('tree|/vendor/apex|apex-package')
    rows.extend('tree|' + path + '|apex-fragment' for path in trees)
    rows.extend('apex-package|' + path + '|' + checksum for path, checksum in sorted(APEX_PACKAGES.items()))
    rows.extend('apex-fragment|' + path + '|' + checksum for path, checksum in sorted(APEX_FRAGMENTS.items()))
    rows.extend('composer|' + patch_composer.NATIVE + '|' + checksum for checksum in
                (patch_composer.BEFORE, patch_composer.AFTER, patch_rear_display.AFTER))
    rows.extend('file|' + VINTF_ROOT + '/' + path + '|' + checksum
                for path, checksum in sorted(VINTF_FILES.items()))
    # This exact software service adds no physical display capability.
    rows.append('optional-file|' + dolby_codecs.VINTF_PATH + '|' + dolby_codecs.VINTF_SHA256)
    return ('\n'.join(rows) + '\n').encode()


def privacy_symbol(data):
    """Authenticate the exported AArch64 function and executable mapping."""
    from patch_rear_display import _sections
    if len(data) != SIZE or struct.unpack_from('<Q', data, 32)[0] != 64:
        raise RuntimeError('Unexpected display privacy ELF layout.')
    sections, names = _sections(data)
    code = names.get(b'.text')
    if code is None or code[1:6] != (1, 6, 0x40000, 0x40000, 356940):
        raise RuntimeError('Unexpected display privacy code section.')
    matches = []
    for section in sections:
        if section[1] != 11:
            continue
        if section[9] != 24 or section[5] % 24 or section[6] >= len(sections):
            raise RuntimeError('Unexpected display privacy symbol table.')
        strings = sections[section[6]]
        if strings[1] != 3:
            raise RuntimeError('Unexpected display privacy symbol names.')
        body = data[strings[4]:strings[4] + strings[5]]
        for offset in range(section[4], section[4] + section[5], 24):
            name, info, _, index, address, size = struct.unpack_from('<IBBHQQ', data, offset)
            end = body.find(b'\0', name)
            if name >= len(body) or end < 0:
                raise RuntimeError('Invalid display privacy symbol name.')
            if body[name:end] != SYMBOL:
                continue
            if info != 0x12 or index >= len(sections) or sections[index] != code:
                raise RuntimeError('Unexpected display privacy symbol type.')
            matches.append((address, size, code[4] + address - code[3]))
    if matches != [(FUNCTION_ADDRESS, FUNCTION_SIZE, FUNCTION_ADDRESS)]:
        raise RuntimeError('Unexpected display privacy symbol extent.')
    entry_size, count = struct.unpack_from('<HH', data, 54)
    if (entry_size, count) != (56, 12):
        raise RuntimeError('Unexpected display privacy program headers.')
    mappings = []
    for offset in range(64, 64 + entry_size * count, entry_size):
        kind, flags, start, virtual, _, length, _, _ = struct.unpack_from('<IIQQQQQQ', data, offset)
        if (kind == 1 and flags == 5 and virtual <= FUNCTION_ADDRESS
                and FUNCTION_ADDRESS + FUNCTION_SIZE <= virtual + length):
            mappings.append(start + FUNCTION_ADDRESS - virtual)
    if mappings != [FUNCTION_ADDRESS]:
        raise RuntimeError('Unexpected display privacy executable mapping.')
    return matches[0]


def patch(data):
    """Preserve all real HAL calls and nonzero requests, caching only zero.

    The absent-HAL path leaves lastPrivacyMode=-1, retrying and logging mode 0
    every frame. Store zero at that path's existing NOP; later zero requests
    take the original equality gate. Failed nonzero modes retain retries, and
    the connected HAL success path continues to store the requested mode.
    The Core runtime separately proves the reviewed ranchu vendor has no such
    declared HAL before publishing these bytes.
    """
    checksum = hashlib.sha256(data).hexdigest()
    if checksum not in (BEFORE, AFTER):
        raise RuntimeError('Unsupported display privacy SHA-256: ' + checksum)
    _, size, offset = privacy_symbol(data)
    expected = FUNCTION_AFTER if checksum == AFTER else FUNCTION_BEFORE
    if hashlib.sha256(data[offset:offset + size]).hexdigest() != expected:
        raise RuntimeError('Unexpected display privacy function body.')
    for address, before, after in SITES:
        if address % 4 or not offset <= address <= offset + size - 4:
            raise RuntimeError('Display privacy instruction exceeds audited function.')
        if data[address:address + 4] != (after if checksum == AFTER else before):
            raise RuntimeError('Unexpected display privacy disabled-state instruction.')
    if checksum == AFTER:
        return data
    result = bytearray(data)
    for address, _, replacement in SITES:
        result[address:address + len(replacement)] = replacement
    if len(result) != len(data) or hashlib.sha256(result).hexdigest() != AFTER:
        raise RuntimeError('Display privacy output checksum mismatch.')
    return bytes(result)
