"""Compile reversible, signed OEM package policies for the shared OS4 Core."""
import hashlib
from pathlib import Path

PACKAGE = 'com.xiaomi.finddevice'
SIGNER_HEX_SHA256 = '5182118e35ce40ff79ab514b4b0bece27fc4c7a43f22832b40856007731a6004'
SIGNER_BYTES = 1136
PROFILES = {
    'finddevice': {'package': PACKAGE, 'signer': SIGNER_HEX_SHA256,
                   'signer_bytes': SIGNER_BYTES, 'apk': 'any', 'operation': 'hide'},
    'vendor-ims': {'package': 'com.xring.ims',
                   'signer': 'e0a4d1b2d5d79b86daf329fc1c75af7b237691acde120f8c1bf53f2107ee69fd',
                   'signer_bytes': 1136,
                   'apk': '93879979a2f1ffc4922642bbf0ae81b815d470c494b58e017a7ec561a25f4494', 'operation': 'disable'},
}
ROOT = Path(__file__).resolve().parents[1]
RECOVERY = '''#!/system/bin/sh
# Restore only this module's recorded package state, including disabled boots.
BB=/data/adb/ksu/bin/busybox
DIR=/data/adb/hyperos-avd-core/@FEATURE@-policy
[ -x "$BB" ] || exit 0
for path in /data/adb/hyperos-avd-core "$DIR"; do
    [ -d "$path" ] && [ ! -L "$path" ] && [ "$("$BB" stat -c %u "$path")" = 0 ] || exit 0
done
[ -f "$DIR/helper.sh" ] && [ ! -L "$DIR/helper.sh" ] &&
    [ "$("$BB" stat -c %u:%h "$DIR/helper.sh")" = 0:1 ] || exit 0
case "$("$BB" sha256sum "$DIR/helper.sh" | "$BB" cut -d ' ' -f 1)" in
    @HELPER_SHA256@|@PREVIOUS_HELPERS@) ;;
    *) exit 0 ;;
esac
"$BB" sh "$DIR/helper.sh" boot
'''


def files(template=None):
    """Bind each disabled-boot callback to its exact canonical helper bytes."""
    directory = ROOT / 'modules/native-compat' if template is None else Path(template)
    source = (directory / 'finddevice-policy.sh').read_text()
    from native_module_history import REVIEWED
    previous = [record['policy_controls'] for record in REVIEWED if 'policy_controls' in record]
    if not previous:
        raise RuntimeError('Missing frozen package policy controls.')
    result = {}
    for feature, profile in PROFILES.items():
        pairs = sorted({(controls[feature]['helper'], controls[feature]['recovery'])
                        for controls in previous})
        helpers = '|'.join(sorted({helper for helper, _ in pairs}))
        controls = '|'.join("'" + helper + '|' + callback + "'" for helper, callback in pairs)
        recovery = RECOVERY.replace('@FEATURE@', feature).replace('@PREVIOUS_HELPERS@', helpers)
        body = source.replace('@FEATURE@', feature).replace('@PACKAGE@', profile['package'])
        body = body.replace('@SIGNER_HEX_SHA256@', profile['signer'])
        body = body.replace('@SIGNER_HEX_LENGTH@', str(profile['signer_bytes'] * 2))
        body = body.replace('@EXPECTED_APK@', profile['apk']).replace('@OPERATION@', profile['operation'])
        body = body.replace('@PREVIOUS_HELPERS@', helpers).replace('@PREVIOUS_CONTROL_PAIRS@', controls)
        body = body.replace('@RECOVERY_TEMPLATE@', recovery.rstrip('\n'))
        data = body.encode()
        result[feature + '-policy.sh'] = data
        result[feature + '-recovery.sh'] = recovery.replace('@HELPER_SHA256@',
                                                        hashlib.sha256(data).hexdigest()).encode()
    return result
