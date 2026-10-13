"""Generate the first-boot helper from complete canonical image recipes."""
import hashlib
import json
import re
import shlex

PATH = '/system/etc/hyperos-kernel-services.sh'
PROBE_PATH = '/system/bin/hyperos_kernel_probe'


def recipes():
    """Use only the image producer's fully authenticated immutable file sets."""
    from patch_boot_services import image_receipts, validate_image_receipt
    values, seen = [], set()
    for value in image_receipts():
        receipt = validate_image_receipt(value)
        pins = {item['path']: item['after'] for item in receipt['targets'].values()}
        pins[PROBE_PATH] = receipt['probe_sha256']
        if len(pins) != len(receipt['targets']) + 1 or len(pins) != 5:
            raise RuntimeError('Incomplete image kernel-service recipe.')
        for path, checksum in pins.items():
            if (not isinstance(path, str) or not re.fullmatch(r'/(?:system|system_ext|product)/[A-Za-z0-9_./-]+', path)
                    or '..' in path.split('/') or '//' in path
                    or not isinstance(checksum, str) or not re.fullmatch(r'[0-9a-f]{64}', checksum)):
                raise RuntimeError('Invalid image kernel-service prerequisite.')
        identity = hashlib.sha256(json.dumps(receipt, sort_keys=True,
                                            separators=(',', ':')).encode()).hexdigest()
        if identity in seen or any(pins == previous[1] for previous in values):
            raise RuntimeError('Duplicate image kernel-service recipe.')
        seen.add(identity)
        values.append((identity, pins))
    if not values or any(set(pins) != set(values[0][1]) for _, pins in values):
        raise RuntimeError('Missing or inconsistent image kernel-service recipes.')
    return tuple(values)


def image_script():
    """Produce a KSU-independent helper without firmware or public-model gates."""
    values = recipes()
    paths = sorted(values[0][1])
    lines = ['''#!/system/bin/sh
# Generated from canonical boot-service receipts; no userdata dependency.
diagnostic() {
    echo "HyperOS kernel capabilities: $2" >&2
    if [ -x /system/bin/log ]; then
        /system/bin/log -p "$1" -t HyperOSAVDKernel "$2" 2>/dev/null || :
    fi
}
skip() { diagnostic w "skip ($1)"; exit 0; }
failed() { diagnostic e "failed ($1)"; exit 1; }
[ "$(id -u)" = 0 ] || skip non-root
[ "$(getprop ro.boot.hardware)" = ranchu ] || skip unsupported-hardware
[ "$(getprop ro.product.cpu.abi)" = arm64-v8a ] &&
    [ "$(uname -m)" = aarch64 ] || skip unsupported-abi
file_sha() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] || return 1
    sha256sum "$1" 2>/dev/null | cut -d ' ' -f 1
}
''']
    for index, path in enumerate(paths):
        lines.append(f'pin{index}=$(file_sha {shlex.quote(path)}) || skip missing-or-aliased-prerequisite\n')
    key = ':'.join(f'$pin{index}' for index in range(len(paths)))
    lines.append(f'case "{key}" in\n')
    for identity, pins in values:
        pattern = ':'.join(pins[path] for path in paths)
        lines.append(f'    {pattern}) recipe={identity} ;;\n')
    lines.append('''    *) skip unknown-mixed-or-incomplete-image-recipe ;;
esac
''')
    lines.append(f'PROBE={shlex.quote(PROBE_PATH)}\n')
    lines.append('''[ -x "$PROBE" ] || skip nonexecutable-probe
diagnostic i "verified recipe $recipe"
"$PROBE" "$(getprop ro.millet.netlink)"
result=$?
case "$result" in
    0) setprop sys.hyperos_avd.millet_supported 1 || failed millet-property ;;
    2)
        setprop sys.hyperos_avd.millet_supported 0 || failed millet-property
        setprop ctl.stop millet_monitor || failed millet-stop
        ;;
    *) failed millet-probe ;;
esac
"$PROBE" gnss-extension
result=$?
case "$result" in
    0) ;;
    2) setprop ctl.stop loc_sys_service || failed gnss-stop ;;
    *) failed gnss-probe ;;
esac
''')
    return ''.join(lines).encode()


def image_script_sha256():
    return hashlib.sha256(image_script()).hexdigest()


def accepted_hashes(build=None):
    """Keep only the published source's frozen helper compatibility exception."""
    values = [image_script_sha256()]
    if build is not None and build.get('boot_service_fix') is not None:
        from phone_profile import profile, profile_from_build
        from patch_boot_services import image_receipt, validate_image_receipt
        selected = profile_from_build(build)
        historical = profile('4.0.18.0.XFRCNXM')
        marker = build.get('boot_service_fix')
        if (selected == historical and marker is not None
                and validate_image_receipt(marker) == image_receipt()):
            from apply_boot_service_fix import KERNEL_SCRIPT_HASHES, KERNEL_SCRIPT_SHA256
            values.extend((KERNEL_SCRIPT_SHA256,) if build.get('boot_policy') is not None
                          else KERNEL_SCRIPT_HASHES)
    return tuple(dict.fromkeys(values))
