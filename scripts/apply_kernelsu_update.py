"""Update only authenticated OS4 KernelSU userspace, retaining profiles and modules."""
import hashlib
import os
import shlex
import stat
import uuid
from pathlib import Path

from common import KSU_ASSETS, adb
from apply_flutter_fix import root
import kernelsu_release as release

PACKAGE = 'me.weishu.kernelsu'
LEGACY_MANAGER = 'KernelSU_v3.3.0_32601-release.apk'


def bootstrap(workspace):
    """Old immutable bundles keep their original bootstrap without downloads."""
    workspace = Path(workspace)
    if release.available(workspace):
        return release.asset(workspace, 'ksud-aarch64-linux-android'), release.asset(workspace, release.MANAGER)
    return workspace / 'tools/ksud-aarch64-linux-android', workspace / 'tools' / LEGACY_MANAGER


def _fresh_bootstrap_command(remote, digest, token):
    """Official install is permitted only with no existing persistent state."""
    remote = shlex.quote(remote)
    return f'''set -eu
refuse() {{ printf '%s\\n' 'Existing or unverified KernelSU state was preserved; authorize the existing su installation instead.' >&2; exit 41; }}
[ "$(id -u)" = 0 ] || refuse
[ "$(getenforce)" = Enforcing ] || refuse
[ -f {remote} ] && [ ! -L {remote} ] && [ "$(stat -c %h {remote})" = 1 ] || refuse
[ "$(sha256sum {remote} | cut -d ' ' -f 1)" = {digest} ] || refuse
if [ -e /data/adb ] || [ -L /data/adb ]; then
    [ -d /data/adb ] && [ ! -L /data/adb ] || refuse
    [ "$(stat -c %u:%g:%a /data/adb)" = 0:0:700 ] || refuse
    # Any daemon, helper, module, allowlist/profile, or unknown hidden file is
    # user state. Never call install() merely because an existing su denied us.
    entries=$(find /data/adb -mindepth 1 -maxdepth 1 -print) || refuse
    [ -z "$entries" ] || refuse
fi
{remote} install || refuse
[ -f /data/adb/ksud ] && [ ! -L /data/adb/ksud ] || refuse
# Official releases install the daemon privately (700) or readably (755).
case "$(stat -c %u:%g:%a:%h /data/adb/ksud)" in
    0:0:700:1|0:0:755:1) ;;
    *) refuse ;;
esac
[ "$(sha256sum /data/adb/ksud | cut -d ' ' -f 1)" = {digest} ] || refuse
printf '%s\\n' {shlex.quote(token)}
exit 0
'''


def initialize_fresh(config, binary):
    """Bootstrap fresh userdata; a failed su never authorizes an existing reset."""
    binary = Path(binary)
    info = binary.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or not 0 < info.st_size < 16 * 1024**2):
        raise RuntimeError('Refused an unverified KernelSU bootstrap binary.')
    descriptor = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as source:
        opened = os.fstat(source.fileno())
        body = source.read(16 * 1024**2)
        after = os.fstat(source.fileno())
    stable = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink')
    digest = hashlib.sha256(body).hexdigest()
    if ((opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
            or len(body) != info.st_size
            or any(getattr(opened, key) != getattr(after, key) for key in stable)
            or digest not in (KSU_ASSETS['ksud-aarch64-linux-android'],
                              release.ASSETS['ksud-aarch64-linux-android'])):
        raise RuntimeError('Unknown or changed KernelSU bootstrap binary was preserved.')
    remote = '/data/local/tmp/hyperos-avd-bootstrap-' + uuid.uuid4().hex
    token = 'HYPEROS_AVD_FRESH_KSU_' + uuid.uuid4().hex
    try:
        adb(config, 'push', str(binary), remote, check=True, capture_output=True, timeout=30)
        selected = shlex.quote(remote)
        adb(config, 'shell', f'[ -f {selected} ] && [ ! -L {selected} ] && '
            f'[ "$(stat -c %h {selected})" = 1 ] && '
            f'[ "$(sha256sum {selected} | cut -d \' \' -f 1)" = {digest} ] && chmod 700 {selected}',
            check=True, capture_output=True, text=True, timeout=15)
        result = adb(config, 'shell', selected + ' debug su',
                     input=_fresh_bootstrap_command(remote, digest, token),
                     text=True, capture_output=True, timeout=30)
        if result.returncode or token not in result.stdout.splitlines():
            detail = (result.stderr or result.stdout).strip()[:600]
            raise RuntimeError('KernelSU fresh bootstrap was not confirmed; existing state was preserved: ' + detail)
    finally:
        adb(config, 'shell', 'rm -f ' + shlex.quote(remote), timeout=15)


def _hash(config, path):
    selected = shlex.quote(path)
    value = root(config, f'if [ -f {selected} ] && [ ! -L {selected} ] && '
                 f'[ "$(stat -c %h {selected})" = 1 ]; then sha256sum {selected}; '
                 'else printf unavailable; fi').split()
    return value[0] if value else None


def _stage(config, source, execute):
    remote = '/data/local/tmp/hyperos-avd-ksu-' + uuid.uuid4().hex
    adb(config, 'push', str(source), remote, check=True, capture_output=True, timeout=30)
    try:
        command = f'''set -e
[ -f {remote} ] && [ ! -L {remote} ] && [ "$(stat -c %h {remote})" = 1 ]
[ "$(sha256sum {remote} | cut -d ' ' -f 1)" = {release.ASSETS[source.name]} ]
chmod 700 {remote}
''' + execute(remote)
        return root(config, command)
    finally:
        adb(config, 'shell', 'rm -f ' + remote, timeout=15)


def _replace_daemon(remote, before=None):
    """Publish on /data/adb atomically without rewriting tools or loaded inodes."""
    before = KSU_ASSETS['ksud-aarch64-linux-android'] if before is None else before
    if before not in release.LEGACY_DAEMONS:
        raise RuntimeError('Unreviewed KernelSU daemon was preserved.')
    after = release.ASSETS['ksud-aarch64-linux-android']
    return f'''[ -d /data/adb ] && [ ! -L /data/adb ]
[ "$(stat -c %u:%g:%a /data/adb)" = 0:0:700 ]
[ -f /data/adb/ksud ] && [ ! -L /data/adb/ksud ]
[ "$(stat -c %u:%g:%a:%h /data/adb/ksud)" = 0:0:755:1 ]
[ "$(ls -Zd /data/adb/ksud | cut -d ' ' -f 1)" = u:object_r:ksu_file:s0 ]
[ "$(sha256sum /data/adb/ksud | cut -d ' ' -f 1)" = {before} ]
staged=$(mktemp /data/adb/.hyperos-avd-ksud-XXXXXXXX)
trap 'rm -f "$staged"' EXIT HUP INT TERM
cat {remote} > "$staged"
chown 0:0 "$staged"
chmod 755 "$staged"
chcon u:object_r:ksu_file:s0 "$staged"
[ "$(sha256sum "$staged" | cut -d ' ' -f 1)" = {after} ]
[ "$(stat -c %d "$staged")" = "$(stat -c %d /data/adb/ksud)" ]
[ -f /data/adb/ksud ] && [ ! -L /data/adb/ksud ]
[ "$(stat -c %u:%g:%a:%h /data/adb/ksud)" = 0:0:755:1 ]
[ "$(sha256sum /data/adb/ksud | cut -d ' ' -f 1)" = {before} ]
mv -f "$staged" /data/adb/ksud
'''


def _confirm_manager(config):
    confirmed = adb(config, 'shell', 'pm path ' + PACKAGE, check=True,
                    capture_output=True, text=True, timeout=15).stdout.strip()
    if (not confirmed.startswith('package:/') or '\n' in confirmed
            or _hash(config, confirmed[len('package:'):]) != release.ASSETS[release.MANAGER]):
        raise RuntimeError('KernelSU Manager update was not confirmed.')


def install(config, workspace):
    """Never downgrade or replace a custom daemon/Manager; keep factory data."""
    if not release.available(workspace):
        return {'state': 'legacy', 'reason': 'current-offline-assets-unavailable'}
    result = {'version': release.VERSION, 'code': release.CODE}
    daemon = release.asset(workspace, 'ksud-aarch64-linux-android')
    current = _hash(config, '/data/adb/ksud')
    if current in release.CURRENT_DAEMONS:
        result['daemon'] = 'verified'
    elif current in release.LEGACY_DAEMONS:
        _stage(config, daemon, lambda remote: _replace_daemon(remote, current))
        if _hash(config, '/data/adb/ksud') != release.ASSETS[daemon.name]:
            raise RuntimeError('KernelSU daemon update was not confirmed.')
        result['daemon'] = 'updated'
    else:
        result['daemon'] = 'preserved-custom'
    probe = adb(config, 'shell', 'pm path ' + PACKAGE,
                capture_output=True, text=True, timeout=15)
    # AOSP/MIUI returns 1 with empty output for an absent package. Other
    # failures never prove absence and must not trigger a replacement install.
    if probe.returncode == 1 and not probe.stdout.strip() and not probe.stderr.strip():
        package = []
    elif (probe.returncode == 0 and probe.stdout.strip() and not probe.stderr.strip()
          and all(line.startswith('package:/') and '\0' not in line
                  for line in probe.stdout.strip().splitlines())):
        package = probe.stdout.strip().splitlines()
    else:
        raise RuntimeError('KernelSU Manager presence was not confirmed; existing package state was preserved.')
    manager = release.asset(workspace, release.MANAGER)
    if not package:
        _stage(config, manager, lambda remote: 'pm install -r ' + remote)
        _confirm_manager(config)
        result['manager'] = 'installed'
    elif len(package) != 1 or not package[0].startswith('package:/'):
        result['manager'] = 'preserved-custom-layout'
    else:
        active = package[0][len('package:'):]
        active_hash = _hash(config, active)
        if active_hash == release.ASSETS[release.MANAGER]:
            result['manager'] = 'verified'
        elif active_hash == KSU_ASSETS[LEGACY_MANAGER]:
            # PackageManager verifies the unchanged official certificate and
            # preserves the UID/data; never uninstall to force a replacement.
            _stage(config, manager, lambda remote: 'pm install -r ' + remote)
            _confirm_manager(config)
            result['manager'] = 'updated'
        else:
            result['manager'] = 'preserved-custom'
    return result
