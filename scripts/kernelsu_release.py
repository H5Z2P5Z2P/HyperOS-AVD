"""Pinned current OS4 KernelSU assets; legacy release contracts stay immutable."""
from pathlib import Path
import stat

from common import KSU_ASSETS, sha256

VERSION = 'v3.3.1'
CODE = 32680
DIRECTORY = 'kernelsu-v3.3.1'
MANAGER = 'KernelSU_v3.3.1_32680-release.apk'
LKM = 'lkm-aarch64-android15-6.6_kernelsu.ko'
REVIEW_COMMIT = '0c0fdb960178fa12d80d6cbcfdcb6ad8be6a865d'
ASSETS = {
    MANAGER: 'b4a059ace71de2fa65cc7f12b1c58d55fc23ab25e057ee4230ce779742abe450',
    'ksud-aarch64-apple-darwin': '6ccadcf7a903f7dbceae053d1793722e18ae401abfdd39b96bf9661658a3c4ed',
    'ksud-aarch64-linux-android': '049491e2b4cc0a6c913d3920cb90b8c94c9e8ca96c0ee92818293304973bfb1b',
    LKM: 'e57ce23de951be6b0dee5030f6724322fed126aa4af71828994437bfb0bb61ad',
}
RUNTIME_ASSETS = (MANAGER, 'ksud-aarch64-linux-android', LKM)
MANAGER_CERTIFICATE = 'c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6'
# Manager installs its own release build of the same ARM64 daemon. These
# members are authenticated by the pinned official, unchanged signed APKs.
MANAGER_DAEMON = 'lib/arm64-v8a/libksud.so'
LEGACY_MANAGER_DAEMON = '99aaa607e9c9da6a0e898366ecf0a14dd67224ea726d952d1ce575e62d3b5c41'
CURRENT_MANAGER_DAEMON = '4f7d5fd65631915ea579ff406bd9cbe58217f2c91dac6527f5b2f28ad4508171'
LEGACY_DAEMONS = frozenset((KSU_ASSETS['ksud-aarch64-linux-android'], LEGACY_MANAGER_DAEMON))
CURRENT_DAEMONS = frozenset((ASSETS['ksud-aarch64-linux-android'], CURRENT_MANAGER_DAEMON))


def asset(workspace, name):
    """Authenticate one regular offline attachment before using it."""
    if name not in ASSETS:
        raise RuntimeError('Unknown current KernelSU asset.')
    directory = Path(workspace) / 'tools' / DIRECTORY
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError('Missing or aliased current KernelSU assets.')
    path = directory / name
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or sha256(path) != ASSETS[name]):
        raise RuntimeError('Current KernelSU attachment differs from its official pin: ' + name)
    return path


def available(workspace):
    """Missing old bundles retain their legacy bootstrap; partial caches refuse."""
    directory = Path(workspace) / 'tools' / DIRECTORY
    if not directory.exists() and not directory.is_symlink():
        return False
    for name in RUNTIME_ASSETS:
        asset(workspace, name)
    return True


def fetch(workspace, names=tuple(ASSETS)):
    """Producer-only download of the exact official release, with no pin refresh."""
    from https_transport import secure_urlretrieve
    directory = Path(workspace) / 'tools' / DIRECTORY
    if directory.is_symlink():
        raise RuntimeError('Refused an aliased KernelSU asset directory.')
    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        if name not in ASSETS:
            raise RuntimeError('Unknown current KernelSU download.')
        path = directory / name
        if not path.exists() and not path.is_symlink():
            temporary = path.with_name(name + '.part')
            if temporary.exists() or temporary.is_symlink():
                raise RuntimeError('Current KernelSU download is already pending.')
            secure_urlretrieve(f'https://github.com/tiann/KernelSU/releases/download/{VERSION}/{name}', temporary)
            if sha256(temporary) != ASSETS[name]:
                temporary.unlink()
                raise RuntimeError('Current KernelSU download checksum mismatch.')
            temporary.replace(path)
        selected = asset(workspace, name)
        if name.startswith('ksud-'):
            selected.chmod(0o755)
    return directory
