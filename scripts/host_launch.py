"""Start an owned Emulator in the macOS GUI launchd domain, outside its caller."""
from dataclasses import dataclass
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

LAUNCHCTL = '/bin/launchctl'
LABEL_PREFIX = 'org.hyperos-avd.emulator.'
ENVIRONMENT_KEYS = frozenset({
    'HOME', 'USER', 'LOGNAME', 'TMPDIR', 'PATH', 'LANG', 'LC_CTYPE', 'LC_ALL',
    'ANDROID_HOME', 'ANDROID_SDK_ROOT', 'ANDROID_AVD_HOME', 'ANDROID_USER_HOME',
    'ANDROID_EMULATOR_HOME', 'ANDROID_EMULATOR_USE_SYSTEM_LIBS',
    'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'DYLD_FALLBACK_LIBRARY_PATH',
    'HYPEROS_AVD_SRGB', 'HYPEROS_AVD_SRGB_AVD',
    'QT_QPA_PLATFORM', 'QT_QPA_PLATFORM_PLUGIN_PATH', 'QT_PLUGIN_PATH',
    'QT_LOGGING_RULES', 'QT_SCALE_FACTOR', 'QT_AUTO_SCREEN_SCALE_FACTOR',
    'QT_ENABLE_HIGHDPI_SCALING', 'QT_FONT_DPI',
    'VK_ICD_FILENAMES', 'VK_DRIVER_FILES', 'VK_LAYER_PATH', 'VK_INSTANCE_LAYERS',
})

GUI_APP_NAME = 'HyperOS-AVD.app'
GUI_APP_IDENTIFIER = 'org.hyperos-avd.gui-launcher'
GUI_APP_INFO = {'CFBundleIdentifier': GUI_APP_IDENTIFIER, 'CFBundleName': 'HyperOS-AVD',
                'CFBundleVersion': '1',
                'NSRemovableVolumesUsageDescription':
                'Run your Android virtual device and preserve its data on your external disk.',
                'NSCameraUsageDescription': 'Use the selected webcam in your Android virtual device.',
                'NSMicrophoneUsageDescription': 'Use the microphone in your Android virtual device.'}
GUI_APP_SOURCE = '''use framework "Foundation"
use scripting additions
on run
    activate
    set launchArguments to (current application's NSProcessInfo's processInfo()'s arguments()) as list
    if (count launchArguments) < 3 then return
    set pythonPath to item 2 of launchArguments
    set requestPath to item 3 of launchArguments
    set resourcePath to (current application's NSBundle's mainBundle()'s resourcePath()) as text
    try
        do shell script (quoted form of pythonPath) & " -I -B " & (quoted form of (resourcePath & "/runner.py")) & " " & (quoted form of requestPath)
    on error launchError
        log launchError
    end try
end run
'''
GUI_RUNNER = '''"""Supervise only a private, explicitly requested Emulator child."""
import hashlib, json, os, pathlib, re, stat, subprocess, sys, tempfile
path = pathlib.Path(sys.argv[1])
directory = path.parent
parent_info = directory.lstat()
if (not directory.is_absolute() or str(directory.resolve()) != str(directory)
        or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid()
        or stat.S_IMODE(parent_info.st_mode) != 0o700):
    raise SystemExit('Refused an unsafe GUI launch state directory.')
info = path.lstat()
if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536):
    raise SystemExit('Refused an unsafe GUI launch request.')
data = json.loads(path.read_text())
keys = {'schema', 'uid', 'label', 'token', 'command', 'environment', 'workspace', 'name', 'port', 'log', 'report'}
if (not isinstance(data, dict) or set(data) != keys or type(data['schema']) is not int
        or data['schema'] != 1 or type(data['uid']) is not int or data['uid'] != os.getuid()
        or not isinstance(data['label'], str) or not re.fullmatch(r'org\\.hyperos-avd\\.emulator\\.[0-9a-f]{24}', data['label'])
        or not isinstance(data['token'], str) or not re.fullmatch(r'[0-9a-f]{32}', data['token'])
        or not isinstance(data['name'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', data['name'])
        or type(data['port']) is not int or data['port'] % 2 or not 5556 <= data['port'] <= 5682
        or not isinstance(data['workspace'], str) or '\\0' in data['workspace']
        or not pathlib.Path(data['workspace']).is_absolute()
        or not all(isinstance(data[key], str) and '\\0' not in data[key] for key in ('log', 'report'))):
    raise SystemExit('Invalid private GUI launch identity.')
stem = data['label'] + '-' + data['token']
if (path.name != stem + '.request.json' or pathlib.Path(data['log']) != path.parent / (data['label'] + '.log')
        or pathlib.Path(data['report']) != path.parent / (stem + '.run.json')):
    raise SystemExit('GUI launch state belongs to another instance.')
command = data['command']
if (not isinstance(command, list) or not command or not all(isinstance(value, str) and '\\0' not in value for value in command)
        or not pathlib.Path(command[0]).is_absolute() or pathlib.Path(command[0]).name != 'emulator'):
    raise SystemExit('Invalid SDK Emulator command.')
for option, value in (('-avd', data['name']), ('-sysdir', str(pathlib.Path(data['workspace']) / 'images')), ('-port', str(data['port']))):
    if command.count(option) != 1 or command.index(option) + 1 >= len(command) or command[command.index(option) + 1] != value:
        raise SystemExit('GUI request does not match the owned AVD.')
if not isinstance(data['environment'], dict) or not all(isinstance(key, str) and isinstance(value, str) and '\\0' not in value for key, value in data['environment'].items()):
    raise SystemExit('Invalid GUI launch environment.')
log = pathlib.Path(data['log'])
entry = log.lstat()
if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid() or entry.st_nlink != 1 or stat.S_IMODE(entry.st_mode) != 0o600):
    raise SystemExit('Refused an unsafe GUI Emulator output.')
descriptor = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
opened = os.fstat(descriptor)
if (opened.st_ino, opened.st_dev) != (entry.st_ino, entry.st_dev):
    os.close(descriptor)
    raise SystemExit('GUI Emulator output changed during preparation.')
with os.fdopen(descriptor, 'ab') as output:
    try:
        process = subprocess.Popen(command, env=data['environment'], stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
    except OSError as error:
        output.write(('Native GUI Emulator launch failed: ' + str(error) + '\\n').encode())
        output.flush()
        raise SystemExit(1)
    report = {'schema': 1, 'token': data['token'], 'pid': process.pid, 'supervisor_pid': os.getpid(), 'command_sha256': hashlib.sha256(json.dumps(command, separators=(',', ':')).encode()).hexdigest()}
    destination = pathlib.Path(data['report'])
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix='.gui-report-', dir=path.parent)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(report, stream)
            stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, destination)
    except OSError as error:
        output.write(('Native GUI child report could not be published; keeping its supervisor alive: ' + str(error) + '\\n').encode())
        output.flush()
    finally:
        try:
            if temporary is not None:
                pathlib.Path(temporary).unlink(missing_ok=True)
        finally:
            exit_code = process.wait()
    raise SystemExit(exit_code)
'''


@dataclass(frozen=True)
class LaunchResult:
    pid: int
    service: str


def selected_environment(environment):
    """Persist only host rendering/Android settings, excluding caller credentials."""
    selected = {}
    for key, value in environment.items():
        if key not in ENVIRONMENT_KEYS and not re.fullmatch(r'MVK_CONFIG_[A-Z0-9_]+', key):
            continue
        if not isinstance(value, str) or '\0' in value:
            raise RuntimeError('Invalid Emulator environment value: ' + key)
        selected[key] = value
    return selected


def owned_directory(path, private=False):
    if path.is_symlink():
        raise RuntimeError('Refused an aliased host launch directory: ' + str(path))
    path.mkdir(exist_ok=True)
    info = path.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o022):
        raise RuntimeError('Refused an unowned or writable host launch directory: ' + str(path))
    if private:
        path.chmod(0o700)


def job_directory():
    """launchd requires real ownership; removable workspaces may disable it."""
    home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    info = home.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise RuntimeError('The current GUI user has no safely owned home directory.')
    directory = home
    for component in ('Library', 'Application Support', 'HyperOS-AVD', 'launchd'):
        directory = directory / component
        owned_directory(directory, private=component in ('HyperOS-AVD', 'launchd'))
    return directory


def owned_file(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & 0o077):
        raise RuntimeError('Refused an unowned or aliased host launch file: ' + str(path))


def write_private(path, data, expected=None):
    """Create exclusively, or replace only the exact previously owned bytes."""
    if path.exists() or path.is_symlink():
        owned_file(path)
        current = path.read_bytes()
        if current == data:
            return
        if expected is None or hashlib.sha256(current).hexdigest() != expected:
            raise RuntimeError('Preserved an unexpectedly changed host launch file: ' + str(path))
    elif expected is not None:
        raise RuntimeError('Preserved a missing previously owned host launch file: ' + str(path))
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if expected is None:
            try:
                os.link(temporary, path)
            except FileExistsError:
                owned_file(path)
                if path.read_bytes() != data:
                    raise RuntimeError('Preserved an unexpectedly created host launch file: ' + str(path))
        else:
            owned_file(path)
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise RuntimeError('Preserved an unexpectedly changed host launch file: ' + str(path))
            Path(temporary).replace(path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def control_environment():
    """Do not inject Emulator render hooks into macOS control applications."""
    environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
    if 'HOME' in os.environ:
        environment['HOME'] = os.environ['HOME']
    return environment


def app_recipe():
    return {'schema': 2, 'bundle_id': GUI_APP_IDENTIFIER,
            'information_sha256': hashlib.sha256(plistlib.dumps(GUI_APP_INFO, sort_keys=True)).hexdigest(),
            'script_sha256': hashlib.sha256(GUI_APP_SOURCE.encode()).hexdigest(),
            'runner_sha256': hashlib.sha256(GUI_RUNNER.encode()).hexdigest()}


def app_inventory(app):
    """A cached native app is executable code; reject extra or aliased entries."""
    entries = {}
    paths = (app, *app.rglob('*'))
    if len(paths) > 256:
        raise RuntimeError('Oversized GUI application cache was preserved: ' + str(app))
    for path in sorted(paths):
        info = path.lstat()
        if (info.st_uid != os.getuid() or info.st_mode & 0o022
                or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
            raise RuntimeError('Refused an unowned or aliased GUI application: ' + str(path))
        if stat.S_ISREG(info.st_mode):
            if info.st_size > 16 * 1024 * 1024:
                raise RuntimeError('Oversized GUI application resource was preserved: ' + str(path))
            entries[str(path.relative_to(app))] = {
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'mode': stat.S_IMODE(info.st_mode)}
        else:
            entries[str(path.relative_to(app))] = {'directory': True, 'mode': stat.S_IMODE(info.st_mode)}
    return entries


def gui_application(directory):
    """Compile a small native app with macOS tools, independent of CLT or SDK copies."""
    recipe = app_recipe()
    digest = hashlib.sha256(json.dumps(recipe, sort_keys=True).encode()).hexdigest()
    parent = directory.parent / 'gui-app'
    owned_directory(parent, private=True)
    cache = parent / digest
    app, receipt = cache / GUI_APP_NAME, cache / 'receipt.json'
    if cache.exists() or cache.is_symlink():
        owned_directory(cache, private=True)
        try:
            saved = json.loads(_private_bytes(receipt))
        except (OSError, ValueError) as error:
            raise RuntimeError('Unknown GUI application cache was preserved: ' + str(cache)) from error
        if not same_record(saved, dict(recipe, files=app_inventory(app))):
            raise RuntimeError('Modified GUI application cache was preserved: ' + str(cache))
        return app
    temporary = Path(tempfile.mkdtemp(prefix='.gui-app-', dir=parent))
    try:
        staged = temporary / GUI_APP_NAME
        source = temporary / 'launcher.applescript'
        write_private(source, GUI_APP_SOURCE.encode())
        compiled = subprocess.run(['/usr/bin/osacompile', '-o', str(staged), str(source)],
                                  env=control_environment(), capture_output=True, text=True, timeout=30)
        if compiled.returncode:
            raise RuntimeError('Could not create the native GUI launcher: ' +
                               (compiled.stderr or compiled.stdout).strip()[:600])
        source.unlink()
        info_path = staged / 'Contents/Info.plist'
        information = plistlib.loads(info_path.read_bytes())
        # osacompile emits generic privacy declarations for all scripting
        # additions. This app only supervises the requested SDK process.
        information = {key: value for key, value in information.items()
                       if not (key.startswith('NS') and key.endswith('UsageDescription'))}
        information.update(GUI_APP_INFO)
        info_path.write_bytes(plistlib.dumps(information, sort_keys=True))
        runner = staged / 'Contents/Resources/runner.py'
        write_private(runner, GUI_RUNNER.encode())
        signed = subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(staged)],
                                env=control_environment(), capture_output=True, text=True, timeout=30)
        if signed.returncode:
            raise RuntimeError('Could not sign the native GUI launcher: ' +
                               (signed.stderr or signed.stdout).strip()[:600])
        write_private(temporary / 'receipt.json',
                      (json.dumps(dict(recipe, files=app_inventory(staged)), sort_keys=True) + '\n').encode())
        if cache.exists() or cache.is_symlink():
            raise RuntimeError('GUI application cache appeared during preparation; it was preserved.')
        temporary.rename(cache)
        return app
    finally:
        # Only this invocation's unpublished private staging directory is disposable.
        if temporary.exists():
            shutil.rmtree(temporary)


def launch_request(directory, identity, command, environment):
    token = uuid.uuid4().hex
    stem = identity['label'] + '-' + token
    request, report = directory / (stem + '.request.json'), directory / (stem + '.run.json')
    data = {'schema': 1, 'uid': os.getuid(), 'label': identity['label'], 'token': token,
            'command': command, 'environment': environment, 'workspace': identity['workspace'],
            'name': identity['name'], 'port': identity['port'], 'log': identity['host_log'],
            'report': str(report)}
    payload = (json.dumps(data, sort_keys=True) + '\n').encode()
    if len(payload) > 65536:
        raise RuntimeError('The selected Emulator environment is too large for private GUI launch.')
    write_private(request, payload)
    return request, report, token


def reported_child(report, token, command):
    if not report.exists() and not report.is_symlink():
        return None
    try:
        data = json.loads(_private_bytes(report, limit=4096))
    except (ValueError, OSError) as error:
        raise RuntimeError('Invalid native GUI child ownership report was preserved.') from error
    if (not isinstance(data, dict) or set(data) != {'schema', 'token', 'pid', 'supervisor_pid', 'command_sha256'}
            or type(data.get('schema')) is not int or data['schema'] != 1
            or data.get('token') != token or type(data.get('pid')) is not int or data['pid'] <= 0
            or type(data.get('supervisor_pid')) is not int or data['supervisor_pid'] <= 0
            or data.get('command_sha256') != hashlib.sha256(
                json.dumps(command, separators=(',', ':')).encode()).hexdigest()):
        raise RuntimeError('Native GUI child report selects another launch; evidence was preserved.')
    return data['pid']


def child_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # An inaccessible PID cannot prove ownership or a successful child launch.
        return False
    return True


def run_control(*arguments):
    # DYLD hooks and caller secrets belong to neither launchctl nor its output.
    return subprocess.run([LAUNCHCTL, *arguments], env=control_environment(),
                          capture_output=True, text=True, timeout=15)


def control_error(action, result):
    detail = (result.stderr or result.stdout or 'No diagnostic output.').strip()
    detail = ' '.join(detail.splitlines())[:600]
    return f'{action} (launchctl exit {result.returncode}): {detail}'


def field(output, name):
    match = re.search(r'^\s*' + re.escape(name) + r' = (.+)$', output, re.MULTILINE)
    return match.group(1).strip() if match else None


def check_service(output, service, plist, executable):
    if (not output.startswith(service + ' = {') or field(output, 'path') != str(plist)
            or field(output, 'program') != str(executable)):
        raise RuntimeError('Refused a launchd service with different runtime ownership: ' + service)


def sdk_command(definition, identity):
    """Authenticate both old CLI jobs and the native Launch Services envelope."""
    arguments = definition.get('ProgramArguments')
    if (not isinstance(arguments, list) or not arguments
            or not all(isinstance(value, str) and '\0' not in value for value in arguments)):
        raise RuntimeError('Invalid saved Emulator command.')
    if definition.get('Program') == identity['executable'] and arguments[0] == identity['executable']:
        command = arguments
    elif definition.get('Program') == '/usr/bin/open':
        directory = Path(identity['working_directory'])
        if (len(arguments) < 9 or arguments[:4] != ['/usr/bin/open', '-W', '-n', '-a']
                or arguments[5] != '--args'):
            raise RuntimeError('Invalid saved native GUI launch envelope.')
        app, python, request = (Path(arguments[index]) for index in (4, 6, 7))
        expected_parent = directory.parent / 'gui-app'
        if (app.parent.parent != expected_parent or app.name != GUI_APP_NAME
                or not re.fullmatch(r'[0-9a-f]{64}', app.parent.name)
                or not python.is_absolute() or str(python.resolve()) != str(python)
                or request.parent != directory or not re.fullmatch(
                    re.escape(identity['label']) + r'-[0-9a-f]{32}\.request\.json', request.name)
                or definition.get('EnvironmentVariables') != {}):
            raise RuntimeError('Saved native GUI envelope belongs to another runtime.')
        command = arguments[8:]
        if not command or command[0] != identity['executable']:
            raise RuntimeError('Invalid saved GUI Emulator command.')
    else:
        raise RuntimeError('Saved host launch ownership does not match this runtime.')
    for option, expected in (('-avd', identity['name']), ('-sysdir', identity['images']),
                             ('-port', str(identity['port']))):
        if command.count(option) != 1 or command.index(option) + 1 >= len(command):
            raise RuntimeError('Invalid saved Emulator ownership arguments.')
        if command[command.index(option) + 1] != expected:
            raise RuntimeError('Saved Emulator arguments select another runtime.')
    return command


def saved_program(plist, identity):
    """Read only the checked envelope; receipt validation still precedes bootout."""
    if not plist.exists() and not plist.is_symlink():
        return identity['executable']
    try:
        definition = plistlib.loads(_private_bytes(plist))
    except (OSError, ValueError) as error:
        raise RuntimeError('Invalid saved host launch ownership definition.') from error
    sdk_command(definition, identity)
    return definition['Program']


def validate_previous(plist, receipt, identity):
    """Only a private, authenticated record can authorize removal of an idle job."""
    try:
        owned_file(plist)
        owned_file(receipt)
    except OSError as error:
        raise RuntimeError('Missing saved host launch ownership record.') from error
    try:
        saved = json.loads(receipt.read_text())
        payload = plist.read_bytes()
    except (ValueError, plistlib.InvalidFileException) as error:
        raise RuntimeError('Invalid saved host launch ownership record.') from error
    validate_record(payload, saved, identity)


def validate_record(payload, saved, identity):
    """Verify saved definition bytes independently of their publication state."""
    try:
        definition = plistlib.loads(payload)
    except (ValueError, plistlib.InvalidFileException) as error:
        raise RuntimeError('Invalid saved host launch definition.') from error
    digest = hashlib.sha256(payload).hexdigest()
    legacy = {key: value for key, value in identity.items()
              if key not in ('working_directory', 'host_log')}
    legacy['schema'] = 1
    legacy_record = same_record(saved, dict(legacy, plist_sha256=digest))
    expected_directory = identity['workspace'] if legacy_record else identity['working_directory']
    expected_log = str(Path(identity['workspace']) / 'logs/emulator-current.log') if legacy_record else identity['host_log']
    if (not isinstance(definition, dict)
            or (not legacy_record and not same_record(saved, dict(identity, plist_sha256=digest)))
            or definition.get('Label') != identity['label']
            or definition.get('WorkingDirectory') != expected_directory
            or definition.get('StandardOutPath') != expected_log
            or definition.get('StandardErrorPath') != expected_log
            or definition.get('RunAtLoad') is not False
            or definition.get('KeepAlive') is not False):
        raise RuntimeError('Saved host launch ownership does not match this runtime.')
    if legacy_record and definition.get('Program') == '/usr/bin/open':
        raise RuntimeError('Legacy ownership cannot authorize a native GUI launch.')
    sdk_command(definition, identity)


def same_record(actual, expected):
    """Do not treat bool/float aliases as authenticated integer fields."""
    try:
        return json.dumps(actual, sort_keys=True, allow_nan=False) == json.dumps(
            expected, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        return False


def previous_job_identity(plist, receipt, identity):
    """An idle same-AVD job may retain its old console port or SDK location."""
    if (plist.with_suffix('.pending.json').exists()
            or not plist.exists() or not receipt.exists()):
        return identity
    owned_file(plist)
    owned_file(receipt)
    try:
        saved = json.loads(receipt.read_text())
        old = {key: value for key, value in saved.items() if key != 'plist_sha256'}
    except (ValueError, AttributeError) as error:
        raise RuntimeError('Invalid saved host launch ownership record.') from error
    legacy = {key: value for key, value in identity.items()
              if key not in ('working_directory', 'host_log')}
    legacy['schema'] = 1
    expected = legacy if old.get('schema') == 1 else identity
    if (set(old) != set(expected) or type(old.get('port')) is not int
            or old['port'] % 2 or not 5556 <= old['port'] <= 5682
            or not isinstance(old.get('executable'), str) or '\0' in old['executable']
            or not Path(old['executable']).is_absolute()
            or str(Path(old['executable']).resolve()) != old['executable']):
        raise RuntimeError('Unknown saved host launch ownership was preserved.')
    mutable = {'port', 'executable'}
    if not same_record({key: value for key, value in old.items() if key not in mutable},
                       {key: value for key, value in expected.items() if key not in mutable}):
        raise RuntimeError('Saved host launch ownership selects another runtime.')
    owner = dict(identity, port=old['port'], executable=old['executable'])
    validate_previous(plist, receipt, owner)
    return owner


def validate_host_log(host_log):
    if host_log.exists() or host_log.is_symlink():
        info = host_log.lstat()
        # launchd can create output before applying the job's Umask. A legacy
        # 0644 log remains private beneath the authenticated 0700 state folder;
        # preserve its bytes/permissions rather than chmod an existing leaf.
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in (0o600, 0o644)):
            raise RuntimeError('Refused an unowned or aliased Emulator host log: ' + str(host_log))


def validate_log(log, host_log):
    """An existing bridge must point exactly to this owned private log."""
    validate_host_log(host_log)
    linked = log.is_symlink()
    if linked:
        info = log.lstat()
        if info.st_uid != os.getuid() or info.st_nlink != 1 or os.readlink(log) != str(host_log):
            raise RuntimeError('Refused an unowned or foreign Emulator log link: ' + str(log))
    elif log.exists():
        info = log.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise RuntimeError('Refused an unowned or aliased Emulator log: ' + str(log))
    return linked


def managed_images(workspace):
    """Recognize only the manager's authenticated, single-hop image link."""
    workspace = Path(workspace)

    def directory(path):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022):
            raise RuntimeError('Unverified managed Emulator image directory.')

    def record(path, maximum=4 * 1024**2):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > maximum):
            raise RuntimeError('Unverified managed Emulator image record.')
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise RuntimeError('Invalid managed Emulator image record.')
        return value

    try:
        directory(workspace)
        directory(workspace / 'local')
        directory(workspace / 'versions')
        manager = record(workspace / 'local/manager.json', 1024**2)
        version = manager.get('version')
        if (type(manager.get('schema')) is not int or manager['schema'] != 1
                or not isinstance(version, str)
                or not re.fullmatch(r'(?:pad-)?v[0-9A-Za-z_.-]{1,127}', version)):
            raise RuntimeError('Invalid managed Emulator image selection.')
        target = workspace / 'versions' / version / 'images'
        for path in (target.parent, target, target.parent / 'local'):
            directory(path)
        active = record(workspace / 'local/installed-release.json')
        frozen = record(target.parent / 'local/installed-release.json')
        if (active.get('project') != 'HyperOS-AVD' or active.get('version') != version
                or type(active.get('format')) is not int or active['format'] not in (1, 2, 3)
                or not same_record(active, frozen)):
            raise RuntimeError('Unverified managed Emulator image provenance does not match its selection.')
        link = workspace / 'images'
        info = link.lstat()
        if (not stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or os.readlink(link) not in (str(target), os.path.relpath(target, workspace))
                or link.resolve(strict=True) != target):
            raise RuntimeError('Unverified managed Emulator image link.')
    except (OSError, ValueError, TypeError) as error:
        raise RuntimeError('Unverified managed Emulator image link.') from error


def previous_log(log, host_log, identity, directory):
    """Authenticate an inactive prior identity before moving its log bridge."""
    if not log.is_symlink() or os.readlink(log) == str(host_log):
        validate_log(log, host_log)
        return host_log
    target = Path(os.readlink(log))
    pattern = re.escape(LABEL_PREFIX) + r'[0-9a-f]{24}\.log'
    if (target.parent != directory or str(target) != os.readlink(log)
            or not re.fullmatch(pattern, target.name)):
        raise RuntimeError('Refused an unowned or foreign Emulator log link: ' + str(log))
    validate_log(log, target)
    label = target.stem
    plist, receipt = directory / (label + '.plist'), directory / (label + '.json')
    owned_file(receipt)
    try:
        saved = json.loads(receipt.read_text())
        old = {key: value for key, value in saved.items() if key != 'plist_sha256'}
    except (ValueError, AttributeError) as error:
        raise RuntimeError('Invalid prior Emulator log ownership record.') from error
    keys = set(identity)
    if (set(old) != keys or type(old.get('schema')) is not int or old['schema'] != 2
            or type(old.get('uid')) is not int or old['uid'] != os.getuid()
            or old.get('label') != label or old.get('working_directory') != str(directory)
            or old.get('host_log') != str(target)
            or not isinstance(old.get('name'), str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', old['name'])
            or type(old.get('port')) is not int or old['port'] % 2
            or not 5556 <= old['port'] <= 5682):
        raise RuntimeError('Unknown prior Emulator log identity was preserved.')
    for key in ('workspace', 'avd', 'executable'):
        value = old.get(key)
        if (not isinstance(value, str) or '\0' in value or not Path(value).is_absolute()
                or str(Path(value).resolve()) != value):
            raise RuntimeError('Invalid prior Emulator log runtime path.')
    prior_root = Path(old['workspace'])
    prior_avd = prior_root / 'avd' / (old['name'] + '.avd')
    if (old['avd'] != str(prior_avd) or old['images'] != str(prior_root / 'images')
            or label != LABEL_PREFIX + hashlib.sha256(str(prior_avd).encode()).hexdigest()[:24]):
        raise RuntimeError('A foreign workspace Emulator log link was preserved.')
    if prior_root != Path(identity['workspace']):
        try:
            prior_root.lstat()
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError('A foreign workspace Emulator log link was preserved.')
    if str(Path(old['images']).resolve()) != old['images']:
        managed_images(prior_root)
    validate_previous(plist, receipt, old)
    service = 'gui/' + str(os.getuid()) + '/' + label
    existing = run_control('print', service)
    if existing.returncode == 0:
        check_service(existing.stdout, service, plist, saved_program(plist, old))
        if field(existing.stdout, 'pid') is not None or field(existing.stdout, 'state') != 'not running':
            raise RuntimeError('The prior Emulator log owner is still active; its log was preserved.')
    elif existing.returncode != 113:
        raise RuntimeError(control_error('Could not inspect the prior Emulator log owner', existing))
    validate_host_log(host_log)
    return target


def _private_bytes(path, limit=1024 * 1024):
    owned_file(path)
    if path.stat().st_size > limit:
        raise RuntimeError('Oversized host launch ownership record was preserved.')
    return path.read_bytes()


def _current_digest(path):
    if not path.exists() and not path.is_symlink():
        return None
    return hashlib.sha256(_private_bytes(path)).hexdigest()


def recover_job(plist, receipt, identity):
    """Roll forward only an authenticated interrupted definition/receipt pair."""
    pending = plist.with_suffix('.pending.json')
    if not pending.exists() and not pending.is_symlink():
        return
    payload = _private_bytes(pending)
    try:
        transaction = json.loads(payload)
        keys = {'schema', 'identity', 'plist', 'receipt', 'previous_plist', 'previous_receipt'}
        if (not isinstance(transaction, dict) or set(transaction) != keys
                or type(transaction['schema']) is not int or transaction['schema'] != 1
                or not same_record(transaction['identity'], identity)
                or not isinstance(transaction['plist'], str)
                or not isinstance(transaction['receipt'], str)):
            raise ValueError('Unknown transaction fields or runtime identity.')
        definition = transaction['plist'].encode()
        marker = transaction['receipt'].encode()
        saved = json.loads(marker)
        validate_record(definition, saved, identity)
        for key in ('previous_plist', 'previous_receipt'):
            value = transaction[key]
            if value is not None and (not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value)):
                raise ValueError('Invalid previous ownership digest.')
    except (ValueError, UnicodeError, KeyError, RuntimeError) as error:
        raise RuntimeError('Unknown pending host launch transaction was preserved.') from error
    states = []
    for path, data, key in ((plist, definition, 'previous_plist'),
                            (receipt, marker, 'previous_receipt')):
        current = _current_digest(path)
        after = hashlib.sha256(data).hexdigest()
        if current not in (transaction[key], after):
            raise RuntimeError('Modified pending host launch state was preserved: ' + str(path))
        states.append((path, data, current, after))
    for path, data, current, after in states:
        if current != after:
            write_private(path, data, expected=current)
    if _private_bytes(pending) != payload:
        raise RuntimeError('Changed pending host launch transaction was preserved.')
    pending.unlink()


def write_job(plist, receipt, identity, definition):
    """Journal both completed payloads before publishing either owned record."""
    marker = (json.dumps(dict(identity, plist_sha256=hashlib.sha256(definition).hexdigest()),
                         sort_keys=True) + '\n').encode()
    transaction = {'schema': 1, 'identity': identity, 'plist': definition.decode(),
                   'receipt': marker.decode(), 'previous_plist': _current_digest(plist),
                   'previous_receipt': _current_digest(receipt)}
    pending = plist.with_suffix('.pending.json')
    write_private(pending, (json.dumps(transaction, sort_keys=True) + '\n').encode())
    recover_job(plist, receipt, identity)


def prepare_log(log, host_log, previous_host_log=None):
    """Keep readable workspace history without making launchd open removable storage."""
    previous_host_log = previous_host_log or host_log
    linked = validate_log(log, previous_host_log)
    validate_host_log(host_log)
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    archive = log.parent / ('emulator-' + stamp + '.log')
    previous = previous_host_log.with_name(previous_host_log.stem + '-' + stamp + '.log')
    current_archive = host_log.with_name(host_log.stem + '-' + stamp + '.log')
    retry_archive = log.parent / ('emulator-retry-' + stamp + '.log')
    if archive.exists() or archive.is_symlink() or previous.exists() or previous.is_symlink():
        raise RuntimeError('Emulator log archive path already exists; evidence was preserved.')
    if previous_host_log != host_log and (current_archive.exists() or retry_archive.exists()
                                          or current_archive.is_symlink() or retry_archive.is_symlink()):
        raise RuntimeError('Emulator transition archive path already exists; evidence was preserved.')
    if previous_host_log.exists():
        previous_host_log.rename(previous)
        if linked:
            archive.symlink_to(previous)
    if previous_host_log != host_log and host_log.exists():
        host_log.rename(current_archive)
        retry_archive.symlink_to(current_archive)
    if linked:
        log.unlink()
    elif log.exists():
        log.rename(archive)
    # Creating the leaf ourselves makes private permissions independent of
    # launchd's ordering of stdio setup and process Umask.
    try:
        descriptor = os.open(host_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError as error:
        raise RuntimeError('Emulator host log appeared during preparation; it was preserved.') from error
    else:
        os.close(descriptor)
    log.symlink_to(host_log)


def start(root, config, command, environment, log):
    """Never kill a running/foreign job, restart on failure, or inherit the caller's coalition."""
    if platform.system() != 'Darwin':
        raise RuntimeError('Detached Emulator launch requires a macOS GUI session.')
    selected = selected_environment(environment)
    root = Path(root).resolve()
    name, port = config.get('name'), config.get('port')
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name)
            or isinstance(port, bool) or not isinstance(port, int) or port % 2
            or not 5556 <= port <= 5682):
        raise RuntimeError('Invalid owned Emulator runtime identity.')
    executable = (Path(config['sdk']).resolve() / 'emulator/emulator')
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError('Missing SDK Emulator executable.')
    avd = root / 'avd' / (name + '.avd')
    if avd.is_symlink() or not (avd / 'config.ini').is_file():
        raise RuntimeError('Missing owned Emulator configuration.')
    if not isinstance(command, list) or not command or command[0] != str(executable):
        raise RuntimeError('Emulator command does not match this SDK runtime.')
    for option, expected in (('-avd', name), ('-sysdir', str(root / 'images')), ('-port', str(port))):
        if (command.count(option) != 1 or command.index(option) + 1 >= len(command)
                or command[command.index(option) + 1] != expected):
            raise RuntimeError('Emulator command does not match the owned AVD.')
    log = Path(log)
    if log.parent != root / 'logs' or log.name != 'emulator-current.log':
        raise RuntimeError('Emulator log must belong to this workspace.')
    owned_directory(root / 'logs')
    directory = job_directory()
    owned_directory(directory, private=True)
    digest = hashlib.sha256(str(avd).encode()).hexdigest()[:24]
    label = LABEL_PREFIX + digest
    domain = 'gui/' + str(os.getuid())
    service = domain + '/' + label
    plist, receipt = directory / (label + '.plist'), directory / (label + '.json')
    host_log = directory / (label + '.log')
    identity = {'schema': 2, 'uid': os.getuid(), 'label': label, 'workspace': str(root),
                'name': name, 'port': port, 'images': str(root / 'images'),
                'avd': str(avd), 'executable': str(executable),
                'working_directory': str(directory), 'host_log': str(host_log)}
    lock = directory / 'launch.lock'
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        owned_file(lock)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('Another owned Emulator launch is already being prepared.') from error
        previous_host_log = previous_log(log, host_log, identity, directory)
        session = run_control('print', domain)
        if session.returncode:
            raise RuntimeError(control_error('No logged-in macOS GUI launchd session; Emulator was not started', session))
        prior_identity = previous_job_identity(plist, receipt, identity)
        existing = run_control('print', service)
        if existing.returncode == 0:
            check_service(existing.stdout, service, plist, saved_program(plist, prior_identity))
            if field(existing.stdout, 'pid') is not None or field(existing.stdout, 'state') != 'not running':
                raise RuntimeError('This Emulator launchd job is still active; no process was stopped.')
        elif existing.returncode != 113:
            # An inaccessible service never authorizes ownership recovery or
            # replacement of a possibly active job.
            raise RuntimeError(control_error('Could not inspect the owned Emulator launchd job', existing))
        recover_job(plist, receipt, identity)
        if existing.returncode == 0:
            validate_previous(plist, receipt, prior_identity)
            removed = run_control('bootout', service)
            if removed.returncode:
                raise RuntimeError(control_error('Could not remove the owned idle Emulator job; no replacement was started', removed))
        elif any(path.exists() or path.is_symlink() for path in (plist, receipt)):
            validate_previous(plist, receipt, prior_identity)
        elif host_log.exists() or host_log.is_symlink() or (log.is_symlink() and previous_host_log == host_log):
            raise RuntimeError('Emulator log ownership record is missing; existing evidence was preserved.')
        app = gui_application(directory)
        request, report, token = launch_request(directory, identity, command, selected)
        gui_command = ['/usr/bin/open', '-W', '-n', '-a', str(app), '--args',
                       str(Path(sys.executable).resolve()), str(request), *command]
        definition = {'Label': label, 'Program': '/usr/bin/open', 'ProgramArguments': gui_command,
                      'WorkingDirectory': str(directory), 'EnvironmentVariables': {},
                      'StandardOutPath': str(host_log), 'StandardErrorPath': str(host_log), 'Umask': 0o077,
                      'RunAtLoad': False, 'KeepAlive': False, 'ProcessType': 'Interactive',
                      'LimitLoadToSessionType': 'Aqua'}
        payload = plistlib.dumps(definition, sort_keys=True)
        write_job(plist, receipt, identity, payload)
        prepare_log(log, host_log, previous_host_log)
        registered = run_control('bootstrap', domain, str(plist))
        if registered.returncode:
            raise RuntimeError(control_error('Could not register the owned GUI Emulator job at ' + str(plist), registered))
        launched = run_control('kickstart', '-p', service)
        if launched.returncode or not re.fullmatch(r'[1-9][0-9]*\s*', launched.stdout):
            raise RuntimeError(control_error('GUI Emulator launch failed; its ownership record and log were retained: ' + str(log), launched))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            running = run_control('print', service)
            if running.returncode == 0:
                check_service(running.stdout, service, plist, '/usr/bin/open')
                current_pid = field(running.stdout, 'pid')
                if (field(running.stdout, 'state') == 'running'
                        and current_pid and re.fullmatch(r'[1-9][0-9]*', current_pid)):
                    child_pid = reported_child(report, token, command)
                    if child_pid is not None and child_alive(child_pid):
                        return LaunchResult(child_pid, service)
                exit_code = field(running.stdout, 'last exit code')
                if (current_pid is None and field(running.stdout, 'state') == 'not running'
                        and exit_code and re.fullmatch(r'-?[0-9]+', exit_code)):
                    break
            time.sleep(0.1)
        raise RuntimeError('GUI Emulator did not remain running or publish its owned child. '
                           'Allow HyperOS-AVD external-disk access if macOS asks, then inspect ' + str(log))
    finally:
        os.close(descriptor)
