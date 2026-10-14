#!/usr/bin/env python3
"""Export audited equal-size native edits for standard KernelSU delivery.

This catalog records content identities, not OTA names or device models.
Unknown binaries remain unsupported. Signed APK, image, kernel and host
patches retain their separate build routes. Audited unsigned framework JARs
use finite equal-length ZIP/DEX sites.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import re


FEATURES = frozenset(('flutter', 'hwui', 'assistant', 'lockscreen-video',
                      'navigation', 'composer', 'rear-display', 'rear-input', 'display-brightness', 'display-privacy', 'display-metadata', 'wifi-capabilities', 'xqos', 'vendor-ims', 'perf-hardware', 'thermal-monitor'))
APP_PACKAGES = frozenset(('com.miui.home', 'com.miui.weather2',
                          'com.miui.voiceassist', 'com.miui.aod'))
SLUG = re.compile(r'[a-z0-9]+(?:-[a-z0-9]+)*\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
HEX = re.compile(r'(?:[0-9a-f]{2})+\Z')
BASENAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]*\Z')
PROFILE_KEYS = frozenset(('id', 'feature', 'before', 'after', 'legacy', 'sites'))
TARGET_KEYS = frozenset(('feature', 'phase', 'kind', 'path', 'package', 'library'))


def _slug(value):
    return re.sub(r'[^a-z0-9]+', '-', value.lower()).strip('-')


def _hex(value):
    return value.hex() if isinstance(value, bytes) else value


def _profile(identifier, feature, before, after, sites, legacy=()):
    return {'id': identifier, 'feature': feature, 'before': before,
            'after': after, 'legacy': list(legacy),
            'sites': [[offset, _hex(original), _hex(replacement)]
                      for offset, original, replacement in sorted(sites)]}


def _target(feature, phase, path='', package='', library=''):
    return {'feature': feature, 'phase': phase, 'kind': 'app' if package else 'system',
            'path': path, 'package': package,
            'library': library or PurePosixPath(path).name}


def validate_catalog(value):
    """Reject unsafe targets, ambiguous content identities and overlapping edits."""
    if (not isinstance(value, dict) or set(value) != {'schema', 'profiles', 'targets'}
            or type(value['schema']) is not int or value['schema'] != 1
            or not isinstance(value['profiles'], list) or not value['profiles']
            or not isinstance(value['targets'], list) or not value['targets']):
        raise RuntimeError('Invalid native patch catalog schema.')
    identifiers, input_owners, output_owners, features = set(), {}, {}, set()
    for row in value['profiles']:
        if (not isinstance(row, dict) or set(row) != PROFILE_KEYS
                or not isinstance(row['id'], str) or not SLUG.fullmatch(row['id'])
                or row['id'] in identifiers or not isinstance(row['feature'], str)
                or row['feature'] not in FEATURES
                or not isinstance(row['legacy'], list)
                or not isinstance(row['sites'], list) or not row['sites']):
            raise RuntimeError('Invalid native patch profile.')
        identifiers.add(row['id'])
        features.add(row['feature'])
        hashes = [row['before'], row['after'], *row['legacy']]
        if (any(not isinstance(item, str) or not SHA256.fullmatch(item) for item in hashes)
                or len(hashes) != len(set(hashes))):
            raise RuntimeError('Invalid native patch profile hashes.')
        for checksum in [row['before'], *row['legacy']]:
            if checksum in input_owners:
                raise RuntimeError('Ambiguous native patch input hash.')
            input_owners[checksum] = row
        if row['after'] in output_owners:
            raise RuntimeError('Ambiguous native patch output hash.')
        output_owners[row['after']] = row
        ranges = []
        for site in row['sites']:
            if (not isinstance(site, list) or len(site) != 3 or type(site[0]) is not int
                    or not 0 <= site[0] <= 0xffffffff
                    or any(not isinstance(part, str) or not HEX.fullmatch(part) for part in site[1:])
                    or len(site[1]) != len(site[2]) or site[1] == site[2]):
                raise RuntimeError('Invalid equal-size native patch site.')
            end = site[0] + len(site[1]) // 2
            if end > 0x100000000:
                raise RuntimeError('Native patch site exceeds supported file offsets.')
            ranges.append((site[0], end))
        ranges.sort()
        if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
            raise RuntimeError('Overlapping native patch sites.')
    # Only explicit producer chains may reuse a canonical output as input.
    # Legacy aliases never authorize an additional edit.
    for checksum in output_owners.keys() & input_owners.keys():
        left, right = output_owners[checksum], input_owners[checksum]
        if ((left['feature'], right['feature']) not in (
                ('composer', 'rear-display'), ('perf-hardware', 'perf-hardware'),
                ('perf-hardware', 'thermal-monitor'), ('thermal-monitor', 'thermal-monitor'),
                ('rear-input', 'display-brightness'))
                or checksum != right['before']):
            raise RuntimeError('Ambiguous native patch hash chain.')
    for start in input_owners:
        seen, checksum = set(), start
        while checksum in input_owners:
            if checksum in seen or len(seen) >= 8:
                raise RuntimeError('Cyclic or excessive native patch hash chain.')
            seen.add(checksum)
            checksum = input_owners[checksum]['after']
    seen_targets, target_features = set(), set()
    system_targets = {}
    for row in value['targets']:
        if (not isinstance(row, dict) or set(row) != TARGET_KEYS
                or not isinstance(row['feature'], str) or row['feature'] not in features
                or row['phase'] not in ('early', 'late')
                or row['kind'] not in ('system', 'app')
                or not isinstance(row['library'], str) or not BASENAME.fullmatch(row['library'])
                or row['library'] in ('.', '..')):
            raise RuntimeError('Invalid native patch target.')
        path, package = row['path'], row['package']
        if row['feature'] == 'wifi-capabilities':
            from patch_wifi_capabilities import PATH
            if (row['kind'] != 'system' or path != PATH or row['phase'] != 'early'
                    or row['library'] != PurePosixPath(PATH).name or package != ''):
                raise RuntimeError('Unsafe unsigned framework patch target.')
        if row['feature'] == 'xqos':
            from patch_xqos import NATIVE
            if (row['kind'] != 'system' or path != NATIVE or row['phase'] != 'early'
                    or row['library'] != PurePosixPath(NATIVE).name or package != ''):
                raise RuntimeError('Unsafe physical QoS patch target.')
        if row['feature'] == 'vendor-ims':
            from patch_xiaomi_ims import PATH
            if (row['kind'] != 'system' or path != PATH or row['phase'] != 'early'
                    or row['library'] != PurePosixPath(PATH).name or package != ''):
                raise RuntimeError('Unsafe vendor IMS framework patch target.')
        if row['feature'] == 'rear-input':
            from patch_rear_input_policy import PATH
            if (row['kind'] != 'system' or path != PATH or row['phase'] != 'early'
                    or row['library'] != PurePosixPath(PATH).name or package != ''):
                raise RuntimeError('Unsafe rear input policy target.')
        if row['feature'] == 'thermal-monitor':
            from patch_thermal_capability import PATH
            if (row['kind'] != 'system' or path != PATH or row['phase'] != 'early'
                    or row['library'] != PurePosixPath(PATH).name or package != ''):
                raise RuntimeError('Unsafe board-temperature framework target.')
        if row['feature'] == 'display-brightness':
            from patch_display_brightness import PATH
            if (row['kind'] != 'system' or path != PATH or row['phase'] != 'early'
                    or row['library'] != PurePosixPath(PATH).name or package != ''):
                raise RuntimeError('Unsafe display-brightness framework target.')
        if row['feature'] == 'display-metadata':
            from patch_display_metadata import RECIPES
            if (row['kind'] != 'system' or path not in {value['path'] for value in RECIPES.values()}
                    or row['phase'] != 'early' or row['library'] != PurePosixPath(path).name or package != ''):
                raise RuntimeError('Unsafe display metadata consumer target.')
        if row['feature'] == 'perf-hardware':
            from patch_bufferqueue_perf import NATIVE as BUFFERQUEUE
            from patch_qti_perf import NATIVE as QTI
            from patch_uniperf import MIUI_SERVICES, PATH
            if (row['kind'] != 'system' or path not in (QTI, PATH, MIUI_SERVICES, BUFFERQUEUE) or row['phase'] != 'early'
                    or row['library'] != PurePosixPath(path).name or package != ''):
                raise RuntimeError('Unsafe proprietary performance patch target.')
        if row['kind'] == 'system':
            if (not isinstance(path, str) or not path.startswith(('/system/', '/system_ext/',
                                                                   '/product/', '/vendor/'))
                    or package != '' or any(part in ('.', '..') for part in path.split('/'))
                    or '//' in path or not re.fullmatch(r'/[A-Za-z0-9_./-]+', path)
                    or PurePosixPath(path).name != row['library']):
                raise RuntimeError('Unsafe system native patch target.')
            system_targets.setdefault(row['feature'], set()).add((path, row['phase']))
        elif (path != '' or not isinstance(package, str) or package not in APP_PACKAGES):
            raise RuntimeError('Unsafe app native patch target.')
        key = tuple(row[name] for name in sorted(TARGET_KEYS))
        if key in seen_targets:
            raise RuntimeError('Duplicate native patch target.')
        seen_targets.add(key)
        target_features.add(row['feature'])
    if target_features != features:
        raise RuntimeError('Native patch feature has no target.')
    for checksum in output_owners.keys() & input_owners.keys():
        left, right = output_owners[checksum], input_owners[checksum]
        if not (system_targets.get(left['feature'], set())
                & system_targets.get(right['feature'], set())):
            raise RuntimeError('Native patch chain has no shared target and boot phase.')
        if left['feature'] != right['feature']:
            for path, phase in (system_targets[left['feature']] & system_targets[right['feature']]):
                order = {row['feature']: index for index, row in enumerate(value['targets'])
                         if row['kind'] == 'system' and row['path'] == path and row['phase'] == phase}
                if order[left['feature']] >= order[right['feature']]:
                    raise RuntimeError('Native patch chain target is out of boot order.')
    return value


def catalog():
    """Use each original patcher's constants as the single source of truth."""
    import apply_flutter_fix as flutter_targets
    import apply_navigation_fix as navigation
    import patch_assistant as assistant
    import patch_composer as composer
    import patch_display_privacy as privacy
    import patch_flutter as flutter
    import patch_lockscreen_video as lockscreen
    import patch_pad_hwui as hwui
    import patch_rear_display as rear
    import patch_rear_input_policy as rear_input
    import patch_wifi_capabilities as wifi
    import patch_xqos as xqos
    import patch_xiaomi_ims as ims
    import patch_qti_perf as qti
    import patch_uniperf as uniperf
    import patch_bufferqueue_perf as bufferqueue
    import patch_display_metadata as metadata
    import patch_thermal_capability as thermal
    import patch_display_brightness as brightness

    profiles = []
    for before, row in flutter.PROFILES.items():
        profiles.append(_profile('flutter-' + _slug(row['name']), 'flutter', before,
                                 row['output'], row['sites'], row.get('legacy', ())))
    for before, row in hwui.PROFILES.items():
        profiles.append(_profile('hwui-' + _slug(row['name']), 'hwui', before, row['after'],
                                 ((row['site'], row['original'], hwui.REPLACEMENT),)))
    profiles.extend((
        _profile('assistant-mgl2', 'assistant', assistant.BEFORE, assistant.AFTER, assistant.SITES),
        _profile('lockscreen-video-fastplayer', 'lockscreen-video', lockscreen.BEFORE,
                 lockscreen.AFTER, lockscreen.SITES),
        _profile('navigation-recents-deadline', 'navigation', navigation.AOT_BEFORE,
                 navigation.AOT_AFTER, navigation.AOT_SITES),
        _profile('navigation-route-watchdog', 'navigation', navigation.WATCHDOG_BEFORE,
                 navigation.WATCHDOG_AFTER, navigation.WATCHDOG_SITES),
        _profile('composer-plane-alpha', 'composer', composer.BEFORE, composer.AFTER, composer.SITES),
        _profile('rear-display-secondary-timing', 'rear-display', rear.BEFORE, rear.AFTER, rear.SITES),
        _profile('display-privacy-disabled-state', 'display-privacy', privacy.BEFORE,
                 privacy.AFTER, privacy.SITES),
    ))
    for recipe in wifi.catalog_recipes():
        profiles.append(_profile('wifi-capabilities-' + recipe['before'][:12], 'wifi-capabilities',
                                 recipe['before'], recipe['after'],
                                 [(site['offset'], site['before'], site['after']) for site in recipe['sites']]))
    for recipe in xqos.catalog_recipes():
        profiles.append(_profile('xqos-' + recipe['before'][:12], 'xqos',
                                 recipe['before'], recipe['after'],
                                 [(site['offset'], site['before'], site['after']) for site in recipe['sites']]))
    for recipe in ims.catalog_recipes():
        profiles.append(_profile('vendor-ims-' + recipe['before'][:12], 'vendor-ims',
                                 recipe['before'], recipe['after'],
                                 [(site['offset'], site['before'], site['after']) for site in recipe['sites']]))
    for recipe in rear_input.catalog_recipes():
        profiles.append(_profile('rear-input-' + recipe['before'][:12], 'rear-input',
                                 recipe['before'], recipe['after'],
                                 [(site['offset'], site['before'], site['after']) for site in recipe['sites']]))
    for producer, label in ((qti, 'qti-perf'), (uniperf, 'uniperf'), (bufferqueue, 'bufferqueue-perf')):
        for recipe in producer.catalog_recipes():
            profiles.append(_profile(label + '-' + recipe['before'][:12], 'perf-hardware',
                                     recipe['before'], recipe['after'],
                                     [(site['offset'], site['before'], site['after']) for site in recipe['sites']]))
    for recipe in metadata.catalog_recipes():
        profiles.append(_profile('display-metadata-' + recipe['before'][:12], 'display-metadata',
                                 recipe['before'], recipe['after'],
                                 [(site['offset'], site['before'], site['after']) for site in recipe['sites']]))
    for producer, feature in ((thermal, 'thermal-monitor'), (brightness, 'display-brightness')):
        for recipe in producer.catalog_recipes():
            profiles.append(_profile(feature + '-' + recipe['before'][:12], feature,
                                     recipe['before'], recipe['after'],
                                     [(site['offset'], site['before'], site['after']) for site in recipe['sites']]))
    targets = [
        _target('flutter', 'early', flutter_targets.SYSTEM_LIB),
        _target('hwui', 'early', hwui.NATIVE),
        _target('composer', 'early', composer.NATIVE),
        _target('rear-display', 'early', rear.NATIVE),
        _target('rear-input', 'early', rear_input.PATH),
        _target('display-brightness', 'early', brightness.PATH),
        _target('display-privacy', 'early', privacy.NATIVE),
        *[_target('display-metadata', 'early', path) for path in sorted({value['path'] for value in metadata.RECIPES.values()})],
        _target('wifi-capabilities', 'early', wifi.PATH),
        _target('xqos', 'early', xqos.NATIVE),
        _target('vendor-ims', 'early', ims.PATH),
        _target('perf-hardware', 'early', qti.NATIVE),
        _target('perf-hardware', 'early', uniperf.PATH),
        _target('perf-hardware', 'early', uniperf.MIUI_SERVICES),
        _target('perf-hardware', 'early', bufferqueue.NATIVE),
        _target('thermal-monitor', 'early', thermal.PATH),
        *[_target('flutter', 'late', package=package,
                  library=PurePosixPath(flutter_targets.SYSTEM_LIB).name)
          for package in flutter_targets.PACKAGES],
        _target('assistant', 'late', package=assistant.PACKAGE, library=PurePosixPath(assistant.NATIVE).name),
        _target('lockscreen-video', 'late', package=lockscreen.PACKAGE,
                library=PurePosixPath(lockscreen.NATIVE).name),
        _target('navigation', 'late', package='com.miui.home', library='libapp.so'),
        _target('navigation', 'late', package='com.miui.home', library='libapp_launcher.so'),
    ]
    # Order cross-feature producers before consumers at the first early hook;
    # late reconciliation must not repair a framework that zygote already read.
    by_output = {row['after']: row['feature'] for row in profiles}
    dependencies = {row['feature']: set() for row in profiles}
    for row in profiles:
        source = by_output.get(row['before'])
        if source is not None and source != row['feature']:
            dependencies[row['feature']].add(source)
    ranks = {}
    while len(ranks) < len(dependencies):
        ready = {feature: 1 + max((ranks[item] for item in required), default=-1)
                 for feature, required in dependencies.items()
                 if feature not in ranks and required <= ranks.keys()}
        if not ready:
            raise RuntimeError('Cyclic native patch feature dependencies.')
        ranks.update(ready)
    value = {'schema': 1, 'profiles': sorted(profiles, key=lambda row: row['id']),
             'targets': sorted(targets, key=lambda row: (ranks[row['feature']], *(row[key] for key in
                                                            ('feature', 'kind', 'package', 'library', 'path'))))}
    return validate_catalog(value)


def dump_catalog(value=None):
    """Return deterministic UTF-8 JSON without storing any proprietary payload."""
    return json.dumps(validate_catalog(catalog() if value is None else value),
                      sort_keys=True, indent=2, ensure_ascii=True) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Write JSON instead of printing it')
    args = parser.parse_args()
    data = dump_catalog()
    if args.output:
        args.output.write_text(data, encoding='utf-8')
    else:
        print(data, end='')


if __name__ == '__main__':
    main()
