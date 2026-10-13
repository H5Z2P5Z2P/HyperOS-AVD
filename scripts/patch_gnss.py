#!/usr/bin/env python3
"""Defer GNSS status callbacks until the framework releases its HAL monitor."""
import hashlib
import os
import re
from pathlib import Path
import shutil
import subprocess
import urllib.request
from https_transport import secure_urlretrieve
import zipfile

from common import ROOT

SOURCE_SHA256 = '49d5d9175d398656c4db3854f72e040ffcccbbd08371dc3bf6e9a3afcb1d96a0'
OS4_SHA256 = 'e60bfa83c50060666c9c157c558f4a88449b3697c45a2895a1069b9d59e32df0'
OS4_18_SHA256 = '9e823fe6df680c05bed72b20b45783aaf0be6aa15e70d69880f1849107954c09'
PAD_SHA256 = '8aa1303fd24261d1a36592b39bf07f42ff6725660f4078f1d3783578836f5ede'
REPRODUCIBLE_RECIPES = {
    OS4_18_SHA256: {
        'after': 'babf026115b889d21189dd8dcaa69cfec3f21098ec077345abdacbf3be7e8e5b',
        'dex_before': 'fe17d1cb4a980591b4fba14016e94adbebfafe531beb778f30478d39ecec3d48',
        'dex_after': '1c0425cbda18cc9051e12032df9a5ff9c9a6967f0d0bc84832e4341f539552d7',
    },
}
ARTIFACTS = {'baksmali': ('org/smali/baksmali/2.5.2/baksmali-2.5.2.jar',
              '1ed236266d7dc4907aade0b19a34f77efac25342b63c8ace52e579039941b389'),
 'smali': ('org/smali/smali/2.5.2/smali-2.5.2.jar',
           '136c5c4653d6531bd7b6f10f35f8691cb96432e727d30b4d5579826ee01e9419'),
 'dexlib2': ('org/smali/dexlib2/2.5.2/dexlib2-2.5.2.jar',
             '5a5c8982d8bd7d6e3bb1a0713049e3c78b719ec32b20f6b619885cec30a0dd61'),
 'util': ('org/smali/util/2.5.2/util-2.5.2.jar',
          '4f580a9cff3ebb83cb3fd20bec88e37e4f183796ca652732992611620282daea'),
 'jcommander': ('com/beust/jcommander/1.64/jcommander-1.64.jar',
                '156be736199c990321d9ff77090b199629cfc9865e2d6c13f7cd291bb1641817'),
 'guava': ('com/google/guava/guava/27.1-android/guava-27.1-android.jar',
           '686404f2d1d4d221911f96bd627ff60dac2226a5dfa6fb8ba517073eb97ec0ef'),
 'antlr-runtime': ('org/antlr/antlr-runtime/3.5.2/antlr-runtime-3.5.2.jar',
                   'ce3fc8ecb10f39e9a3cddcbb2ce350d272d9cd3d0b1e18e6fe73c3b9389c8734')}


def output_receipt(source_sha256):
    """Describe an audited reproducible producer without relying on cached output."""
    if source_sha256 not in REPRODUCIBLE_RECIPES:
        raise RuntimeError('Unsupported reproducible GNSS source.')
    return {'schema': 1, 'kind': 'gnss-callback-dispatch', 'before': source_sha256,
            **REPRODUCIBLE_RECIPES[source_sha256], 'dex': 'classes2.dex',
            'assembly_jobs': 1,
            'tools': {name: checksum for name, (_, checksum) in ARTIFACTS.items()}}


def java():
    candidates = [Path(os.environ.get('JAVA_HOME', '/nonexistent')) / 'bin/java',
                  Path('/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin/java')]
    for path in candidates:
        if path.is_file():
            return str(path)
    found = shutil.which('java')
    if found:
        return found
    raise RuntimeError('Set JAVA_HOME to an Android Studio JBR or JDK 17+.')


def patch(source, destination):
    source, destination = Path(source), Path(destination)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if digest not in (SOURCE_SHA256, OS4_SHA256, OS4_18_SHA256, PAD_SHA256):
        raise RuntimeError('Unsupported services.jar; use a verified fuxi, hongkong or yingtian image.')
    cache = ROOT / 'tools/smali'
    cache.mkdir(parents=True, exist_ok=True)
    for name, (coordinate, expected) in ARTIFACTS.items():
        path = cache / (name + '.jar')
        if not path.exists():
            secure_urlretrieve('https://repo.maven.apache.org/maven2/' + coordinate, path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError('Invalid Maven artifact: ' + str(path))
    work = ROOT / 'work/gnss-patch'
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    with zipfile.ZipFile(source) as archive:
        if archive.namelist().count('classes2.dex') != 1:
            raise RuntimeError('Missing or duplicate GNSS dex.')
        (work / 'input.dex').write_bytes(archive.read('classes2.dex'))
    recipe = REPRODUCIBLE_RECIPES.get(digest)
    if recipe and hashlib.sha256((work / 'input.dex').read_bytes()).hexdigest() != recipe['dex_before']:
        raise RuntimeError('Unexpected reproducible GNSS dex input.')
    command = [java(), '-cp', str(cache / '*')]
    subprocess.run(command + ['org.jf.baksmali.Main', 'disassemble', str(work / 'input.dex'),
                              '-o', str(work / 'smali')], check=True)
    package = work / 'smali/com/android/server/location/gnss/hal'
    native = package / 'GnssNative.smali'
    text = native.read_text()
    callbacks = {'reportStatus(I)V': 2,
                 'reportSvStatus(I[I[F[F[F[F[F)V': 8,
                 'reportLocation(ZLandroid/location/Location;)V': 3}
    if digest in (OS4_SHA256, OS4_18_SHA256, PAD_SHA256):
        del callbacks['reportSvStatus(I[I[F[F[F[F[F)V']
        callbacks['reportSvStatus(I[I[I[I[F[F[F[F[F[Ljava/lang/String;[J[D)V'] = 13
    original = 'invoke-static {v0}, Landroid/os/Binder;->withCleanCallingIdentity(Lcom/android/internal/util/FunctionalUtils$ThrowingRunnable;)V'
    for signature, parameter_words in callbacks.items():
        start = text.index('.method ' + signature + '\n')
        end = text.index('.end method', start) + len('.end method')
        method = text[start:end]
        if method.count(original) != 1:
            raise RuntimeError('Unexpected GNSS callback implementation: ' + signature)
        registers = int(re.search(r'\.registers (\d+)', method).group(1))
        if registers - parameter_words < 2:
            method = method.replace('.registers ' + str(registers),
                                    '.registers ' + str(registers + 1), 1)
        method = method.replace(original, '''invoke-static {}, Lcom/android/server/FgThread;->getHandler()Landroid/os/Handler;

    move-result-object v1

    invoke-virtual {v1, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z''')
        adapter_name = re.search(r'new-instance v0, Lcom/android/server/location/gnss/hal/([^;]+);', method).group(1)
        text = text[:start] + method + text[end:]
        adapter = package / (adapter_name + '.smali')
        body = adapter.read_text()
        if body.count('.implements Lcom/android/internal/util/FunctionalUtils$ThrowingRunnable;') != 1:
            raise RuntimeError('Unexpected GNSS callback adapter: ' + adapter_name)
        body = body.replace('.implements Lcom/android/internal/util/FunctionalUtils$ThrowingRunnable;',
                            '.implements Lcom/android/internal/util/FunctionalUtils$ThrowingRunnable;\n.implements Ljava/lang/Runnable;')
        body += '''

.method public final run()V
    .registers 1

    invoke-static {p0}, Landroid/os/Binder;->withCleanCallingIdentity(Lcom/android/internal/util/FunctionalUtils$ThrowingRunnable;)V

    return-void
.end method
'''
        adapter.write_text(body)
    native.write_text(text)
    # Parallel assembly changes DEX ordering even for identical smali input.
    # Keep frozen legacy producers; modern audited output uses one worker.
    jobs = ['-j', '1'] if recipe else []
    subprocess.run(command + ['org.jf.smali.Main', 'assemble', *jobs, str(work / 'smali'),
                              '-o', str(work / 'output.dex')], check=True)
    if recipe and hashlib.sha256((work / 'output.dex').read_bytes()).hexdigest() != recipe['dex_after']:
        raise RuntimeError('Reproducible GNSS dex output checksum mismatch.')
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(destination, 'w') as dst:
        for entry in src.infolist():
            dst.writestr(entry, (work / 'output.dex').read_bytes()
                         if entry.filename == 'classes2.dex' else src.read(entry))
    output = destination.read_bytes()
    if recipe and hashlib.sha256(output).hexdigest() != recipe['after']:
        raise RuntimeError('Reproducible GNSS archive output checksum mismatch.')
    return output


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    patch(args.source, args.destination)
