# Stable installer protocol

New Phone and Pad OS4 bundles declare `verified-bundle-runtime-v1`. Installer
**1.2.3 is the fixed baseline** for this protocol. Image packaging must use
`bundle_runtime.PROTOCOL_MINIMUM`, never the current installer version.
Updating an audited firmware profile, patch recipe, or image revision therefore
does not require publishing another installer. A host requirement or protocol
change may still require an installer update.

The stable installer validates the manifest envelope, firmware family,
encryption template, upgrade order, ownership, and idle instance. It extracts
only listed regular files and verifies every archive part, file size, and SHA-256
before executing the fixed `runtime/scripts/bundle_runtime.py` entrypoint.
Cached bundles receive the same checks and must retain the exact manifest.
Unlisted runtime files, including Python bytecode, are rejected. Handoff and
launch use a fresh external cache directory and never write caches into a bundle.

The verified image runtime authenticates its audited firmware profile, Core
context, and Apps catalog, then performs the existing backed-up installation
transaction. Child and parent pin the same manifest digest; failure retains the
normal recovery path. Old bundles without this protocol keep their strict
historical installation path.

Firmware-specific rules travel with the image. This does **not** authorize
arbitrary official OTA packages: maintainers must still audit and package each
new source. The protocol separates image maintenance from installer releases;
it does not implement automatic in-guest OTA adaptation.

For a local prepared bundle, use the normal installer entrypoint:

```sh
python3 scripts/manage.py install --bundle /path/to/release/manifest.json \
  --root /path/to/instance --name Existing_AVD --port 5580 --sdk /path/to/sdk \
  --ram 6 --cores 4 --storage 32
```

Keep the existing instance root, name, and port for upgrades. Preserve current
RAM, CPU, storage, and camera choices rather than applying these example values
to an existing instance.

## Optional incremental transport

Installer 1.3.0 adds `block-delta-v1` transport without changing the fixed
`verified-bundle-runtime-v1` installation protocol or its 1.2.3 baseline.
The target manifest keeps its complete `files` and full archive `parts`.
An optional `deltas` list adds source-specific descriptors containing
`protocol`, `from_version`, `from_manifest_sha256` (canonical source manifest
digest), and separately hashed archive `parts`. Older installers ignore this
field and download the full archive.

Only verified OS4 releases with the same official OTA `build.archive_sha256`,
firmware identity, platform, userdata family, and encryption template may use
incremental transport. A version tag or AVD name alone never establishes this
relationship. The current installed manifest and its saved version directory
must match the source digest and every reused source file must match its size
and SHA-256. Live AVD userdata and mutable instance image paths are never delta
inputs.

Each changed or added target file is represented by a regular tar member with
the target relative path and a bounded COPY/DATA instruction stream. Unchanged
files are copied from the authenticated source version. Reconstruction happens
in a temporary version directory. Missing, duplicate, unlisted, linked, or
unsafe members fail before promotion. The installer validates all reconstructed
target files and the complete staged runtime before an atomic directory rename,
then uses the existing backed-up installation transaction. No old files are
patched in place. Removed files are absent from the new version.

Online upgrades fall back to the full archive when a source is unavailable or
incremental download/reconstruction fails. Offline upgrades can provide the
manifest plus the selected delta parts, or the complete full archive. Space is
still required for a full reconstructed version and the normal data backup.

Maintainers can request one or more source versions during normal packaging:

```sh
python3 scripts/package_release.py --variant os4-official --version <new-tag> \
  --output /path/to/new-release \
  --delta-from /path/to/old-instance/versions/<old-tag>/local/installed-release.json
```

Repeat `--delta-from` to support several earlier versions directly. An unpacked
release with `manifest.json` at its root is also accepted. Each source must be
an intact portable release, never a personal AVD image. Full parts are always
retained. A generated delta is advertised only when it is smaller than the full
archive. Archive SHA-256 entries and delta descriptors are finalized before the
target manifest and `SHA256SUMS` are written. Packaging does not publish assets.
