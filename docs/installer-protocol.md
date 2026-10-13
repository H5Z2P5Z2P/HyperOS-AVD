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
