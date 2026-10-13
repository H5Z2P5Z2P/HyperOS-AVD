#!/system/bin/sh
MODDIR=${0%/*}
. "$MODDIR/runtime.sh"
native_guard && native_assets || exit 0
for feature in finddevice vendor-ims; do
    "$BB" sh "$MODDIR/$feature-policy.sh" restore
done
