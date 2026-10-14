#!/system/bin/sh
# The OEM runtime-off switch skips only its optional idle-connection monitor.

core_tcm_recipe() {
    local file="$MODDIR/tcm-capability.tsv" expected
    core_safe_file "$file" && core_safe_file "$MODDIR/SHA256SUMS" || return 1
    expected=$("$BB" awk '$2=="tcm-capability.tsv" {if(NF!=2 || length($1)!=64 || $1~/[^0-9a-f]/ || found++)bad=1; value=$1}
        END {if(bad || found!=1)exit 1;print value}' "$MODDIR/SHA256SUMS") || return 1
    native_hex "$expected" && [ "$(native_hash "$file")" = "$expected" ] || return 1
    "$BB" awk -F '|' '
        BEGIN {split("/system/framework/tcmclient.jar /system_ext/etc/init/dpmd.rc /system_ext/bin/dpmd /system_ext/lib64/libdpmframework.so /system_ext/lib64/libdpmtcm.so /system_ext/lib64/libdpmctmgr.so /system_ext/framework/com.qti.dpmframework.jar /system_ext/etc/selinux/system_ext_sepolicy.cil /system_ext/etc/selinux/system_ext_file_contexts /vendor/etc/selinux/vendor_sepolicy.cil", paths, " ")}
        NR==1 {if($0!="schema|1")bad=1;next}
        NR>=2 && NR<=11 {if(NF!=3 || $1!="file" || $2!=paths[NR-1] || length($3)!=64 || $3~/[^0-9a-f]/)bad=1;pins=pins $2 "|" $3 "\n";next}
        NR==12 {if($0!="property|persist.vendor.dpm.tcm|1")bad=1;next}
        NR==13 {if($0!="policy|unset-current-boot-only")bad=1;next}
        {bad=1}
        END {if(bad || NR!=13)exit 1;printf "%s",pins}' "$file"
}

core_tcm_unset() {
    # Preserve even an explicitly present empty property. No persist-store read
    # or write is needed, and a failed property inventory never means absent.
    local properties
    properties=$(getprop) || return 1
    [ -n "$properties" ] && [ "$(getprop ro.boot.hardware)" = ranchu ] &&
        [ "$(getprop ro.kernel.qemu)" = 1 ] && [ "$(getprop ro.boot.qemu)" = 1 ] || return 1
    printf '%s\n' "$properties" | "$BB" awk '
        index($0,"[persist.vendor.dpm.tcm]: [")==1 {found=1}
        index($0,"[ro.boot.hardware]: [")==1 {hardware++;if($0!="[ro.boot.hardware]: [ranchu]")bad=1}
        index($0,"[ro.kernel.qemu]: [")==1 {kernel++;if($0!="[ro.kernel.qemu]: [1]")bad=1}
        index($0,"[ro.boot.qemu]: [")==1 {boot++;if($0!="[ro.boot.qemu]: [1]")bad=1}
        END {exit found || bad || hardware!=1 || kernel!=1 || boot!=1}' || return 1
    [ -z "$(getprop persist.vendor.dpm.tcm)" ]
}

core_tcm_early() {
    [ "$(getprop sys.boot_completed)" != 1 ] &&
        ! pidof zygote64 zygote system_server >/dev/null 2>&1
}

core_tcm_file_matches() {
    local pins=$1
    native_ns 1 "$BB" sh -c '
        bb=$1; pins=$2; count=0
        while IFS="|" read -r file pin extra; do
            [ -z "$extra" ] && [ -f "$file" ] && [ ! -L "$file" ] &&
                [ "$("$bb" stat -c %u "$file")" = 0 ] &&
                [ "$("$bb" stat -c %h "$file")" = 1 ] &&
                [ "$("$bb" sha256sum "$file" | "$bb" cut -d " " -f 1)" = "$pin" ] || exit 1
            parent=${file%/*}
            while [ "$parent" != / ]; do
                [ -d "$parent" ] && [ ! -L "$parent" ] || exit 1
                parent=${parent%/*}; [ -n "$parent" ] || parent=/
            done
            count=$((count + 1))
        done <<EOF
$pins
EOF
        [ "$count" = 10 ]
        ' sh "$BB" "$pins"
}

core_network_tcm() {
    core_permitted network-tcm || return 0
    # core_early also runs during later reconciliations. Apply the switch only
    # during post-fs, before clients can create their optional receiver thread.
    core_tcm_early || return 0
    native_guard && native_assets || return 1
    if ! core_tcm_unset; then
        native_status network-tcm persist.vendor.dpm.tcm skipped property-present-or-inventory-unavailable; return 0
    fi
    if ! native_privacy_eligible; then
        native_status network-tcm persist.vendor.dpm.tcm skipped unaudited-ranchu-vendor; return 0
    fi
    local pins
    pins=$(core_tcm_recipe) || { native_status network-tcm persist.vendor.dpm.tcm skipped unverified-tcm-recipe; return 0; }
    if ! core_tcm_file_matches "$pins"; then
        native_status network-tcm persist.vendor.dpm.tcm skipped unsupported-tcm-content; return 0
    fi
    [ -x "$CORE_RESETPROP" ] || { native_status network-tcm persist.vendor.dpm.tcm skipped resetprop-unavailable; return 0; }
    # Preserve a concurrent user/property choice and recheck the complete
    # hardware and exact client contract immediately before the single write.
    core_permitted network-tcm && core_tcm_early && core_tcm_unset &&
        native_privacy_eligible && core_tcm_file_matches "$pins" && core_tcm_unset || return 0
    "$CORE_RESETPROP" -n persist.vendor.dpm.tcm 1 || return 1
    [ "$(getprop persist.vendor.dpm.tcm)" = 1 ] || return 1
    native_status network-tcm persist.vendor.dpm.tcm ready verified-oem-runtime-opt-out
}
