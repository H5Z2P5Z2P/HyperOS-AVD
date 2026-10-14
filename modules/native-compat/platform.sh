#!/system/bin/sh
# Platform state is persistent userdata; image identity is never an OTA table.
CORE_STATE=${HYPEROS_CORE_STATE:-/data/adb/hyperos-avd-core}
CORE_RESETPROP=${HYPEROS_CORE_RESETPROP:-/data/adb/ksu/bin/resetprop}
CORE_SYS=${HYPEROS_CORE_SYS:-/sys}
CORE_PENDING=${HYPEROS_CORE_PENDING:-/data/adb/modules_update/hyperos_avd_native_compat}

core_safe_file() {
    [ -f "$1" ] && [ ! -L "$1" ] &&
        [ "$("$BB" stat -c %u "$1")" = 0 ] && [ "$("$BB" stat -c %h "$1")" = 1 ]
}

core_state_safe() {
    local parent="$CORE_STATE"
    while [ "$parent" != / ]; do
        [ ! -L "$parent" ] || return 1
        if [ -e "$parent" ]; then [ -d "$parent" ] || return 1; fi
        parent=${parent%/*}; [ -n "$parent" ] || parent=/
    done
    [ -d "$CORE_STATE" ] && [ "$("$BB" stat -c %u "$CORE_STATE")" = 0 ]
}

core_permitted() {
    native_blocked && return 1
    native_enabled "$1" || return 1
    core_state_safe
}

core_boot_recipe() {
    # Match one complete immutable recipe before inspecting any guest file.
    # SHA256SUMS is anchored by the installed module's reviewed manifest and
    # verified by native_assets before its hooks run. Recheck this small asset
    # here so a changed catalog cannot authorize later platform effects.
    local catalog="$MODDIR/boot-prerequisites.tsv" expected
    core_safe_file "$catalog" && core_safe_file "$MODDIR/SHA256SUMS" || return 1
    expected=$("$BB" awk '$2 == "boot-prerequisites.tsv" {
        if (NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ || found++) exit 1;
        checksum=$1} END {if (found != 1) exit 1; print checksum}' "$MODDIR/SHA256SUMS") || return 1
    native_hex "$expected" && [ "$(native_hash "$catalog")" = "$expected" ] || return 1
    "$BB" awk -F '|' '
        function hex(value) {return length(value) == 64 && value !~ /[^0-9a-f]/}
        FNR == NR {
            if (FNR == 1) {if ($0 != "schema|1") bad=1; next}
            if ($1 == "recipe" && NF == 3 && hex($2) && $3 ~ /^[1-9][0-9]*$/ && length($3) <= 3) {
                if (declared[$2]++) bad=1; required[$2]=$3+0; next
            }
            if ($1 == "file" && NF == 4 && hex($2) && $3 ~ /^\/(system|system_ext|product)\// && hex($4)) {
                key=$2 SUBSEP $3;
                if ((key in pins) || !declared[$2]) bad=1;
                pins[key]=$4; count[$2]++; next
            }
            bad=1; next
        }
        $1 == "boot" {
            if (NF != 3 || !hex($3) || ($2 in image)) bad=1;
            image[$2]=$3; found++
        }
        END {
            if (bad || !found) exit 1;
            for (recipe in declared) {
                if (count[recipe] != required[recipe]) exit 1;
                if (found != required[recipe]) continue;
                matches=1;
                for (path in image) if (pins[recipe SUBSEP path] != image[path]) matches=0;
                if (matches) {selected=recipe; accepted++}
            }
            if (accepted != 1) exit 1;
            for (path in image) print "boot|" path "|" pins[selected SUBSEP path]
        }' "$catalog" "$CORE_STATE/image.tsv"
}

core_reviewed_native_derivative() {
    # An owned early bind may add a bounded exact-content producer chain to
    # an immutable image prerequisite. Check every edge and capability; legacy
    # aliases and unrelated framework targets cannot establish boot provenance.
    local path=$1 expected=$2 actual=$3 feature features
    native_hex "$expected" && native_hex "$actual" && [ "$expected" != "$actual" ] || return 1
    native_guard && native_assets || return 1
    core_safe_file "$MODDIR/targets.tsv" && core_safe_file "$MODDIR/profiles.tsv" || return 1
    native_owns_mount 1 "$path" || return 1
    features=$("$BB" awk -F '|' -v path="$path" -v expected="$expected" -v actual="$actual" '
        function hex(value) {return length(value) == 64 && value !~ /[^0-9a-f]/}
        FNR == NR {
            if ($4 == path) {
                targets++; parts_count=split(path, parts, "/");
                reviewed=((($3 == "perf-hardware" || $3 == "thermal-monitor") && path == "/system_ext/framework/miui-services.jar") ||
                          (($3 == "rear-input" || $3 == "display-brightness") && path == "/system/framework/services.jar"));
                if (NF != 6 || $1 != "early" || $2 != "system" ||
                    !reviewed || $5 != "" || $6 != parts[parts_count] || scopes[$3]++) bad=1;
                allowed[$3]=1;
            }
            next
        }
        allowed[$4] {
            prefix=($4 == "perf-hardware" ? "uniperf-" : $4 "-");
            if ($5 != prefix substr($1,1,12)) next;
            if (NF != 5 || !hex($1) || !hex($2) || $3 != "" || seen[$1]++ || outputs[$2]++) bad=1;
            edge[$1]=$2; group[$1]=$4;
        }
        END {
            if (bad || !targets) exit 1;
            current=expected;
            for (depth=0; depth<8 && current != actual; depth++) {
                if (visited[current]++ || !(current in edge)) exit 1;
                used[group[current]]=1; current=edge[current];
            }
            if (current != actual || depth == 0) exit 1;
            for (feature in used) print feature;
        }
        ' "$MODDIR/targets.tsv" "$MODDIR/profiles.tsv") || return 1
    # Content remains the same when the user disables a feature while its
    # inode is loaded. Reboot controls applicability; it cannot revoke the
    # image's independent boot provenance or authorize a new mutation.
    for feature in $features; do native_eligible "$feature" || return 1; done
    [ "$(native_ns_hash 1 "$path")" = "$actual" ]
}

core_context_rows_ready() {
    local kind=$1 row path expected extra actual found=0 seen='|'
    while IFS='|' read -r row path expected extra; do
        [ "$row" = "$kind" ] || continue
        [ -z "$extra" ] && native_hex "$expected" || return 1
        case "$seen" in *"|$path|"*) return 1 ;; esac
        seen="$seen$path|"
        case "$kind:$path" in
            identity:/system/build.prop|identity:/product/etc/build.prop) ;;
            rear:/system_ext/framework/rear-display-wake.jar|rear:/system_ext/bin/rear-display-wake|rear:/product/etc/hyperos-avd-rear-display.json|rear:/product/overlay/HyperOSAVDRearDisplay/RearDisplay.apk|rear:/product/etc/displayconfig/display_id_*.xml) ;;
            boot:*) ;;
            *) return 1 ;;
        esac
        native_path "$path" && core_safe_file "$path" || return 1
        actual=$(native_ns_hash 1 "$path")
        if [ "$actual" != "$expected" ]; then
            [ "$kind" = boot ] && core_reviewed_native_derivative "$path" "$expected" "$actual" || return 1
        fi
        found=$((found + 1))
    done
    [ "$found" -gt 0 ]
}

core_context_ready() {
    local kind=$1 rows
    core_state_safe && core_safe_file "$CORE_STATE/image.tsv" || return 1
    if [ "$kind" = boot ]; then
        # Verify the canonical matched snapshot, not a second read of mutable
        # userdata that could change between recipe matching and hashing.
        rows=$(core_boot_recipe) || return 1
        printf '%s\n' "$rows" | core_context_rows_ready "$kind"
    else
        core_context_rows_ready "$kind" < "$CORE_STATE/image.tsv"
    fi
}

core_identity_rows() {
    # Whitelist public product/build fields. Never overwrite ranchu HAL keys,
    # serials, boot properties, vendor API level, or the board platform.
    local row path expected extra
    while IFS='|' read -r row path expected extra; do
        [ "$row" = identity ] || continue
        "$BB" awk -F '=' '
            /^[[:space:]]*#/ {next}
            NF >= 2 {
                key=$1; value=substr($0, length(key)+2);
                if (key ~ /^ro\.product\.(.*\.)?(brand|device|manufacturer|model|name|marketname|cert|board)$/ ||
                    key ~ /^ro\.product\.(brand|device|manufacturer|model|name)_for_attestation$/ ||
                    key == "ro.product.first_api_level" ||
                    key ~ /^ro\.(build|system|system_ext|product|vendor|odm|system_dlkm|vendor_dlkm)\.build\.fingerprint$/ ||
                    key == "ro.build.fingerprint" || key == "ro.build.characteristics" ||
                    key == "ro.soc.model" || key == "ro.soc.manufacturer" ||
                    key == "ro.miui.product.home") {
                    if (key !~ /^[A-Za-z0-9_.]+$/ || value == "" || value ~ /[\r|]/ || seen[key]++) exit 1;
                    print key "|" value;
                }
            }' "$path" || return 1
    done < "$CORE_STATE/image.tsv"
}

core_identity() {
    core_permitted identity || return 0
    if ! core_context_ready identity; then
        native_status identity image skipped unverified-image-defaults; return 0
    fi
    [ -x "$CORE_RESETPROP" ] || { native_status identity image skipped resetprop-unavailable; return 0; }
    local rows="$MODDIR/state/identity.next.$$" key value extra current
    core_identity_rows > "$rows" || { rm -f "$rows"; native_status identity image skipped invalid-image-defaults; return 0; }
    while IFS='|' read -r key value extra; do
        core_permitted identity || { rm -f "$rows"; return 0; }
        [ -z "$extra" ] || { rm -f "$rows"; return 1; }
        current=$(getprop "$key")
        [ "$current" != "$value" ] || continue
        core_context_ready identity || { rm -f "$rows"; return 0; }
        if [ "${#value}" -ge 91 ] && [ -n "$current" ]; then
            "$CORE_RESETPROP" -d "$key" || { rm -f "$rows"; return 1; }
            core_permitted identity || { rm -f "$rows"; return 0; }
        fi
        "$CORE_RESETPROP" -n "$key" "$value" || { rm -f "$rows"; return 1; }
    done < "$rows"
    rm -f "$rows"
    native_status identity image ready verified-current-image
}

core_serial_valid() {
    printf '%s\n' "$1" | "$BB" grep -Eq '^([0-9]{5}/[A-HJ-NP-Z][0-9][NPQRSTUVWXYZ][1-9ABCDEFHJKMNPQRSTUVWXYZ][0-9]{5}|[0-9A-F]{16})$'
}

core_serial_new() {
    local numbers a b c year month day factory
    numbers=$("$BB" od -An -N12 -tu4 /dev/urandom) || return 1
    set -- $numbers
    [ "$#" = 3 ] || return 1
    for a in "$@"; do case "$a" in ''|*[!0-9]*) return 1 ;; esac; done
    a=$1; b=$2; c=$3
    year=$(date +%y); year=${year#?}
    month=$(date +%m); month=${month#0}; day=$(date +%d); day=${day#0}
    factory=$(printf 'ABCDEFGHJKLMNPQRSTUVWXYZ' | "$BB" cut -c "$((c % 23 + 1))")
    month=$(printf 'NPQRSTUVWXYZ' | "$BB" cut -c "$month")
    day=$(printf '123456789ABCDEFHJKMNPQRSTUVWXYZ' | "$BB" cut -c "$day")
    printf '%05d/%s%s%s%s%05d\n' "$((10000 + a % 90000))" "$factory" "$year" "$month" "$day" "$((1 + b % 99999))"
}

core_serial() {
    core_permitted serial || return 0
    [ -x "$CORE_RESETPROP" ] || return 0
    local file="$CORE_STATE/serial.record" lease="$CORE_STATE/serial.guard" schema owner serial extra next
    if [ -e "$lease" ] || [ -L "$lease" ]; then
        core_safe_file "$lease" && [ ! -s "$lease" ] || return 1
    fi
    exec 8>>"$lease" || return 1
    "$BB" flock -n 8 || { exec 8>&-; return 0; }
    chmod 600 "$lease" || { exec 8>&-; return 1; }
    if [ ! -e "$file" ] && [ ! -L "$file" ]; then
        # Refuse to mint an identifier while an unmigrated legacy record exists.
        if [ -e /data/adb/modules/hyperos_avd_navigation ] || [ -L /data/adb/modules/hyperos_avd_navigation ] ||
                [ -e /data/adb/hyperos-avd-pad/serial.json ] || [ -L /data/adb/hyperos-avd-pad/serial.json ]; then
            exec 8>&-; native_status serial userdata skipped legacy-identity-needs-authentication; return 0
        fi
        serial=$(core_serial_new) && core_serial_valid "$serial" || { exec 8>&-; return 1; }
        next="$file.next.$$"
        [ ! -e "$next" ] && [ ! -L "$next" ] || { exec 8>&-; return 1; }
        core_permitted serial || { exec 8>&-; return 0; }
        (set -C; printf '1|hyperos_avd_native_compat|%s\n' "$serial" > "$next") && chmod 600 "$next" &&
            mv "$next" "$file" || { rm -f "$next"; exec 8>&-; return 1; }
    fi
    core_safe_file "$file" && [ "$("$BB" wc -l < "$file")" -eq 1 ] || { exec 8>&-; return 1; }
    IFS='|' read -r schema owner serial extra < "$file"
    [ "$schema" = 1 ] && [ "$owner" = hyperos_avd_native_compat ] && [ -z "$extra" ] &&
        core_serial_valid "$serial" || { exec 8>&-; return 1; }
    for key in ro.serialno ro.boot.serialno ro.ril.oem.psno; do
        core_permitted serial || { exec 8>&-; return 0; }
        [ "$(getprop "$key")" = "$serial" ] || "$CORE_RESETPROP" -n "$key" "$serial" || { exec 8>&-; return 1; }
    done
    exec 8>&-
    native_status serial userdata ready persistent-identity
}

core_thermal() {
    core_permitted thermal || return 0
    local node label
    for node in "$CORE_SYS/devices/virtual/thermal/thermal_zone0/type" "$CORE_SYS/devices/virtual/thermal/thermal_zone0/temp"; do
        [ -f "$node" ] && [ ! -L "$node" ] || continue
        label=$(ls -Z "$node")
        case "$label" in
            *u:object_r:sysfs:s0*) core_permitted thermal || return 0; chcon u:object_r:sysfs_thermal:s0 "$node" || return 1 ;;
            *u:object_r:sysfs_thermal:s0*) ;;
            *) native_status thermal "$node" skipped unknown-sysfs-label; continue ;;
        esac
        native_status thermal "$node" ready capability-label
    done
}

core_refresh_capable() {
    [ "$(getprop ro.boot.qemu.vsync)" = 60 ] || return 1
    dumpsys SurfaceFlinger | "$BB" awk '
        /activeMode/ && /id=0([, }]|$)/ && /vsyncRate=60\.00 Hz/ {found=1}
        END {exit !found}'
}

core_refresh() {
    core_permitted refresh || return 0
    if ! core_refresh_capable; then native_status refresh display skipped unsupported-active-mode; return 0; fi
    if dumpsys SurfaceFlinger | "$BB" grep -Fq 'renderRate=60.00 Hz'; then
        native_status refresh display ready compositor-60hz; return 0
    fi
    local reply
    core_permitted refresh || return 0
    reply=$(service call SurfaceFlinger 1035 i32 0)
    [ "$reply" = 'Result: Parcel(NULL)' ] || { native_status refresh display skipped unsupported-sf-api; return 0; }
    core_permitted refresh || return 0
    dumpsys SurfaceFlinger | "$BB" grep -Fq 'renderRate=60.00 Hz' || {
        native_status refresh display failed render-rate-not-retained; return 1;
    }
    native_status refresh display ready compositor-60hz
}

core_kernel() {
    core_permitted boot-services || return 0
    if ! core_context_ready boot; then
        native_status boot-services kernel skipped unverified-image-prerequisites; return 0
    fi
    local probe=/system/bin/hyperos_kernel_probe code protocol service
    if ! core_safe_file "$probe" || [ ! -x "$probe" ]; then
        native_status boot-services kernel skipped verified-image-probe-unavailable; return 0
    fi
    protocol=$(getprop ro.millet.netlink)
    case "$protocol" in ''|*[!0-9]*) native_status boot-services millet skipped unknown-netlink-protocol ;; *)
        "$probe" "$protocol"; code=$?
        core_permitted boot-services && core_context_ready boot || return 0
        case "$code" in
            0) setprop sys.hyperos_avd.millet_supported 1 ;;
            2) setprop sys.hyperos_avd.millet_supported 0
               [ -z "$(getprop init.svc.millet_monitor)" ] || setprop ctl.stop millet_monitor ;;
            *) native_status boot-services millet failed capability-probe-error; return 1 ;;
        esac ;;
    esac
    core_permitted boot-services && core_context_ready boot || return 0
    "$probe" gnss-extension; code=$?
    core_permitted boot-services && core_context_ready boot || return 0
    case "$code" in
        0) ;;
        2) [ -z "$(getprop init.svc.loc_sys_service)" ] || setprop ctl.stop loc_sys_service ;;
        *) native_status boot-services gnss failed capability-probe-error; return 1 ;;
    esac
    native_status boot-services kernel ready verified-capability-probe
}

core_rear_recipe() {
    # Only the complete installed package may supply executable helper bytes.
    # The legacy image contract stays immutable; the current helper lives in
    # Core's directory and is never bound over a loaded image inode.
    native_assets || return 1
    local recipe="$MODDIR/rear-wake.tsv" expected
    core_safe_file "$recipe" && core_safe_file "$MODDIR/rear-wake.jar" || return 1
    expected=$("$BB" awk '$2 == "rear-wake.tsv" {
        if (NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ || found++) exit 1;
        checksum=$1} END {if (found != 1) exit 1; print checksum}' "$MODDIR/SHA256SUMS") || return 1
    native_hex "$expected" && [ "$(native_hash "$recipe")" = "$expected" ] || return 1
    "$BB" awk -F '|' '
        function hex(value) {return length(value) == 64 && value !~ /[^0-9a-f]/}
        NR == 1 {if ($0 != "schema|1") bad=1; next}
        NR == 2 {if ($0 != "class|io.github.hyperosavd.RearDisplayWake") bad=1; next}
        NR == 3 {if (NF != 3 || $1 != "jar" || $2 != "rear-wake.jar" || !hex($3)) bad=1; jar=$3; next}
        NR == 4 {if (NF != 3 || $1 != "legacy-jar" || $2 != "/system_ext/framework/rear-display-wake.jar" || !hex($3)) bad=1; legacy=$3; next}
        NR == 5 {if (NF != 3 || $1 != "legacy-launcher" || $2 != "/system_ext/bin/rear-display-wake" || !hex($3)) bad=1; launcher=$3; next}
        {bad=1}
        END {if (bad || NR != 5) exit 1; print jar "|" legacy "|" launcher}' "$recipe"
}

core_rear_process() {
    local pid=$1 directory="$PROC/$1"
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    [ -r "$directory/cmdline" ] && [ -r "$directory/environ" ] && [ -r "$directory/status" ] || return 1
    "$BB" tr '\000' '\n' < "$directory/cmdline" | "$BB" grep -Fxq io.github.hyperosavd.RearDisplayWake || return 1
    "$BB" awk '$1 == "Uid:" {found++; if(NF!=5)bad=1; for(i=2;i<=5;i++) if($i!=0)bad=1} END {exit bad || found!=1}' "$directory/status"
}

core_rear_kind() {
    local pid=$1 directory="$PROC/$1" recipe jar legacy launcher extra classpath
    core_rear_process "$pid" || return 1
    recipe=$(core_rear_recipe) || return 1
    IFS='|' read -r jar legacy launcher extra <<EOF
$recipe
EOF
    [ -z "$extra" ] && [ "$(native_hash "$MODDIR/rear-wake.jar")" = "$jar" ] || return 1
    classpath=$("$BB" tr '\000' '\n' < "$directory/environ" | "$BB" awk '
        /^CLASSPATH=/ {if (found++) exit 1; value=substr($0,11)}
        END {if (found != 1) exit 1; print value}') || return 1
    case "$classpath" in
        "$MODDIR/rear-wake.jar")
            [ "$(native_ns_hash "$pid" "$classpath")" = "$jar" ] || return 1
            echo current ;;
        /system_ext/framework/rear-display-wake.jar)
            [ "$(native_ns_hash "$pid" "$classpath")" = "$legacy" ] &&
                [ "$(native_ns_hash "$pid" /system_ext/bin/rear-display-wake)" = "$launcher" ] || return 1
            echo legacy ;;
        *) return 1 ;;
    esac
}

core_rear_owned() { core_rear_kind "$1" >/dev/null; }

core_rear_start_time() {
    [ -r "$PROC/$1/stat" ] || return 1
    "$BB" awk '{sub(/^.*\) /, ""); print $20}' "$PROC/$1/stat"
}

core_rear_record_safe() {
    local file="$CORE_STATE/rear-daemon.record" schema boot pid start extra
    [ -e "$file" ] || [ -L "$file" ] || return 0
    core_safe_file "$file" && [ "$("$BB" wc -l < "$file")" -eq 1 ] || return 1
    IFS='|' read -r schema boot pid start extra < "$file"
    [ "$schema" = 1 ] && [ -n "$boot" ] && [ -z "$extra" ] || return 1
    case "$pid:$start" in *[!0-9:]*) return 1 ;; esac
    [ -n "$pid" ] && [ -n "$start" ]
}

core_rear_lease_pid() {
    local file="$CORE_STATE/rear-daemon.record" schema boot pid start extra
    core_rear_record_safe && core_safe_file "$file" || return 1
    IFS='|' read -r schema boot pid start extra < "$file"
    [ "$schema" = 1 ] && [ -z "$extra" ] && [ -n "$pid" ] && [ -n "$start" ] || return 1
    case "$pid:$start" in *[!0-9:]*) return 1 ;; esac
    [ "$boot" = "$(cat "$PROC/sys/kernel/random/boot_id")" ] && core_rear_owned "$pid" || return 1
    [ "$(core_rear_start_time "$pid")" = "$start" ] || return 1
    printf '%s\n' "$pid"
}

core_rear_receipt() {
    local pid=$1 boot start next="$CORE_STATE/rear-daemon.record.next.$$" row
    core_rear_owned "$pid" && core_rear_record_safe || return 1
    boot=$(cat "$PROC/sys/kernel/random/boot_id") && start=$(core_rear_start_time "$pid") || return 1
    case "$start" in ''|*[!0-9]*) return 1 ;; esac
    [ -n "$boot" ] && [ ! -e "$next" ] && [ ! -L "$next" ] || return 1
    row="1|$boot|$pid|$start"
    if [ -f "$CORE_STATE/rear-daemon.record" ] && [ "$(cat "$CORE_STATE/rear-daemon.record")" = "$row" ]; then return 0; fi
    core_rear_owned "$pid" && [ "$(core_rear_start_time "$pid")" = "$start" ] || return 1
    (set -C; printf '%s\n' "$row" > "$next") &&
        chmod 600 "$next" && mv "$next" "$CORE_STATE/rear-daemon.record"
}

core_rear_lock() {
    core_state_safe || return 1
    local lease="$CORE_STATE/rear.guard"
    if [ -e "$lease" ] || [ -L "$lease" ]; then core_safe_file "$lease" && [ ! -s "$lease" ] || return 1; fi
    exec 7>>"$lease" || return 1
    "$BB" flock -n 7 || { exec 7>&-; return 1; }
    chmod 600 "$lease" || { exec 7>&-; return 1; }
}

core_rear_cleanup_locked() {
    # The lease binds ownership to this boot and process lifetime. Unknown
    # helper bytes, stale leases and PID reuse never authorize a signal.
    core_state_safe || return 0
    local pid start
    pid=$(core_rear_lease_pid) || return 0
    start=$(core_rear_start_time "$pid") || return 0
    [ "$(core_rear_lease_pid)" = "$pid" ] && [ "$(core_rear_start_time "$pid")" = "$start" ] || return 0
    kill -TERM "$pid" || return 1
    native_status rear-wake display disabled verified-daemon-stopped
}

core_rear_cleanup() {
    core_safe_file "$CORE_STATE/rear-daemon.record" || return 0
    core_rear_lock || return 0
    core_rear_cleanup_locked
    local result=$?
    exec 7>&-
    return "$result"
}

core_rear_ready() {
    native_eligible rear-display && core_context_ready rear || return 1
    local row id group unique extra recipe jar legacy launcher
    core_safe_file "$CORE_STATE/rear.record" || return 1
    IFS='|' read -r row id group unique extra < "$CORE_STATE/rear.record"
    [ "$row" = 1 ] && [ "$id" = 1 ] && [ "$group" = 1 ] &&
        [ "$unique" = local:4619827551948147201 ] && [ -z "$extra" ] || return 1
    recipe=$(core_rear_recipe) || return 1
    IFS='|' read -r jar legacy launcher extra <<EOF
$recipe
EOF
    [ -z "$extra" ] && [ "$(native_hash "$MODDIR/rear-wake.jar")" = "$jar" ] &&
        [ "$(native_ns_hash 1 /system_ext/framework/rear-display-wake.jar)" = "$legacy" ] &&
        [ "$(native_ns_hash 1 /system_ext/bin/rear-display-wake)" = "$launcher" ] || return 1
    # Early framework mounts precede live DisplayManager publication. This
    # mode still requires every pinned image asset and the exact rear record.
    [ "${1:-}" != image ] || return 0
    dumpsys display | "$BB" awk -v unique="$unique" '
        /DisplayInfo/ && /displayId[ =:]*1([, }]|$)/ && /displayGroupId[ =:]*1([, }]|$)/ && index($0,unique) {found=1}
        END {exit !found}'
}

core_rear() {
    if ! core_permitted rear-wake; then core_rear_cleanup; return 0; fi
    if ! core_rear_ready; then native_status rear-wake display skipped physical-display-prerequisite; return 0; fi
    local directory pid count=0 kind
    core_rear_lock || return 0
    if ! core_rear_record_safe; then
        exec 7>&-; native_status rear-wake display skipped unsafe-daemon-lease; return 0
    fi
    pid=$(core_rear_lease_pid) || pid=
    if [ -n "$pid" ]; then
        kind=$(core_rear_kind "$pid") || { exec 7>&-; return 1; }
        if [ "$kind" = current ]; then
            core_permitted rear-wake && core_rear_ready || { exec 7>&-; return 0; }
            exec 7>&-; native_status rear-wake display ready verified-existing-daemon; return 0
        fi
        core_rear_cleanup_locked || { exec 7>&-; return 1; }
        # Do not race a still-running getevent owner after a reviewed migration.
        while [ -d "$PROC/$pid" ] && [ "$count" -lt 20 ]; do count=$((count + 1)); sleep 0.1; done
        if [ -d "$PROC/$pid" ]; then
            exec 7>&-; native_status rear-wake display pending previous-daemon-stopping; return 0
        fi
    fi
    # Existing unleased or customized owners remain intact. Do not duplicate
    # their raw input listener, adopt them or terminate them by class name.
    for directory in "$PROC"/[0-9]*; do
        if core_rear_process "${directory##*/}"; then
            exec 7>&-; native_status rear-wake display skipped unowned-daemon-preserved; return 0
        fi
    done
    count=0
    while [ "$count" -lt 30 ]; do
        core_permitted rear-wake && core_rear_ready || { exec 7>&-; return 0; }
        count=$((count + 1))
        (export CLASSPATH="$MODDIR/rear-wake.jar"
         exec "$BB" nohup /system/bin/app_process /system/bin io.github.hyperosavd.RearDisplayWake) >> "$MODDIR/runtime.log" 2>&1 < /dev/null 7>&- 8>&- 9>&- &
        pid=$!; sleep 2
        if [ "$(core_rear_kind "$pid")" = current ]; then
            core_rear_receipt "$pid" || { exec 7>&-; return 1; }
            if ! core_permitted rear-wake; then core_rear_cleanup_locked; exec 7>&-; return 0; fi
            exec 7>&-; native_status rear-wake display ready verified-started-daemon; return 0
        fi
        core_permitted rear-wake || { exec 7>&-; return 0; }
    done
    exec 7>&-
    native_status rear-wake display failed daemon-not-ready
}

core_early() {
    core_identity && core_serial && core_thermal
}

core_late() {
    core_refresh; core_kernel; core_rear; core_policies; core_device_credential
}

core_policy_restore_required() {
    local feature=$1 file
    for file in "$MODDIR/disable" "$MODDIR/remove"; do
        [ ! -e "$file" ] && [ ! -L "$file" ] || return 0
    done
    for file in "$MODDIR/features.disabled" "$CORE_STATE/legacy-blocked.features"; do
        [ ! -L "$file" ] || return 1
        [ ! -e "$file" ] || core_safe_file "$file" || return 1
        if [ -f "$file" ] && "$BB" grep -Fxq "$feature" "$file"; then return 0; fi
    done
    return 1
}

core_package_policy() {
    local feature=$1 package=$2 mode=apply observed state reason extra
    native_assets || return 1
    if core_policy_restore_required "$feature"; then mode=restore
    elif ! core_permitted "$feature"; then
        if native_blocked; then native_status "$feature" "$package" pending module-update-staged
        else native_status "$feature" "$package" skipped unsafe-platform-state; fi
        return 0
    # This complete pinned ranchu inventory proves the OEM display and XRING
    # IMS HALs are absent; a transient missing live Binder is insufficient.
    elif ! native_privacy_eligible; then
        native_status "$feature" "$package" skipped unaudited-ranchu-vendor
        return 0
    fi
    observed=$("$BB" sh "$MODDIR/$feature-policy.sh" "$mode")
    IFS='|' read -r state reason extra <<EOF
$observed
EOF
    [ -z "$extra" ] && native_word "$state" && native_word "$reason" || return 1
    native_status "$feature" "$package" "$state" "$reason"
}

core_policies() {
    core_package_policy finddevice com.xiaomi.finddevice
    core_package_policy vendor-ims com.xring.ims
}

core_policy_cleanup() {
    local feature
    native_assets || return 1
    for feature in finddevice vendor-ims; do
        core_policy_restore_required "$feature" || continue
        "$BB" sh "$MODDIR/$feature-policy.sh" restore >/dev/null
    done
}

. "$MODDIR/device-credential.sh"
