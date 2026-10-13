#!/system/bin/sh
# Only the owned package visibility/enabled state is changed; app data is kept.
BB=/data/adb/ksu/bin/busybox
MODULE=/data/adb/modules/hyperos_avd_native_compat
STATE=/data/adb/hyperos-avd-core/@FEATURE@-policy
WRAPPER=/data/adb/service.d/hyperos-avd-@FEATURE@-restore.sh
FEATURE=@FEATURE@
OPERATION=@OPERATION@
PACKAGE=@PACKAGE@
EXPECTED_APK=@EXPECTED_APK@
SIGNER=@SIGNER_HEX_SHA256@
umask 077

fd_hash() { "$BB" sha256sum "$1" 2>/dev/null | "$BB" cut -d ' ' -f 1; }
safe_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$("$BB" stat -c %u:%h "$1")" = 0:1 ]; }
reviewed_helper() { case "$1" in @PREVIOUS_HELPERS@) return 0 ;; *) return 1 ;; esac; }
reviewed_controls() { case "$1|$2" in @PREVIOUS_CONTROL_PAIRS@) return 0 ;; *) return 1 ;; esac; }
safe_dir() {
    local path=$1 owner
    while [ "$path" != / ]; do
        [ ! -L "$path" ] || return 1
        if [ -e "$path" ]; then
            [ -d "$path" ] || return 1
            owner=$("$BB" stat -c %u "$path")
            [ "$owner" = 0 ] || { [ "$path" = /data ] && [ "$owner" = 1000 ]; } || return 1
        fi
        path=${path%/*}; [ -n "$path" ] || path=/
    done
    [ ! -e "$1" ] || [ "$("$BB" stat -c %u "$1")" = 0 ]
}
emit_recovery() {
    "$BB" sed "s/@HELPER_SHA256@/$1/g" <<'RECOVERY'
@RECOVERY_TEMPLATE@
RECOVERY
}
state_inventory_safe() {
    local entry
    [ ! -e "$STATE" ] && [ ! -L "$STATE" ] && return 0
    for entry in "$STATE"/* "$STATE"/.[!.]* "$STATE"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        case "$entry" in "$STATE/lock"|"$STATE/helper.sh"|"$STATE/receipt.tsv") ;; *) return 1 ;; esac
    done
}
result() { printf '%s|%s\n' "$1" "$2"; }
guard() {
    [ "$(id -u)" = 0 ] && [ -x "$BB" ] && [ "$(getprop ro.boot.hardware)" = ranchu ] || return 1
    case "$(getprop ro.mi.os.version.incremental)" in OS4.*|4.*) ;; *) return 1 ;; esac
    safe_dir "$STATE" && safe_dir "${WRAPPER%/*}" && state_inventory_safe
}
snapshot() {
    local info paths apk uid state cert checksum hidden installed suspended
    # Hidden packages are absent from ordinary pm path results. Query known
    # packages and bind exactly this package, including its active update APK.
    paths=$(pm list packages -u -f --user 0 "$PACKAGE" 2>/dev/null | "$BB" awk -v package="$PACKAGE" '
        index($0,"package:")==1 && substr($0,length($0)-length(package)) == "=" package {
            print substr($0,1,length($0)-length(package)-1)}') || return 1
    [ "$(printf '%s\n' "$paths" | "$BB" wc -l)" -eq 1 ] || return 1
    case "$paths" in package:/product/*/*.apk|package:/system/*/*.apk|package:/system_ext/*/*.apk|package:/data/app/*/*.apk) ;; *) return 1 ;; esac
    apk=${paths#package:}
    case "$apk" in *'/../'*|*'/./'*|*'//'*) return 1 ;; esac
    [ "$(printf '%s' "$apk" | "$BB" tr -d 'A-Za-z0-9_./=+~-')" = '' ] && [ -f "$apk" ] && [ ! -L "$apk" ] || return 1
    info=$(dumpsys package "$PACKAGE" 2>/dev/null | "$BB" awk -v package="$PACKAGE" '
        /^Packages:$/ {section=1; on=0; next}
        /^[^[:space:]]/ {section=0; on=0; next}
        section && /^[[:space:]]*Package \[/ {
            name=$0; sub(/.*Package \[/, "", name); sub(/\].*/, "", name);
            on=(name == package); if (on && found++) bad=1; next
        }
        on && /^[[:space:]]*(appId|userId)=/ {value=$0; sub(/.*=/, "", value); if (uid && uid != value) bad=1; uid=value}
        on && /pkgFlags=\[/ && /(^|[[:space:]])SYSTEM([[:space:]]|\])/ {system_app=1}
        on && /User 0:/ {
            for(i=1;i<=NF;i++) {split($i,pair,"=");if(pair[1]=="installed")installed=pair[2];if(pair[1]=="hidden")hidden=pair[2];if(pair[1]=="suspended")suspended=pair[2]}
            value=$0; sub(/.* enabled=/, "", value); sub(/[[:space:]].*/, "", value); if (seen++) bad=1; state=value
        }
        END {if (bad || found != 1 || !system_app || seen != 1 || uid !~ /^[0-9]+$/ || state !~ /^[0-4]$/ ||
            hidden !~ /^(true|false)$/ || installed !~ /^(true|false)$/ || suspended !~ /^(true|false)$/) exit 1;
            print uid "|" state "|" hidden "|" installed "|" suspended}') || return 1
    IFS='|' read -r uid state hidden installed suspended <<EOF
$info
EOF
    [ "${#uid}" -le 5 ] && [ "$uid" -ge 1000 ] || return 1
    # PackageManager has already authenticated installed signatures. Resolve its
    # complete current certificate through the global XML index, not Java hashCode.
    cert=$(/system/bin/abx2xml /data/system/packages.xml - 2>/dev/null | "$BB" awk -v RS='<' -v package="$PACKAGE" '
        function attr(text, key, value) {if (!match(text, key "=\"[^\"]*\"")) return ""; value=substr(text,RSTART,RLENGTH); sub(/^[^\"]*\"/, "", value); sub(/\"$/, "", value); return value}
        /^package / {on=(attr($0,"name") == package); if (on && found++) bad=1; current=0}
        /^\/package/ {on=0; current=0}
        on && /^sigs / {if (attr($0,"count") != "1" || sigs++) bad=1; current=1}
        /^\/sigs/ {current=0}
        /^cert / {
            idx=attr($0,"index"); key=attr($0,"key");
            if (key != "") {if (keys[idx] && keys[idx] != key) bad=1; keys[idx]=key}
            if (on && current) {if (refs++) bad=1; wanted=idx}
        }
        END {if (bad || found != 1 || sigs != 1 || refs != 1 || wanted !~ /^[0-9]+$/ || !keys[wanted]) exit 1; print keys[wanted]}') || return 1
    [ "${#cert}" = @SIGNER_HEX_LENGTH@ ] || return 1
    case "$cert" in *[!0-9a-f]*) return 1 ;; esac
    [ "$(printf '%s' "$cert" | "$BB" sha256sum | "$BB" cut -d ' ' -f 1)" = "$SIGNER" ] || return 1
    checksum=$(fd_hash "$apk")
    [ "${#checksum}" = 64 ] || return 1
    [ "$EXPECTED_APK" = any ] || [ "$checksum" = "$EXPECTED_APK" ] || return 1
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$uid" "$apk" "$checksum" "$state" "$hidden" "$installed" "$suspended" "$SIGNER"
}
receipt_read() {
    safe_file "$STATE/receipt.tsv" || return 1
    local schema feature operation extra
    IFS='|' read -r schema feature operation OLD_UID OLD_APK OLD_HASH OLD_STATE OLD_HIDDEN OLD_INSTALLED OLD_SUSPENDED OLD_SIGNER PHASE extra < "$STATE/receipt.tsv"
    [ "$schema" = 2 ] && [ "$feature" = "$FEATURE" ] && [ "$operation" = "$OPERATION" ] &&
        [ -z "$extra" ] && [ "$OLD_SIGNER" = "$SIGNER" ] || return 1
    case "$OLD_STATE:$PHASE" in 0:prepared|1:prepared|0:owned|1:owned) ;; *) return 1 ;; esac
    [ "$OLD_HIDDEN:$OLD_INSTALLED:$OLD_SUSPENDED" = false:true:false ] || return 1
    [ "$OLD_UID" != '' ] && [ "${#OLD_HASH}" = 64 ] || return 1
    case "$OLD_UID" in *[!0-9]*) return 1 ;; esac
    case "$OLD_HASH" in *[!0-9a-f]*) return 1 ;; esac
    [ "$("$BB" wc -l < "$STATE/receipt.tsv")" -eq 1 ] || return 1
    RECEIPT_HASH=$(fd_hash "$STATE/receipt.tsv")
    [ "${#RECEIPT_HASH}" = 64 ]
}
original_snapshot() { printf '%s|%s|%s|%s|false|true|false|%s\n' "$OLD_UID" "$OLD_APK" "$OLD_HASH" "$OLD_STATE" "$OLD_SIGNER"; }
owned_snapshot() {
    if [ "$OPERATION" = hide ]; then printf '%s|%s|%s|%s|true|true|false|%s\n' "$OLD_UID" "$OLD_APK" "$OLD_HASH" "$OLD_STATE" "$OLD_SIGNER"
    else printf '%s|%s|%s|3|false|true|false|%s\n' "$OLD_UID" "$OLD_APK" "$OLD_HASH" "$OLD_SIGNER"; fi
}
legacy_receipt() {
    [ -e "$STATE/receipt.tsv" ] || return 0
    [ "$("$BB" cut -d '|' -f 1 "$STATE/receipt.tsv")" = 1 ] || return 0
    safe_file "$STATE/receipt.tsv" && safe_file "$STATE/helper.sh" && safe_file "$WRAPPER" &&
        { reviewed_controls "$(fd_hash "$STATE/helper.sh")" "$(fd_hash "$WRAPPER")" || recovery_owned; } || return 1
    # A canonical current callback/helper with an old receipt is the sole
    # reviewed partial upgrade state after atomic control publication.
    local schema extra now
    IFS='|' read -r schema OLD_UID OLD_APK OLD_HASH OLD_STATE OLD_SIGNER PHASE extra < "$STATE/receipt.tsv"
    [ "$schema" = 1 ] && [ -z "$extra" ] && [ "$OLD_SIGNER" = "$SIGNER" ] &&
        [ "$("$BB" wc -l < "$STATE/receipt.tsv")" -eq 1 ] || return 1
    case "$OLD_STATE:$PHASE" in 0:prepared|1:prepared|0:owned|1:owned) ;; *) return 1 ;; esac
    case "$OLD_UID" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#OLD_HASH}" = 64 ] || return 1
    case "$OLD_HASH" in *[!0-9a-f]*) return 1 ;; esac
    RECEIPT_HASH=$(fd_hash "$STATE/receipt.tsv")
    now=$(snapshot) || return 1
    OLD_HIDDEN=false; OLD_INSTALLED=true; OLD_SUSPENDED=false
    if [ "$now" = "$(original_snapshot)" ]; then
        [ "$PHASE" = prepared ] || [ "$1" = restore ] || return 1
        # Core7's rejected FindDevice command left a prepared transaction;
        # its exact unchanged baseline is proof of no package-state mutation.
        install_recovery && cleanup_owned || return 1
        return 0
    fi
    [ "$PHASE" = owned ] &&
        [ "$now" = "$OLD_UID|$OLD_APK|$OLD_HASH|3|false|true|false|$OLD_SIGNER" ] || return 1
    install_recovery || return 1
    if [ "$OPERATION" = hide ]; then
        [ "$(snapshot)" = "$now" ] || return 1
        if [ "$OLD_STATE" = 0 ]; then pm default-state --user 0 "$PACKAGE" >/dev/null 2>&1
        else pm enable --user 0 "$PACKAGE" >/dev/null 2>&1; fi
        [ "$(snapshot)" = "$(original_snapshot)" ] && cleanup_owned
    else receipt_write owned; fi
}

receipt_write() {
    local phase=$1 file="$STATE/receipt.next.$$"
    [ ! -e "$file" ] && [ ! -L "$file" ] || return 1
    (set -C; printf '2|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$FEATURE" "$OPERATION" "$OLD_UID" "$OLD_APK" "$OLD_HASH" "$OLD_STATE" "$OLD_HIDDEN" "$OLD_INSTALLED" "$OLD_SUSPENDED" "$SIGNER" "$phase" > "$file") || return 1
    chmod 600 "$file" || return 1
    if [ -e "$STATE/receipt.tsv" ] || [ -L "$STATE/receipt.tsv" ]; then
        safe_file "$STATE/receipt.tsv" && [ "$(fd_hash "$STATE/receipt.tsv")" = "$RECEIPT_HASH" ] || return 1
        mv "$file" "$STATE/receipt.tsv" || return 1
    else
        ln "$file" "$STATE/receipt.tsv" && rm "$file" || return 1
    fi
    RECEIPT_HASH=$(fd_hash "$STATE/receipt.tsv")
}
recovery_owned() {
    safe_file "$STATE/helper.sh" && safe_file "$WRAPPER" || return 1
    local helper_sha
    helper_sha=$(fd_hash "$STATE/helper.sh")
    [ "$helper_sha" = "$(fd_hash "$0")" ] || reviewed_helper "$helper_sha" || return 1
    [ "$(fd_hash "$WRAPPER")" = "$(emit_recovery "$(fd_hash "$0")" | "$BB" sha256sum | "$BB" cut -d ' ' -f 1)" ]
}
install_recovery() {
    local helper="$STATE/helper.sh" source=$0 wrapper="$STATE/wrapper.next.$$" staged="$STATE/helper.next.$$" helper_sha wrapper_sha
    mkdir -p "$STATE" "${WRAPPER%/*}" || return 1
    if [ -e "$helper" ] || [ -L "$helper" ]; then
        safe_file "$helper" || return 1
        helper_sha=$(fd_hash "$helper")
        [ "$helper_sha" = "$(fd_hash "$source")" ] || reviewed_helper "$helper_sha" || return 1
    fi
    if [ -e "$WRAPPER" ] || [ -L "$WRAPPER" ]; then
        safe_file "$WRAPPER" || return 1
        wrapper_sha=$(fd_hash "$WRAPPER")
        recovery_owned || reviewed_controls "$helper_sha" "$wrapper_sha" || return 1
    fi
    if [ "$helper_sha" = "$(fd_hash "$source")" ] && recovery_owned; then return 0; fi
    [ ! -e "$wrapper" ] && [ ! -L "$wrapper" ] && [ ! -e "$staged" ] && [ ! -L "$staged" ] || return 1
    (set -C; emit_recovery "$(fd_hash "$source")" > "$wrapper") && chmod 700 "$wrapper" || return 1
    # Publish the callback first. Its two exact pins cover the authenticated
    # old helper until the replacement inode is atomically published.
    if [ -n "$wrapper_sha" ]; then
        [ "$(fd_hash "$WRAPPER")" = "$wrapper_sha" ] && mv "$wrapper" "$WRAPPER" || return 1
    else ln "$wrapper" "$WRAPPER" && rm "$wrapper" || return 1; fi
    if [ "$helper_sha" = "$(fd_hash "$source")" ]; then return 0; fi
    (set -C; cat "$source" > "$staged") && chmod 700 "$staged" || return 1
    if [ -n "$helper_sha" ]; then
        [ "$(fd_hash "$helper")" = "$helper_sha" ] && mv "$staged" "$helper" || return 1
    else ln "$staged" "$helper" && rm "$staged" || return 1; fi
}

cleanup_owned() {
    if [ -e "$STATE/receipt.tsv" ] || [ -L "$STATE/receipt.tsv" ]; then
        safe_file "$STATE/receipt.tsv" && [ "$(fd_hash "$STATE/receipt.tsv")" = "$RECEIPT_HASH" ] &&
            rm "$STATE/receipt.tsv" || return 1
    fi
    if recovery_owned; then
        rm "$WRAPPER"
    fi
}
restore() {
    legacy_receipt restore || { result skipped unreviewed-legacy-policy-state; return 1; }
    if [ ! -e "$STATE/receipt.tsv" ] && [ ! -L "$STATE/receipt.tsv" ]; then cleanup_owned; result skipped no-owned-package-state; return 0; fi
    receipt_read || { result skipped unknown-policy-receipt; return 1; }
    local now uid apk checksum state hidden installed suspended signer output command_rc
    now=$(snapshot) || { result skipped unsupported-package-identity; return 1; }
    IFS='|' read -r uid apk checksum state hidden installed suspended signer <<EOF
$now
EOF
    [ "$uid|$apk|$checksum|$signer" = "$OLD_UID|$OLD_APK|$OLD_HASH|$OLD_SIGNER" ] || { result skipped package-identity-changed; return 1; }
    if [ "$now" = "$(original_snapshot)" ]; then cleanup_owned; result disabled original-state-retained; return 0; fi
    [ "$PHASE" = owned ] && [ "$now" = "$(owned_snapshot)" ] || { result skipped user-state-preserved; return 1; }
    [ "$(snapshot)" = "$now" ] || { result skipped package-state-raced; return 1; }
    if [ "$OPERATION" = hide ]; then output=$(pm unhide --user 0 "$PACKAGE" 2>/dev/null)
    elif [ "$OLD_STATE" = 0 ]; then output=$(pm default-state --user 0 "$PACKAGE" 2>/dev/null)
    else output=$(pm enable --user 0 "$PACKAGE" 2>/dev/null); fi
    [ "$(snapshot)" = "$(original_snapshot)" ] || { result failed package-restore-unconfirmed; return 1; }
    cleanup_owned; result disabled original-state-restored
}
apply() {
    legacy_receipt apply || { result skipped unreviewed-legacy-policy-state; return 1; }
    local now uid apk checksum state hidden installed suspended signer output command_rc
    now=$(snapshot) || { result skipped unsupported-package-identity; return 1; }
    if [ -e "$STATE/receipt.tsv" ] || [ -L "$STATE/receipt.tsv" ]; then
        receipt_read || { result skipped unknown-policy-receipt; return 1; }
        if [ "$now" = "$(owned_snapshot)" ] && [ "$PHASE" = owned ]; then
            install_recovery || { result skipped recovery-owner-conflict; return 1; }
            result ready owned-package-$OPERATION; return 0
        fi
        if [ "$PHASE" != prepared ] || [ "$now" != "$(original_snapshot)" ]; then result skipped user-state-preserved; return 1; fi
    fi
    IFS='|' read -r uid apk checksum state hidden installed suspended signer <<EOF
$now
EOF
    case "$state:$hidden:$installed:$suspended" in 0:false:true:false|1:false:true:false) ;; *) result skipped user-state-preserved; return 0 ;; esac
    OLD_UID=$uid; OLD_APK=$apk; OLD_HASH=$checksum; OLD_STATE=$state
    OLD_HIDDEN=$hidden; OLD_INSTALLED=$installed; OLD_SUSPENDED=$suspended; OLD_SIGNER=$signer
    install_recovery || { result skipped recovery-owner-conflict; return 1; }
    [ "$(snapshot)" = "$now" ] || { result skipped package-state-raced; return 1; }
    receipt_write prepared || { result failed package-receipt-unavailable; return 1; }
    [ "$(snapshot)" = "$now" ] || { result skipped package-state-raced; return 1; }
    if [ "$OPERATION" = hide ]; then output=$(pm hide --user 0 "$PACKAGE" 2>/dev/null)
    else output=$(pm disable-user --user 0 "$PACKAGE" 2>/dev/null); fi
    command_rc=$?
    # The PM hide shell command can return zero even when its setter rejected
    # the request. Authenticate the complete resulting state, never only RC.
    [ "$command_rc" = 0 ] && [ "$(snapshot)" = "$(owned_snapshot)" ] || { result failed package-policy-unconfirmed; return 1; }
    receipt_write owned || { result failed package-receipt-unavailable; return 1; }
    result ready owned-package-$OPERATION
}

boot() {
    local count=0
    while [ "$(getprop sys.boot_completed)" != 1 ]; do count=$((count+1)); [ "$count" -lt 300 ] || return 1; sleep 1; done
    if [ -e "$MODULE" ] || [ -L "$MODULE" ]; then
        [ -d "$MODULE" ] && [ ! -L "$MODULE" ] && safe_file "$MODULE/module.prop" || return 1
        "$BB" grep -Fxq 'id=hyperos_avd_native_compat' "$MODULE/module.prop" &&
            "$BB" grep -Fxq 'author=HyperOS-AVD' "$MODULE/module.prop" || return 1
        if [ ! -e "$MODULE/disable" ] && [ ! -L "$MODULE/disable" ] && [ ! -e "$MODULE/remove" ] && [ ! -L "$MODULE/remove" ]; then
            safe_file "$MODULE/features.disabled" || return 1
            "$BB" grep -Fxq "$FEATURE" "$MODULE/features.disabled" || return 0
        fi
    fi
    restore
}
guard || { result skipped unaudited-policy-environment; exit 1; }
if [ ! -e "$STATE" ]; then mkdir -p "$STATE" && chmod 700 "$STATE" || exit 1; fi
[ "$("$BB" stat -c %a "$STATE")" = 700 ] || exit 1
if [ -e "$STATE/lock" ] || [ -L "$STATE/lock" ]; then safe_file "$STATE/lock" || exit 1; fi
exec 8>>"$STATE/lock" || exit 1
safe_file "$STATE/lock" && [ "$("$BB" stat -c %s "$STATE/lock")" = 0 ] || exit 1
"$BB" flock -n 8 || { result pending policy-transaction-busy; exit 0; }
case "$1" in apply) apply ;; restore) restore ;; boot) boot ;; *) exit 1 ;; esac
