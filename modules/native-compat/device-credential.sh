#!/system/bin/sh
# Source after runtime.sh and platform.sh. No package or policy mutation here.

core_credential_recipe() {
    native_assets || return 1
    local recipe="$MODDIR/device-credential.tsv" expected
    core_safe_file "$recipe" && core_safe_file "$MODDIR/device-credential.jar" || return 1
    expected=$("$BB" awk '$2 == "device-credential.tsv" {
        if (NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ || found++) exit 1;
        value=$1} END {if (found != 1) exit 1; print value}' "$MODDIR/SHA256SUMS") || return 1
    native_hex "$expected" && [ "$(native_hash "$recipe")" = "$expected" ] || return 1
    "$BB" awk -F '|' '
        function hex(v) {return length(v) == 64 && v !~ /[^0-9a-f]/}
        NR==1 {if ($0!="schema|1") bad=1; next}
        NR==2 {if ($0!="class|io.github.hyperosavd.DeviceCredentialRuntime") bad=1; next}
        NR==3 {if (NF!=3 || $1!="jar" || $2!="device-credential.jar" || !hex($3)) bad=1; jar=$3; next}
        NR==4 {if (NF!=2 || $1!="client-dex" || !hex($2)) bad=1; dex=$2; next}
        NR==5 {if (NF!=3 || $1!="client-signer" || !hex($2) || $3!~/^[1-9][0-9]*$/ || length($3)>5) bad=1; signer=$2; bytes=$3; next}
        NR==6 {if ($0!="service|miui.sedc") bad=1; next}
        NR==7 {if ($0!="legacy|com.xiaomi.security.devicecredential.ISecurityDeviceCredentialManager.v1") bad=1; next}
        NR==8 {if ($0!="bound|com.xiaomi.security.devicecredential.ISecurityDeviceCredentialManager") bad=1; next}
        NR==9 {if ($0!="callback|com.xiaomi.security.devicecredential.ionremotecallfinishedlistener.v0") bad=1; next}
        NR==10 {if ($0!="unsupported|-100") bad=1; next}
        {bad=1}
        END {if (bad || NR!=10) exit 1; print jar "|" dex "|" signer "|" bytes}' "$recipe"
}

core_credential_process() {
    local pid=$1 directory="$PROC/$1"
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    [ -r "$directory/cmdline" ] && [ -r "$directory/environ" ] && [ -r "$directory/status" ] || return 1
    "$BB" tr '\000' '\n' < "$directory/cmdline" | "$BB" awk -v module="$MODDIR" -v state="$CORE_STATE" '
        NR==1 {if ($0!="/system/bin/app_process") bad=1}
        NR==2 {if ($0!="/system/bin") bad=1}
        NR==3 {if ($0!="io.github.hyperosavd.DeviceCredentialRuntime") bad=1}
        NR==4 {if ($0!="--serve") bad=1}
        NR==5 {if ($0!=module) bad=1}
        NR==6 {if ($0!=state "/credential-daemon.record") bad=1}
        END {exit bad || NR!=6}' || return 1
    "$BB" awk '$1=="Uid:" {found++;for(i=2;i<=5;i++)if($i!=0)bad=1} END {exit bad || found!=1}' "$directory/status" || return 1
    "$BB" tr '\000' '\n' < "$directory/environ" | "$BB" awk -v path="$MODDIR/device-credential.jar" '
        /^CLASSPATH=/ {if(found++)bad=1; value=substr($0,11)} END {exit bad || found!=1 || value!=path}'
}

core_credential_record() {
    local file="$CORE_STATE/credential-daemon.record"
    core_safe_file "$file" && [ "$("$BB" wc -l < "$file")" -eq 1 ] || return 1
    "$BB" awk -F '|' -v path="$MODDIR/device-credential.jar" '
        NF!=6 || $1!="1" || $2!~/^[a-f0-9-]+$/ || length($2)!=36 || $3!~/^[0-9]+$/ || $4!~/^[0-9]+$/ ||
        length($5)!=64 || $5~/[^0-9a-f]/ || $6!=path {bad=1} END {exit bad || NR!=1}' "$file"
}

core_credential_lease_pid() {
    local schema boot pid start jar path recipe current extra
    core_credential_record || return 1
    IFS='|' read -r schema boot pid start jar path < "$CORE_STATE/credential-daemon.record"
    [ "$boot" = "$(cat "$PROC/sys/kernel/random/boot_id")" ] && core_credential_process "$pid" || return 1
    [ "$(core_rear_start_time "$pid")" = "$start" ] || return 1
    recipe=$(core_credential_recipe) || return 1
    current=${recipe%%\|*}
    [ "$jar" = "$current" ] && [ "$(native_ns_hash "$pid" "$path")" = "$jar" ] || return 1
    printf '%s\n' "$pid"
}

core_credential_lock() {
    core_state_safe || return 1
    local lock="$CORE_STATE/credential.guard"
    if [ -e "$lock" ] || [ -L "$lock" ]; then core_safe_file "$lock" && [ ! -s "$lock" ] || return 1; fi
    exec 6>>"$lock" || return 1
    "$BB" flock -n 6 || { exec 6>&-; return 1; }
    chmod 600 "$lock" || { exec 6>&-; return 1; }
}

core_device_credential_cleanup() {
    core_credential_lock || return 0
    local pid start
    pid=$(core_credential_lease_pid) || { exec 6>&-; return 0; }
    start=$(core_rear_start_time "$pid") || { exec 6>&-; return 0; }
    if [ "$(core_credential_lease_pid)" = "$pid" ] && [ "$(core_rear_start_time "$pid")" = "$start" ]; then
        kill -TERM "$pid" || { exec 6>&-; return 1; }
        native_status device-credential miui.sedc disabled verified-owned-daemon-stopped
    fi
    exec 6>&-
}

core_credential_present() {
    /system/bin/service check miui.sedc 2>/dev/null | "$BB" grep -Fxq 'Service miui.sedc: found'
}

core_credential_apk() {
    local apk=$1 owner parent="${1%/*}"
    [ -f "$apk" ] && [ ! -L "$apk" ] && [ "$("$BB" stat -c %h "$apk")" = 1 ] || return 1
    owner=$("$BB" stat -c %u "$apk") || return 1
    case "$apk" in
        /data/app/*/*.apk) [ "$owner" = 1000 ] || return 1 ;;
        /system/*/*.apk|/system_ext/*/*.apk|/product/*/*.apk) [ "$owner" = 0 ] || return 1 ;;
        *) return 1 ;;
    esac
    while [ "$parent" != / ]; do
        [ -d "$parent" ] && [ ! -L "$parent" ] || return 1
        parent=${parent%/*}; [ -n "$parent" ] || parent=/
    done
}

core_credential_finddevice_owned() {
    local state="$CORE_STATE/finddevice-policy" row schema feature operation uid apk hash enabled hidden installed suspended signer phase extra expected actual
    core_safe_file "$state/receipt.tsv" && core_safe_file "$state/helper.sh" &&
        core_safe_file "$MODDIR/finddevice-policy.sh" || return 1
    [ "$(native_hash "$state/helper.sh")" = "$(native_hash "$MODDIR/finddevice-policy.sh")" ] || return 1
    [ "$("$BB" wc -l < "$state/receipt.tsv")" -eq 1 ] || return 1
    IFS='|' read -r schema feature operation uid apk hash enabled hidden installed suspended signer phase extra < "$state/receipt.tsv"
    [ "$schema|$feature|$operation|$hidden|$installed|$suspended|$phase" = '2|finddevice|hide|false|true|false|owned' ] && [ -z "$extra" ] || return 1
    case "$enabled:$uid" in 0:*|1:*) ;; *) return 1 ;; esac
    case "$uid" in ''|*[!0-9]*) return 1 ;; esac
    native_path "$apk" && native_hex "$hash" && core_credential_apk "$apk" && [ "$(native_hash "$apk")" = "$hash" ] || return 1
    expected=$("$BB" sed -n 's/^SIGNER=\([a-f0-9]*\)$/\1/p' "$MODDIR/finddevice-policy.sh")
    native_hex "$expected" && [ "$signer" = "$expected" ] || return 1
    actual=$(pm list packages -u -f --user 0 com.xiaomi.finddevice 2>/dev/null | "$BB" awk '
        index($0,"package:")==1 && /[=]com[.]xiaomi[.]finddevice$/ {sub(/^package:/, ""); sub(/=com[.]xiaomi[.]finddevice$/, ""); if(found++)bad=1; path=$0}
        END {if(bad || found!=1)exit 1; print path}') || return 1
    [ "$actual" = "$apk" ] || return 1
    dumpsys package com.xiaomi.finddevice 2>/dev/null | "$BB" awk -v uid="$uid" -v enabled="$enabled" '
        /^Packages:$/ {section=1; next} /^[^[:space:]]/ {section=0; active=0}
        section && /Package \[com[.]xiaomi[.]finddevice\]/ {if(found++)bad=1;active=1}
        active && /^[[:space:]]*(appId|userId)=/ {value=$0;sub(/.*=/,"",value); if(value!=uid || uid_seen++)bad=1}
        active && /User 0:/ {for(i=1;i<=NF;i++){split($i,p,"=");if(p[1]=="hidden" && p[2]=="true")h=1;if(p[1]=="installed" && p[2]=="true")iok=1;if(p[1]=="suspended" && p[2]=="false")s=1;if(p[1]=="enabled" && p[2]==enabled)e=1}seen++}
        END {exit bad || found!=1 || uid_seen!=1 || seen!=1 || !h || !iok || !s || !e}'
}

core_credential_client_signer() {
    /system/bin/abx2xml "$PACKAGES_XML" - 2>/dev/null | "$BB" awk -v RS='<' '
        function attr(t,k,v){if(!match(t,k "=\"[^\"]*\""))return "";v=substr(t,RSTART,RLENGTH);sub(/^[^\"]*\"/,"",v);sub(/\"$/,"",v);return v}
        /^package / {on=attr($0,"name")=="com.miui.analytics";if(on && found++)bad=1;current=0}
        /^\/package/ {on=0;current=0}
        on && /^sigs / {if(attr($0,"count")!="1" || sigs++)bad=1;current=1}
        /^\/sigs/ {current=0}
        /^cert / {idx=attr($0,"index");key=attr($0,"key");if(key!=""){if(keys[idx] && keys[idx]!=key)bad=1;keys[idx]=key}if(on && current){if(refs++)bad=1;wanted=idx}}
        END {if(bad || found!=1 || sigs!=1 || refs!=1 || wanted!~/^[0-9]+$/ || !keys[wanted])exit 1;print keys[wanted]}'
}

core_credential_ready() {
    CREDENTIAL_REASON=unaudited-ranchu-vendor
    native_guard && native_privacy_eligible || return 1
    CREDENTIAL_REASON=finddevice-policy-not-owned
    core_permitted finddevice && core_credential_finddevice_owned || return 1
    local recipe jar dex signer length extra apk actual cert directory pid context permissions
    recipe=$(core_credential_recipe) || { CREDENTIAL_REASON=unverified-credential-assets; return 1; }
    IFS='|' read -r jar dex signer length extra <<EOF
$recipe
EOF
    [ -z "$extra" ] && [ "$(native_hash "$MODDIR/device-credential.jar")" = "$jar" ] || return 1
    CREDENTIAL_REASON=unsupported-credential-client
    apk=$(native_active_apk com.miui.analytics) || return 1
    native_path "$apk" && core_credential_apk "$apk" || return 1
    actual=$("$BB" unzip -p "$apk" classes.dex 2>/dev/null | "$BB" sha256sum | "$BB" cut -d ' ' -f 1)
    [ "$actual" = "$dex" ] || return 1
    cert=$(core_credential_client_signer) || return 1
    [ "${#cert}" = "$length" ] || return 1
    case "$cert" in *[!0-9a-f]*) return 1 ;; esac
    [ "$(printf '%s' "$cert" | "$BB" sha256sum | "$BB" cut -d ' ' -f 1)" = "$signer" ] || return 1
    CREDENTIAL_REASON=credential-client-domain-unconfirmed
    pid=$(pidof com.miui.analytics)
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    [ "$("$BB" tr '\000' '\n' < "$PROC/$pid/cmdline")" = com.miui.analytics ] || return 1
    context=$(cat "$PROC/$pid/attr/current") || return 1
    CREDENTIAL_REASON=existing-selinux-route-unavailable
    permissions=$(CLASSPATH="$MODDIR/device-credential.jar" /system/bin/app_process /system/bin io.github.hyperosavd.DeviceCredentialRuntime --permissions "$context" 2>/dev/null) || return 1
    [ "$(printf '%s\n' "$permissions" | "$BB" wc -l)" -eq 3 ] &&
        printf '%s\n' "$permissions" | "$BB" grep -Fxq 'context=u:r:ksu:s0 sedc_add=true probe_add=true' &&
        printf '%s\n' "$permissions" | "$BB" grep -Fxq 'client_find=true client_call=true client_transfer=true server_call=true server_transfer=true' &&
        printf '%s\n' "$permissions" | "$BB" grep -Fxq 'finddevice_hidden=true'
}

core_device_credential() {
    if ! core_permitted device-credential || ! core_permitted finddevice; then core_device_credential_cleanup; return 0; fi
    core_credential_lock || return 0
    local pid recipe jar boot start row schema expected path directory count=0 file="$CORE_STATE/credential-daemon.record" next="$CORE_STATE/credential-daemon.record.next.$$"
    pid=$(core_credential_lease_pid) || pid=
    if [ -n "$pid" ]; then
        exec 6>&-
        if core_credential_present; then native_status device-credential miui.sedc ready verified-owned-unsupported-service
        else native_status device-credential miui.sedc pending owned-service-not-yet-registered; fi
        return 0
    fi
    if core_credential_present; then
        exec 6>&-; native_status device-credential miui.sedc skipped existing-service-preserved; return 0
    fi
    if [ -e "$file" ] || [ -L "$file" ]; then
        core_credential_record || { exec 6>&-; native_status device-credential miui.sedc skipped unknown-daemon-lease-preserved; return 0; }
        recipe=$(core_credential_recipe) || { exec 6>&-; return 0; }; jar=${recipe%%\|*}
        IFS='|' read -r schema boot pid start expected path < "$file"
        # Only this exact reviewed code may retire its stale receipt. A new
        # helper revision must freeze/admit the prior hash before migration.
        if [ "$expected" != "$jar" ] || { [ "$boot" = "$(cat "$PROC/sys/kernel/random/boot_id")" ] && [ -d "$PROC/$pid" ]; }; then
            exec 6>&-; native_status device-credential miui.sedc skipped unknown-daemon-lease-preserved; return 0
        fi
        rm "$file" || { exec 6>&-; return 1; }
    fi
    for directory in "$PROC"/[0-9]*; do
        [ -r "$directory/cmdline" ] || continue
        if "$BB" tr '\000' '\n' < "$directory/cmdline" | "$BB" grep -Fxq io.github.hyperosavd.DeviceCredentialRuntime; then
            exec 6>&-; native_status device-credential miui.sedc skipped unowned-daemon-preserved; return 0
        fi
    done
    if ! core_credential_ready; then
        exec 6>&-; native_status device-credential miui.sedc skipped "$CREDENTIAL_REASON"; return 0
    fi
    # Recheck the service immediately before launch. Never signal, replace or
    # adopt a registered service just because it has a familiar descriptor.
    if core_credential_present; then exec 6>&-; native_status device-credential miui.sedc skipped existing-service-preserved; return 0; fi
    recipe=$(core_credential_recipe) || { exec 6>&-; return 1; }; jar=${recipe%%\|*}
    [ ! -e "$next" ] && [ ! -L "$next" ] || { exec 6>&-; return 1; }
    (export CLASSPATH="$MODDIR/device-credential.jar"
     exec "$BB" nohup /system/bin/app_process /system/bin io.github.hyperosavd.DeviceCredentialRuntime --serve "$MODDIR" "$file") >> "$MODDIR/runtime.log" 2>&1 < /dev/null 6>&- 7>&- 8>&- 9>&- &
    pid=$!
    while [ "$count" -lt 30 ]; do
        core_credential_process "$pid" && break
        [ -d "$PROC/$pid" ] || break
        count=$((count + 1)); sleep 0.1
    done
    if ! core_credential_process "$pid"; then exec 6>&-; native_status device-credential miui.sedc failed daemon-identity-unconfirmed; return 0; fi
    boot=$(cat "$PROC/sys/kernel/random/boot_id"); start=$(core_rear_start_time "$pid")
    row="1|$boot|$pid|$start|$jar|$MODDIR/device-credential.jar"
    (set -C; printf '%s\n' "$row" > "$next") && chmod 600 "$next" && ln "$next" "$file" && rm "$next" || { exec 6>&-; return 1; }
    count=0
    while [ "$count" -lt 30 ]; do
        if core_credential_lease_pid >/dev/null && core_credential_present; then
            exec 6>&-; native_status device-credential miui.sedc ready verified-started-unsupported-service; return 0
        fi
        [ -d "$PROC/$pid" ] || break
        count=$((count + 1)); sleep 0.1
    done
    exec 6>&-
    native_status device-credential miui.sedc failed unsupported-service-not-ready
}
