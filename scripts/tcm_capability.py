"""Offline data for the audited OEM optional idle-connection monitor switch."""

CLIENT_PATH = '/system/framework/tcmclient.jar'
CLIENT_SHA256 = '60b95dd59e317c51c3121b3fd2713a0294693a8b154803fd010af546fe6e2704'
PROPERTY = 'persist.vendor.dpm.tcm'
DISABLED = '1'
PINS = (
    (CLIENT_PATH, CLIENT_SHA256),
    ('/system_ext/etc/init/dpmd.rc', 'f2b68252ae6086ebeb67ef5885f83c63cdd4faf2fe6f00024beb678bd0ae6261'),
    ('/system_ext/bin/dpmd', 'baeb48b3e7dd4d4ec08fd7911ae078890fe1a4c53ebc96bccf56c5b133dda52f'),
    ('/system_ext/lib64/libdpmframework.so', 'e9383d06e168bd26ddd87ed8de9e3ec956ca68843e71bc41d5cc77e22d63c4eb'),
    ('/system_ext/lib64/libdpmtcm.so', 'ef5895c933b6df51da84d6182ddd5ef6d6055a55bc4a8c19d672e62b08b96c0d'),
    ('/system_ext/lib64/libdpmctmgr.so', '2e4c88ab9de96d165b3fc6fa0aede5b02f07bb7da7a574aaef841213ee612fd5'),
    ('/system_ext/framework/com.qti.dpmframework.jar', '136afbfc7e3c30ae04e5b1164f0769584cd1f652921b10d822b5282bf5ca81d9'),
    ('/system_ext/etc/selinux/system_ext_sepolicy.cil', '95b3121a3efd5a4cdf88c551553aaf6c228f76b012d88a2739ce36a101f09870'),
    ('/system_ext/etc/selinux/system_ext_file_contexts', 'beb7b21f4e6709ebca8e79c7b161c3daac31527b59f32714d4ea9c977838b4eb'),
    ('/vendor/etc/selinux/vendor_sepolicy.cil', 'f3328ba1ca05e2f1efaff107b1ee80841748e9891e4206dd0af31f90dc8bca07'),
)


def files():
    """Keep the exact client pin and supported native policy in one producer."""
    rows = ('schema|1', *(f'file|{path}|{checksum}' for path, checksum in PINS),
            f'property|{PROPERTY}|{DISABLED}', 'policy|unset-current-boot-only')
    return {'tcm-capability.tsv': ('\n'.join(rows) + '\n').encode()}
