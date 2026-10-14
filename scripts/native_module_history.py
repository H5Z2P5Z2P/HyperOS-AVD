"""Reviewed immutable Core releases eligible for unattended control migration.

Add the full manifest/checksum identities of each shipped module here before
changing its controls. Guest-provided receipts never authorize unknown code.
"""
import hashlib
import json

REVIEWED = (
    {'revision': 2, 'source_commit': '0ec75d3',
     'manifest_sha256': '88fd81c92905b0f75ff733aa4fe10994c8c6f4a779f995c26d294951fe4e98ca',
     'checksums_sha256': '41129ea926983baa8972f1a3579512c9a0f489701e67318355bb84ed3959cfd9'},
    {'revision': 3,
     'package_sha256': '311608ab7ecfcb490337e102a637c72e9f492e892fcaaa17d09e789a77066d61',
     'manifest_sha256': 'dfb9e53dcf9b3ce065f48c6dcfe6c191666fff253d274e9e0624e33c1c19382a',
     'checksums_sha256': 'fa204e270753618e9ff114c1131d118265eb359da682801679c546105833f355'},
    {'revision': 4, 'source_commit': '11e1abe0e35e61c0fc253c45935f2aaff0af4027',
     'package_sha256': 'c62f5834424a0292d36ea0a41d8fd34297bb62e739dbc68ca7b96b72b97a86a0',
     'manifest_sha256': 'c3eb03f52913ebe184392f0922b8494ddefdb7db9be6c883959dd4b3a38dbd38',
     'checksums_sha256': 'd50c1ea813e3933dd6e0fb23e1a0a6fd10ea5235151e4cd59d790ae67ed5b036'},
    {'revision': 5, 'source_commit': '0ada79d5c8f0bf7bc30237ea81d652701a0d0cd5',
     'package_sha256': 'bad68c06204069ed6848f5684dbc97e695f8dac5a5bf672456f086a8d81e8ea9',
     'manifest_sha256': 'ae131c55ff156a72be62116fe58de30bf7855be07ea327b1fa4d2c194c705af7',
     'checksums_sha256': '5981c413d1654fb83959b37b5bed9ede2fb38ecaa95dbd1c87a95a6e30fcfa61'},
    # Frozen before capability-proof tightening; installed development controls
    # were independently verified against this complete canonical archive.
    {'revision': 6, 'source_kind': 'unpublished-canonical-development-package',
     'package_sha256': '551a540dd4653969d68fa39507455c3d663f2905742b68c74f96d7afb3adf1cf',
     'manifest_sha256': 'edc36a84d62ac2f32c0333125ce6f545977cefa9055e53b362c9e26c49da0902',
     'checksums_sha256': '2ed45419f0d19c78d4f1e1665ed49042df51dd9f42ee9ab1019a54bd024384d6'},
    # Canonical capability data with the preceding frozen runtime; every
    # installed control byte matched that independently reconstructed package.
    {'revision': 6, 'source_kind': 'unpublished-canonical-intermediate-development-package',
     'package_sha256': '461128c64afbd1d944a5b458afa2cf8dcd5462969a5c2d9b8e65a58229056b24',
     'manifest_sha256': 'b64d414bbe125fa407934f9532056e572d8b3d528ae595db7490d07ee48244cd',
     'checksums_sha256': '03b675711f0d24633e688dd01fbeff8be5a12e16100ac766b2e4519fe477a337'},
    {'revision': 6, 'source_kind': 'unpublished-final-canonical-development-package',
     'package_sha256': '81a0a55db4e39d0d95c34ce889406182de0325b905a58046fb260c168314cf5b',
     'manifest_sha256': '516224391c68316513aa8fab4430f5cdfca4aaf8e4f942fdeea07010b42deaeb',
     'checksums_sha256': '57f2b841a029072510c781fd414fa470d09da66745efd027b4c892049b43755f'},
    {'revision': 7, 'source_kind': 'unpublished-final-canonical-development-package', 'package_sha256': 'cb2aea8adeb3f165971dff57f297adeaad0fc244a589e4451a5ec02524771f2a', 'manifest_sha256': 'abd7afb5282466ed05b59f2bc77529bb97d5746c910a1d0ca3ae0923f92432b7', 'checksums_sha256': '2e671f8403f731eadd3a03d02458ef5d35c72fe2c5b099bbda01bc294d97d56e', 'policy_controls': {'finddevice': {'helper': '278b5814e11ad732941a5d56601acf249c388cfbbc08913c1ab5c8e1121f6a77', 'recovery': 'e5ea856e42bfd4912e2d68e6443318219bde0a449115c7ad830985faa1b7620f'}, 'vendor-ims': {'helper': '2dbf9f5cae8b2c70fdcf544dc63c5898e0dface772a88e3d73a0f54eb9dcc0b3', 'recovery': 'c44ca11f17f8ef0271e55469f0a272fa7db6c77b56432ba57fae0e6b3920340e'}}},
    # Frozen complete controls, verified against the installed Pad module before
    # correcting the package snapshot section boundary.
    {'revision': 8, 'source_kind': 'unpublished-final-canonical-development-package', 'package_sha256': 'dbd8357045f9bc0bb7cd28c053c7816234f8f02225b381f2767203ec9deaefb7', 'manifest_sha256': '10af3289cd3b3b733fe458a35e427a947e5e5ad19ef810de8501ca7d203a97b0', 'checksums_sha256': '35b825474def8b02bdfdd412998436c0bc4a4522b2f278712632399488c401fa', 'policy_controls': {'finddevice': {'helper': 'a162d44c6f8cbf33eb15f47bdef1fb11ad2f4af1ae4d3dbc5408e1a218ffe6b8', 'recovery': '35cadc920231955c59f819facc0bec6908dfdd5bb06030965d497bead1719b2e'}, 'vendor-ims': {'helper': 'd90ed39962dafc01bbf5e8f99c2e72414d3a7e968b98e775368608b4dc42e274', 'recovery': '9420d622501ba85a82a1b8f31ea10757c28ce82c93eaf53bac944e3d48e1b3a8'}}},
    # Complete deployed controls, frozen before the vendor-only IMS connector gate.
    {'revision': 9, 'source_kind': 'unpublished-final-canonical-development-package', 'package_sha256': '588d76c4ef65333ffc9b9919a06f848f3c21216d2c6cf698a6442df1ba886ca6', 'manifest_sha256': '73778aa993948efef8f3f1e96e077d8a726dab9ae8f41d5ff949734c20ef9450', 'checksums_sha256': 'b8cd95fd879c49eb07d6d59c9cc9bf8c5b8b08361fda4d9a71c403f6853b1b6e', 'policy_controls': {'finddevice': {'helper': '757e1d195149901a38fa5202da153d603b9e970951c0aeae64cd2116c16446bc', 'recovery': 'a82a459466b211acfb15be9773e602ccc55765bc9013224672da559bac3977fd'}, 'vendor-ims': {'helper': 'b4076026dced0d18f2795734979901d298f139cf9d39c5b80759c5337b93672d', 'recovery': '77bc904612bd5ca887d629a94d2cbad369a8c35afa871e3517de4094c107266f'}}},
    # Deployed complete IMS/performance controls, frozen before the graphics
    # producer's missing physical frame-boost capability gate.
    {'revision': 10, 'source_kind': 'unpublished-final-canonical-development-package', 'package_sha256': 'a3b7d3e9a19fd2156664e4562dc5b4416c5b52e7dbbca02660baa75bd4b9d4b9', 'manifest_sha256': '08e3c8dba6856fb4d0fe2e5705228797433f31b3a2980ce5e1a9041122df8a7f', 'checksums_sha256': 'eafe2c308408582aa9e89d6b37afb4baee2a5b74905afaabaf5840efc36d4af8', 'policy_controls': {'finddevice': {'helper': '02310734be16af14eb2089ca93375eb9f2ab2c2971a9f7441e48293389a91087', 'recovery': 'c443829f14cd3ad883787995330f8380719ed1d5381c5145fcc661c9dc004b9a'}, 'vendor-ims': {'helper': 'b748953c98e0c4b6b60e113cbb415104c42acd5f5f3b34096594ee91822957fb', 'recovery': '5a953696cb582d7ce15aa258350810af41ee0b0c16b0272ac49145bab905feb7'}}},
    # Complete deployed Core11 controls, frozen before the owned rear gesture helper.
    {'revision': 11, 'source_commit': '03cccfa', 'source_kind': 'unpublished-final-canonical-development-package', 'package_sha256': 'e30e3554ec7b23e585897476f34ec8a5a5252c401b5931a6ac60c2462fff304b', 'manifest_sha256': '608c98a60b915c6ef2a4bc3abd8868d010ba4d41634604f2aac37be1acb2da67', 'checksums_sha256': '340f419d0cd201e96c9af1b62ec9338b6a1ba883d96ed795c8a6008139e87f23', 'policy_controls': {'finddevice': {'helper': 'cbcb899d940af66aedf810dc3d3bb9c3b32f6c1baa57d1cdb3700b9f28994d16', 'recovery': '234f14a7aae93ba1a81f1db957f59ae547747dd5a474c23d631686f28b092e9e'}, 'vendor-ims': {'helper': 'ca4cbd524d437294224d118c686d96f813242cbd1118882a0f10be0445366909', 'recovery': '9886ef31f038f4321922ddd7ccbd6a99c614dec553beeaad8a05bf61a9268b48'}}},
)


def checksum_for(manifest):
    if not isinstance(manifest, dict):
        return None
    body = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    expected = hashlib.sha256(body).hexdigest()
    return next((record['checksums_sha256'] for record in REVIEWED
                 if record['revision'] == manifest.get('revision')
                 and record['manifest_sha256'] == expected), None)
