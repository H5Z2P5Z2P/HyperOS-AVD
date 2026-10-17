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
    # Complete deployed Core12 controls, frozen before rear input and fade-state recovery.
    {'revision': 12, 'source_kind': 'unpublished-final-canonical-development-package', 'package_sha256': 'aa3f547bafa6924e7ff8f04356384c22cc6acf827014f6ae4abc0bc374855514', 'manifest_sha256': '677ba06c8158ec0a6d6ebccddac180de67c70d7863499c2c4f3fdb29086fc2a3', 'checksums_sha256': 'c7bbf4a27b0226318be7d2d9fb3ffc384cb798db0f836dcab2ecb3ebcb272cc7', 'policy_controls': {'finddevice': {'helper': '09c881e96d099634136dcdc84258bacf322692960356ce8064db1c6e05387c10', 'recovery': 'e7739552cf77fe288480a6f69616a7e1180fbac401f42bb1a97e97d04afcd655'}, 'vendor-ims': {'helper': 'b2260fc3f450cc1705a53b3a1e8536475cab6304007612678e0293dae4ca7102', 'recovery': '834bc0a7cf6aa9c8e5ae196b947968363f1b03d6367aec334e3b3f017535ce0b'}}},
    # Frozen deployed Core13 before missing-hardware retry capability fixes.
    {'revision': 13, 'source_commit': 'aad7cd24c1957d17e1c112eaa7057449a7e119bb', 'source_kind': 'unpublished-final-canonical-development-package', 'package_sha256': 'f0886e8d7832490afb87b4641caf0e84e1cf7b41b5b3a53743f2c567334c4e3c', 'manifest_sha256': '6b192ca830cfc13c7f680fff5bac31691e37d348327c58622baffb5b63439d86', 'checksums_sha256': 'dc5017041281acfb0b4d5df0fdcabdda17803789c818658fa18b7b7b1b2d52c7', 'policy_controls': {'finddevice': {'helper': 'c253b7d92ba594850a52f4654c970c801105bd25950d7d6a8ebce580febbe849', 'recovery': 'b9678384ddd3072d390d8d16b8ff85e02aab4a8b8a2330224a6f70caf991aa11'}, 'vendor-ims': {'helper': '4215c1558d7a96ec2b4f568d72b0f7c37408541048ef8f06933cdfb352a3dd2b', 'recovery': '9f8ffea1a55cf715fb61e2badf4c2cc92205200400d16b02d2ea6e230ca0e496'}}},
    # Frozen deployed Core14 before explicit-source stacked-bind remount fix.
    {'revision': 14, 'source_kind': 'deployed-final-canonical-package', 'package_sha256': 'd5469832f6c2014976748a572aa589a981c613d899d99b37133d39d29ff19f04', 'manifest_sha256': '89a2de073ef0708d10d0b6cbb92638726e256eefb7ad774c3ba4f6f52b5397a4', 'checksums_sha256': 'f49c3f709991edb809dece1997e0693bae5385b4031ab3fe64679b7da9f0888e', 'policy_controls': {'finddevice': {'helper': '65680161436b38ad22de359a1c15aac7c10367719237ded4daa353c17df93263', 'recovery': '7834863479f08a769f8b6bda814ed72c0a0244457493a038e8c04d4b85f5e24e'}, 'vendor-ims': {'helper': 'c063dce420cd6acad487a74a67c587c2cb0bfc37817f49c6176c4aa5136c44dc', 'recovery': 'd05d46c11e1422556e4b9be2f6e03e8266ebb628cd5b383065d19b1b31db5fca'}}},
    # Frozen deployed Core15 before the Pad scene-sensor compatibility guard.
    {'revision': 15, 'source_kind': 'deployed-final-canonical-package', 'package_sha256': 'bc0330d23683216c504beb38fdb7e81e521c4d7085f13e9e3d1ac37fa231a8fa', 'manifest_sha256': 'e85fee78faae160dcffd6725e566a006b86642d22da7891c33daa91f1c852d89', 'checksums_sha256': '71fd439241df235482803e155a42bb2486f6786aed89f31737d71d36905eb016', 'policy_controls': {'finddevice': {'helper': '99a3607421830516906c9216a704373c77d4e08a8efa5a957cb3851bb06c57a5', 'recovery': '5e8f3ed2e90c5445310d5f95f2f511326328ec3b33fe8a4f3e26343713629a8f'}, 'vendor-ims': {'helper': '046a29771ef8431833d7d19a85255c3d08f0aeaf56e579b628cb6d1899569b1c', 'recovery': 'ebe20d653f0aef502186b61660c2bcb33b73d67202a32cf850b3ea046d59aebc'}}},
    # Frozen deployed Core16 before verified content-addressed cache reuse.
    {'revision': 16, 'source_kind': 'deployed-final-canonical-package', 'package_sha256': '42ccf7b92c0ba41a08ee4b5e63ff806d09827adc29fdb4d4c8ae3263615f3417', 'manifest_sha256': '907bfe60a7814493facc12f0fa1a8dff708157d089bf21205451b7b79aff9985', 'checksums_sha256': '78ea6b5cb42eca9a8c22755e2edc4542be9e30a1a6a140e616195b0f7a59f85d', 'policy_controls': {'finddevice': {'helper': 'c67aae79a1cc8ddaf94e6ce59ee94121490c3c87920a853ef3b7ed5bc7a2f6d8', 'recovery': '57575e215612ac14f655b19a97812eb248053b9c8f45ef0311f39ae6a1f5e398'}, 'vendor-ims': {'helper': '8c4fb8e67492b1e5fe02ab3708c2fecd6a827bbccb0b218b133ad677537df811', 'recovery': 'db1aaacba6cc614fc188b747604b194bc1727691224a3e68a6fa6660f20d6604'}}},
    # Frozen deployed Core17 before per-call process-map scan batching.
    {'revision': 17, 'source_kind': 'deployed-final-canonical-package', 'package_sha256': '797ff25ee6b32c212ed6cf38eb7228cc50dd9ae33de61a31c17737bd849cc66e', 'manifest_sha256': '706e655f1a2235dd2284803c68dec063c7b52831bea41c1d78ac4c601e25e687', 'checksums_sha256': '31e5461352a04a5771e2dbfd2a9ecba429451be03dc5c3d53595eb28d5cd1910', 'policy_controls': {'finddevice': {'helper': '9ee75c8097d71babe793fa06a4138e539c7af39c725023514d02766374781a26', 'recovery': '27414971e4ac5c476e60a27e2e85d0d04704aa63857956b2d9b3efb2e5f71ff1'}, 'vendor-ims': {'helper': '9e32f98d444372e3834b95e9be3a083a9cb17b8108aae9117bad218af85854e2', 'recovery': '6a40df9f4f5aaf75dc3f5d76a32cb894dd16cde8d50b5513f2dbbccffeab0e75'}}},
    # Frozen Core18 controls before firmware-independent ABI guards.
    {'checksums_sha256': '1d7856b5b812ccf309f8d20e1393f4c1d6455a82117a6fb18651f55f3aa73514', 'manifest_sha256': '92194ddd65e588c152fda085a3617122484aef76f364c9456f9609ab7f9c6776', 'package_sha256': '51e89df525fe14fcf069e7013bb4a33a50a3b927dff50cc049482c9af141e7ef', 'policy_controls': {'finddevice': {'helper': '0cb8f66c37f7012fbaff11234b86b4ab8972989a3bdfe2319dcf6085570a817a', 'recovery': 'b10ffd236e10b35820a90441bab315bec51b05167cf4fb674415ea685bd4ebb0'}, 'vendor-ims': {'helper': 'bba4d843fd41bc89462164c786628545f161fa08849262730b0540b5648056e7', 'recovery': '46a2f87cffadee9c69cd9caf84b2d39540f4f9b74bea704c7998413b43dcd37c'}}, 'revision': 18, 'source_kind': 'deployed-final-canonical-package'},
)


def checksum_for(manifest):
    if not isinstance(manifest, dict):
        return None
    body = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    expected = hashlib.sha256(body).hexdigest()
    return next((record['checksums_sha256'] for record in REVIEWED
                 if record['revision'] == manifest.get('revision')
                 and record['manifest_sha256'] == expected), None)
