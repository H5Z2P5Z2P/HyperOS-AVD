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
)


def checksum_for(manifest):
    if not isinstance(manifest, dict):
        return None
    body = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    expected = hashlib.sha256(body).hexdigest()
    return next((record['checksums_sha256'] for record in REVIEWED
                 if record['revision'] == manifest.get('revision')
                 and record['manifest_sha256'] == expected), None)
