# Security

Do not report suspected Runtime Pack supply-chain issues in a public issue.
Use GitHub's private vulnerability reporting for this repository, or contact the
OpenSquilla maintainers through the security channel published by the organization.

Published Runtime Pack tags and mirrored OSS object paths are immutable. If a source
pin, generated archive, catalog digest, or SBOM is wrong, maintainers must revoke the
draft or affected catalog and publish a new catalog version. Existing bytes must not
be replaced under the same tag.

GitHub immutable releases must be enabled before the first publication. Runtime Packs
reuse the versioned `opensquilla-releases` bucket only under the isolated
`runtime-packs/<release-tag>/` prefix. Because OSS ignores `forbid-overwrite` when
versioning is enabled, the mirror treats that header as defense in depth only: it
refuses existing different bytes, verifies authenticated and anonymous downloads, and
records each non-null Version ID. The mirror workflow never writes a desktop release
or update-channel path. If the reused credential currently has broader rights, the
protected environment and required reviewers are compensating controls until a
prefix-scoped RAM identity can replace it; do not grant new delete or bucket-policy
permissions for Runtime Packs.

The client path requires anonymous `GetObject` only under `runtime-packs/*`. Anonymous
listing and every mutation remain forbidden. Mirroring is successful only after an
unsigned HTTPS download of every object matches the corresponding GitHub Release byte
for byte.

The GitHub Draft Release and the protected `runtime-pack-release` and
`runtime-pack-oss` environments require maintainer approval. Reusing an existing
credential is an operational compromise, not an integrity dependency: where IAM
changes are available, scope a separate RAM identity to `runtime-packs/*`. Regardless
of credential scope, clients reject any byte sequence whose catalog size or SHA-256
does not match and try the alternate GitHub/OSS source.
