# Security

Do not report suspected Runtime Pack supply-chain issues in a public issue.
Use GitHub's private vulnerability reporting for this repository, or contact the
OpenSquilla maintainers through the security channel published by the organization.

Published Runtime Pack tags and mirrored OSS object paths are immutable. If a source
pin, generated archive, catalog digest, or SBOM is wrong, maintainers must revoke the
draft or affected catalog and publish a new catalog version. Existing bytes must not
be replaced under the same tag.

GitHub immutable releases must be enabled before the first publication. The OSS
bucket must remain unversioned so `PutObject` with `forbid-overwrite=true` cannot be
silently converted into a new object version. The mirror identity must not have
delete, bucket-administration, or desktop update-channel permissions.

The GitHub Draft Release and the protected `runtime-pack-release` and
`runtime-pack-oss` environments require maintainer approval. OSS credentials must be
scoped to `runtime-packs/*` and must not have permission to modify desktop update
channels.
