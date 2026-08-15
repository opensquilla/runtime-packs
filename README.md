# OpenSquilla Runtime Packs

This repository builds the optional Python, Node.js, and Git Bash runtimes used by
OpenSquilla. The desktop application embeds an immutable catalog containing each
archive's exact filename, size, and SHA-256 digest. It never trusts a mutable remote
catalog or a caller-provided URL.

Runtime Packs are release artifacts, not application updates. Every archive contains
only these top-level entries:

```text
pack-manifest.json
payload/
licenses/
SBOM.spdx.json
```

The release workflow builds and probes all six targets on their native architecture,
creates deterministic `tar.xz` archives, audits the exact asset set, and leaves the
GitHub Release in draft state for maintainer approval. Publishing triggers an
immutable byte-for-byte mirror to the Beijing OSS bucket; no `latest` alias is made.

## Local verification

```bash
python -m pytest -q
python scripts/validate_sources.py sources.json
```

Individual packs are built by CI because probes must run on the target operating
system and CPU architecture. Source archives, versions, and digests are pinned in
[`sources.json`](sources.json).

## Trust and release policy

- Upstream bytes are accepted only after their pinned SHA-256 is verified.
- Git for Windows self-extracting archives are unpacked only inside trusted CI; the
  OpenSquilla client never downloads or executes the SFX.
- Pack extraction rejects traversal, link escapes, special files, duplicate paths,
  and expansion beyond declared limits. Safe internal upstream links are resolved inside
  the reviewed archive namespace and materialized as regular files; links never ship
  in a Runtime Pack.
- Published tags and OSS paths are immutable. Corrections require a new catalog
  version and tag.
- Publishing a draft release and configuring protected OSS credentials remain human
  maintainer actions.

## Required repository and infrastructure controls

The workflows intentionally fail closed until maintainers configure all of these
controls:

- Enable GitHub **immutable releases** for this repository. The mirror workflow
  checks the published Release API's `immutable` field before sending any bytes to
  OSS.
- Protect the `runtime-pack-release` and `runtime-pack-oss` environments with required
  reviewers. Only the former may create a Draft Release; it never publishes one.
- Register isolated organization runners with the exact labels declared in
  `sources.json`. Every runner needs Python 3.12; Windows runners also need a trusted
  7-Zip CLI. Do not attach these labels to general-purpose or fork-controlled runners.
- Create the `opensquilla-releases` bucket in `cn-beijing` with bucket versioning
  unconfigured. OSS ignores `forbid-overwrite` when versioning is enabled or
  suspended, so the workflow refuses either state.
- Give the mirror RAM identity only list/read/create access under
  `runtime-packs/*`. It must not have `DeleteObject`, unrestricted overwrite, bucket
  administration, or access to desktop update-channel paths. Keep the access key only
  in the protected `runtime-pack-oss` environment.
- Set `RUNTIME_PACK_OSS_BUCKET=opensquilla-releases` and
  `RUNTIME_PACK_OSS_ENDPOINT=https://oss-cn-beijing.aliyuncs.com`. The workflow rejects
  other destinations and never writes a moving `latest` or `stable` alias.

Before approving a Draft Release, reviewers must independently confirm every upstream
URL and SHA-256 pin, all fourteen native probe jobs, the exact asset inventory,
`SHA256SUMS`, both SBOM layers, and third-party notices. Publishing is the human stop
gate; a published catalog is never repaired in place.
