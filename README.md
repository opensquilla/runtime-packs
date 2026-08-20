# OpenSquilla Runtime Packs

This repository builds the optional Python, Node.js, and Git Bash runtimes used by
OpenSquilla. The desktop application embeds an immutable catalog containing each
archive's exact filename, size, and SHA-256 digest. It never trusts a mutable remote
catalog or a caller-provided URL. Each component entry also carries a bounded,
reviewed `trustedArchiveSha256` history so an already-installed older Runtime Pack can
remain trusted after a catalog upgrade without weakening integrity checks.

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
- Historical Runtime Pack digests must be unique, lowercase SHA-256 values and must
  never repeat the current pack digest. The first release starts with empty histories.
- Git for Windows self-extracting archives are unpacked only inside trusted CI; the
  OpenSquilla client never downloads or executes the SFX. The native Windows build
  also requires valid Authenticode signatures on the SFX and the probed Git/Bash
  executables before any of them can enter a Runtime Pack.
- Every discovered upstream license/notice file is preserved. Explicit per-file,
  count, and total-size bounds fail the build instead of silently truncating notices.
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
- The reviewed matrix uses standard GitHub-hosted native runners declared in
  `sources.json`: macOS arm64/x64, Linux arm64/x64, and Windows arm64/x64. This avoids
  persistent organization runners and keeps every build on the target architecture.
  Windows images must continue to provide the trusted 7-Zip and PowerShell tools used
  by the Git Bash extraction and Authenticode gates.
- Reuse the reviewed `opensquilla-releases` bucket in `cn-beijing`, but isolate every
  object under `runtime-packs/<release-tag>/`. Bucket versioning must remain enabled so
  every write has a recoverable Version ID. OSS ignores `forbid-overwrite` on a
  versioned bucket, so the workflow never relies on that header: an existing object is
  accepted only when its downloaded SHA-256 already matches the GitHub Release byte.
- The workflow itself only lists, reads, and creates objects under `runtime-packs/*`;
  it has no delete or desktop update-channel operation. Keep the reused access key
  behind required reviewers in the protected `runtime-pack-oss` environment. When RAM
  policy changes become available, replace it with a prefix-scoped identity rather
  than expanding the existing credential further.
- Allow anonymous `GetObject` only for `runtime-packs/*`; do not grant anonymous
  `ListObjects`, write, delete, or bucket-administration permissions. The mirror job
  downloads every object again over the exact unsigned public client URL and compares
  its SHA-256 before succeeding.
- Expose the existing encrypted `ALIYUN_OSS_ACCESS_KEY_ID` and
  `ALIYUN_OSS_ACCESS_KEY_SECRET` to the protected `runtime-pack-oss` environment.
  GitHub secrets are repository-scoped, so using the same values in this repository
  still requires an environment or organization secret grant; the values are never
  copied by a workflow. The bucket and Beijing endpoint are fixed in the workflow,
  which never writes a moving `latest` or `stable` alias.
- Preserve the generated `oss-version-ids.json` workflow artifact for each mirror run.
  It records the exact current Version ID of every verified object without changing
  the immutable GitHub Release.

Before approving a Draft Release, reviewers must independently confirm every upstream
URL and SHA-256 pin, all fourteen native probe jobs, the exact asset inventory,
`SHA256SUMS`, both SBOM layers, and third-party notices. Publishing is the human stop
gate; a published catalog is never repaired in place.

## License

This repository's original build tooling is licensed under the
[Apache License 2.0](LICENSE). Runtime Pack artifacts contain third-party software
under the licenses preserved inside each archive and summarized in the release's
`THIRD_PARTY_NOTICES.md`.
