# Personal firmware with private downloads

This is an **owner-only, manual, main-branch** entry in the existing public firmware repository. It does not change ordinary public builds. Private Core/HomeProxy source, build logs and personal firmware must stay in the selected private repository. No automatic installation or router configuration change is performed.

## Before the first run

1. Create/configure the `personal-private` environment in the public repository. Restrict deployment to `main`; configure the owner as the required reviewer if the account supports that protection.
2. Add environment variables `PERSONAL_PRIVATE_REPOSITORY` (`owner/private-repository`) and `PERSONAL_PRIVATE_REPOSITORY_ID` (its immutable numeric GitHub ID).
3. Create a **dedicated fine-grained PAT**, selecting **only that private repository**, with **Contents: read and write**. Store it as environment secret `PERSONAL_PRIVATE_CONTENTS`. Do not use a broad host PAT or repository-wide inherited secrets. Classic `ghp_` credentials are rejected by this CI transport.
4. Confirm the private repository is private, non-Fork, has default branch `main`, and that its current main HEAD equals the full 40-character private-source pin in the manual form. Review a changed source pin before using it. Set a reviewed full firmware-source commit as well.
5. Check the actual account's Actions/billing limits. Hosted-runner use is not a promise of zero cost. No new schedule, budget or retention policy is configured by this entry.

Without the dedicated secret, the entry stops; there is no public download fallback. This document is configuration guidance, **not evidence that these settings have already been installed**.

## Start one target, manually

Open Actions → `Personal firmware (private downloads, manual only)` → Run workflow, choose `main` and one target. The existing [manual caller](<../workflows/PERSONAL-PRIVATE.yml>) supplies ordinary defaults to the [reusable core](<../workflows/WRT-CORE.yml>); its private path preserves the existing packages, theme/settings and services, with only the target/profile restricted.

| Target key | Existing configuration | Go architecture | Board / subtarget | Device |
| --- | --- | --- | --- | --- |
| `x86-64` | `X86` | `amd64` | `x86 / 64` | `generic` |
| `armsr-armv8` | `ARMSR` | `arm64` | `armsr / armv8` | `generic` |
| `ipq60xx-zn_m2` | `IPQ60XX-WIFI-YES` | `arm64` | `qualcommax / ipq60xx` | `zn_m2` |
| `ipq807x-redmi_ax6-stock` | `IPQ807X-WIFI-YES` | `arm64` | `qualcommax / ipq807x` | `redmi_ax6-stock` |

These are build target mappings, **not device or firmware acceptance results**. The personal profile uses multi-profile mode with exactly one selected device and ALL_PROFILES disabled. Raw device hyphens are preserved. X86 keeps the existing 4096 MiB rootfs setting, Docker and file services. N1 rootfs is a personal download, not a public Docker/GHCR update.

## What the job does

- Fetches the exact reviewed private commit and tree only after repeated repository identity/private/main checks. Git authentication is an immutable anonymous in-memory config; no token is written into Git URL/config, source, recipe, build environment or products.
- Closes the Git authentication descriptor before running source. Separate source/build steps do not receive the dedicated token. Hosted administrators and reviewed build code remain trusted; this is not a sandbox against malicious same-UID code.
- Uses the existing private-source CLI build scripts with exact Go version and static `CGO_ENABLED=0`, `GOAMD64=v1`, `GOARM64=v8.0`; never re-labels historical archives as a new commit.
- Exports paired HomeProxy/recipe source privately, then uses [the offline data reader](<private-prebuilt.py>) against the **actual buildroot/config/target Makefiles/generated Kconfig**. Schema v3 binds CLI source commit/tree separately from the paired feed commit/tree, config hash, firmware base, device and architecture. The personal producer requires CLI and paired source identities to match its verified FETCH receipt.
- Installs `box-private` through the [install-only recipe](<prebuilt-box.Makefile>), rechecking during prepare/compile/install. It retains official `sing-box`; the Core recipe itself installs no service/config and does not switch a backend. Exact real `luci-app-homeproxy` and `box-private` package artifacts are required; the empty HomeProxy-private meta package cannot substitute for the real UI.
- Captures source/make reports only in private state, including a private shadow of the unchanged public Config/Scripts. It invokes no public artifact, cache, release, Docker or report-upload path.

## Downloads and failures

The only download destination is a guarded private release in the selected private repository. The publisher checks identity/private status again for every upload, verifies local SHA256 and GitHub's uploaded digest, and finalizes the draft only after all expected assets succeed.

A successful release includes firmware/packages, fresh CLI and corresponding private-CLI source/license archives, paired HomeProxy source, effective config, input/receipt and private build logs. The private CLI source archive includes the corresponding selected Go/dependency source and notices; this is not a legal-completeness certification for the entire firmware. Observe all relevant licenses before any redistribution beyond personal use.

After a non-cancelled build failure, **only with a verified FETCH receipt**, a separate data-only stage may prepare private logs/reports, a token-free FETCH receipt and a STOP marker. Its release title explicitly says **NO FIRMWARE**; partial firmware is never included. Cancellation, missing/invalid state, diagnostic preparation failure or publication-guard failure produces no public fallback. A malformed existing completion marker is rejected, not assumed ready or overwritten. Final JSON markers are atomically created after all checks.

## Verification boundary

[Personal-path regression tests](<test_personal_private.py>) and [reader/recipe regression tests](<test_private_prebuilt.py>) are offline and use synthetic configuration/Kconfig/paired fixtures. GNU make stub installation tests are **not an OpenWrt SDK**. Reading authentic historical archives verifies data/hash/ELF/build-info/evidence only; it executes no Core and does not certify new-pin compilation, package/firmware ABI, device operation or protocol interoperability.

The first authorized cold build must still validate real generated metadata, toolchain and APK/IPK/firmware results. Device testing, backend selection, upgrade/restore/rollback, new protocol configuration and source-preserving bypass acceptance are separate tasks. Native source-preserving bypass remains default-off and unaccepted; this workflow does not enable it.
