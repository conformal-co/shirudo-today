# shirudo.today

> [!IMPORTANT]
> **This is shirudo.today, a fork of [shirudo-dev/shirudo](https://github.com/shirudo-dev/shirudo)
> maintained by Conformal. It is not affiliated with or endorsed by the shirudo project, OpenAI or Cisco.**
> It adds a stock-kernel profile so signed upatches run on unmodified distribution kernels.

## Read this first

On a stock kernel, shirudo protects against unprivileged users and the
network, not against root:

- **Root can load unsigned BPF.** So can a privileged container, or any
  task with `CAP_BPF` and `CAP_SYS_ADMIN`. shirudo verifies signatures
  only for what it loads itself.
- **Root can unload or replace any upatch**, and make `shirudo status`
  report it as loaded: the keys, the archive, the eventlog and the pin
  records are plain root-owned files.
- **There is no TPM measurement and no attestation.** The eventlog is a
  log root can rewrite; there is no `shirudo attest`.
- **Shields start after the root file system and fail open.** `init`
  runs from a systemd unit, not the initrd; a upatch that fails to load
  leaves its hole open, and nothing enforces its presence.
- **Whoever holds a trusted signing key can load kernel code on the
  host.** Every certificate in `/etc/shirudo/keys` is trusted, at once.

What it keeps: unprivileged users and the network cannot load, detach or
read shirudo's BPF, and every load is refused unless its signature
verifies against a certificate in `/etc/shirudo/keys`. The full mapping
onto upstream's threat model is in
[What is lost, against upstream's threat model](Documentation/operate/plan/stock-kernels.rst#what-is-lost-against-upstreams-threat-model).

## What this fork changes

Upstream shirudo needs a kernel carrying its patches. This fork adds a
build profile, `make STOCK_KERNEL=1`, that runs on the kernels
distributions already ship. Without `STOCK_KERNEL=1` the build is
upstream's.

**Changed in the stock-kernel profile**

| Upstream, patched kernel | This fork, stock kernel |
|---|---|
| The kernel verifies each loader's signature against the sealed `.bpf` keyring | `shirudo` verifies the same CMS signature in userspace, then loads the loader without a signature |
| Trust anchor: sealed kernel keyring, vouched certificates | Every DER certificate in `/etc/shirudo/keys` (root-owned) is trusted; `revoked/` excludes one |
| Pin records in bpffs extended attributes | Pin records in per-boot files under `/run/shirudo/pins` |
| Measurement into a TPM NV register; `shirudo attest` | The eventlog alone, replayed per boot; no TPM, no `attest` |
| `init` from the initrd, guards attached at boot | `init` from the root file system by a systemd unit; no guards |
| Pre-flight of the patched kernel's ABI | Probes of the BPF of Linux 5.17 (kernel BTF, `BPF_PROG_TYPE_SYSCALL` with `bpf_sys_bpf()`, BTF type tags, in-kernel CO-RE); a kernel without them is refused |
| Attach kinds the patched kernel provides | A load whose attach kind the kernel lacks is refused, and `lsm` programs are refused unless `bpf` is in the active LSM list |
| Policy labels carried to tasks by the seal LSM | A upatch with policy labels is refused |

`shirudo status` reports `"profile": "stock-kernel"`, what it does not
guarantee and whether the BPF LSM is active.

**What you give up.** Upstream is built against root on the target; on a
stock kernel nothing the kernel would enforce is enforced, so none of
upstream's goals against root holds:

- **G1, signed BPF only: lost against root.** Any root process (or task
  with `CAP_BPF` and `CAP_PERFMON`, or `CAP_SYS_ADMIN`) can load unsigned
  BPF. shirudo still refuses a tampered or foreign-signed package for what
  it loads itself.
- **G2, upatches stay attached: lost against root.** Root can detach,
  unpin or replace any upatch, or race a load between its check and
  `BPF_PROG_LOAD`.
- **G3, only shirudo changes its state: lost against root.** Keys,
  archive, eventlog and pin records are plain root-owned files;
  adding a certificate to `/etc/shirudo/keys` trusts it at once.
- **G4, measurement in the TPM: lost.** The eventlog is a log root can
  rewrite. No TPM is used.
- **G5, attestation: lost.** There is no `shirudo attest`; a compromised
  host can report healthy upatches.
- **G6, a trace of refused attempts: partly kept.** Upatches count what
  they refuse; attempts to tamper with shirudo are not counted.
- **G7, only signed artifacts: kept** against the network and registries;
  root can register its own repository or certificate.
- **G8, maps and pins private to shirudo: lost against root**, kept
  against unprivileged code.
- No config images, dm-verity, initrd phase, revocation by config or
  policy labels on tasks; `init` runs later in boot, from the root file
  system.

Against unprivileged local code (ADV-A), the adversary a kernel-CVE
upatch is for, nothing a upatch needs is lost: it cannot load BPF, detach
a link or read a map. A loaded upatch is not proof that it works on that
kernel: test each upatch on each kernel line. Use the profile to roll
shields out to hosts that cannot run a patched kernel yet, not as a
replacement for one. The mapping onto upstream's threat model, with the
adversaries and residual risks, is in
[stock-kernels.rst](Documentation/operate/plan/stock-kernels.rst#what-is-lost-against-upstreams-threat-model).

**Supported kernels.** The profile needs the BPF of Linux 5.17, which
`shirudo init --check-only` probes, whatever release the kernel reports.
Tested on Ubuntu 24.04 and 26.04, Debian 12 and 13, RHEL 9 and 10 rebuilds (Alma,
Rocky, CentOS Stream, Oracle Linux), Fedora and Fedora CoreOS, openSUSE
Leap 15.6 and 16, Amazon Linux 2023 and Flatcar. Ubuntu 22.04, Debian 11,
RHEL 8 and Amazon Linux 2 are not supported. Where the BPF LSM is not
active by default (Ubuntu 24.04's 6.8 kernels, generic and `-lts-24.04`
cloud, and Flatcar), `lsm=…,bpf` on the kernel command line and one reboot
are needed for `lsm` upatches; Ubuntu 24.04's 7.0 kernels have it.

**Unchanged.** The `.upatch` and `.bee` formats, signing, `bpm`, the
Beefile, packages and upatches. A package built and signed for upstream
shirudo loads unchanged on the stock-kernel profile.

## Install

```console
curl -fsSL https://shirudo.today/install | bash
sudo shirudo status
sudo shirudo-uninstall    # removes it again
```

Run the installer as your user: it asks for `sudo` itself where it needs
root. Shields for kernel CVEs are published at
[registry.conformal.co](https://registry.conformal.co).

To build from source instead:

```console
make STOCK_KERNEL=1
```

The binary is `build/stock/shirudo`. Set up a target as in
[stock-kernels.rst](Documentation/operate/plan/stock-kernels.rst#set-up-a-target).

## Keeping up with upstream

The fork is the `main` branch, rebased onto upstream `main` (base:
[`87ae310f`](https://github.com/shirudo-dev/shirudo/commit/87ae310f)).
The changes are kept in a short series of self-contained commits
(`git log upstream/main..main`) so they stay easy to review and
rebase. Without `STOCK_KERNEL=1` the build is upstream's. Report
fork-specific problems here, not upstream.

---

Upstream's README follows, unchanged except for the logo and its CI
badges ("Project status"), removed.

shirudo is a BPF-based security platform for Linux. After boot-time
initialization, it restricts BPF program loads from userspace to signed
loaders. Operators ship signed micropatches, called
[upatches](https://docs.shirudo.dev/upatches/learn/concepts.html),
and verify a target's measured upatch state with TPM-signed evidence.

shirudo (Japanese シールド, pronounced “shee-roo-doh”) means “shield”.

Read the announcements of shirudo on the blogs of
[OpenAI](https://openai.com/index/introducing-shirudo/) and
[Cisco](https://isovalent.com/blog/post/cisco-openai-shirudo/).

## Quickstart

- [Try shirudo in a local VM](https://docs.shirudo.dev/start/quickstart.html).
  The VM uses a software TPM.
- [Read the documentation](https://docs.shirudo.dev/).

shirudo is pre-release. Production targets require a Linux kernel with
the signed-loader ABI and shirudo's kernel patches, plus a TPM 2.0. See the
[system requirements](https://docs.shirudo.dev/operate/plan/system-requirements.html).

CI runs all test tiers on x86-64 and host tests on arm64. The test VM
also boots locally on arm64. Target validation for riscv64 is pending.
The operator and target may use different architectures. See
[architecture support](https://docs.shirudo.dev/contribute/arch-support.html).

## Use cases

- **Runtime security and observability.** Observe process executions,
  network activity, and privilege changes with the included
  [`kernel-obs` package](upatches/kernel-obs/README.md).
- **Live mitigations.** Use BPF upatches to block vulnerable paths at kernel
  hooks or Java upatches to guard application code.
- **System hardening.** Use BPF upatches to enforce policies for
  containers, Kubernetes Pods, and LLM agents.
- **Embedded and edge devices.** Deliver signed mitigations to devices
  with long update cycles.

## Properties

- **Boot-time enforcement.** On production targets, enforcement starts
  when `shirudo init` attaches its guards from the initrd. The guards
  protect shirudo's runtime and state from root on the target without
  the operator's signing key.
- **Signed and sealed BPF.** BPF upatch loads and unloads go through
  loaders that the kernel verifies against the sealed `.bpf` keyring.
- **Signed Java agents.** shirudo verifies Java upatches in userspace.
  Configured JVMs load the agents at startup. See
  [Java agent upatches](https://docs.shirudo.dev/upatches/write/java-agents.html).
- **TPM measurement.** Changes to the loaded upatch set extend a
  per-boot TPM register. `shirudo attest` returns evidence that
  operators can verify offline.
- **Upatches** are small logically contained programs that engineers and
  agents can read, generate and maintain. Commands take and produce
  structured data.
- **Pull-based delivery.** Targets use one-shot commands to pull packages
  from OCI registries and export telemetry to configured OpenTelemetry
  collectors.

The [threat model](https://docs.shirudo.dev/security/threat-model.html)
states where each of these mechanisms stops.

## How it works

[![The operator host builds, signs and pushes to an OCI registry. The target pulls, its kernel checks the signature and runs the loader, its TPM extends the register and signs evidence, which the operator verifies.](Documentation/images/start-how-it-works.svg)](https://docs.shirudo.dev/start/how-it-works.html)

BPF upatch lifecycle, from signing through offline verification.
[Follow the numbered steps](https://docs.shirudo.dev/start/how-it-works.html).

## By role

- New to shirudo:
  [FAQ](https://docs.shirudo.dev/start/faq.html)
- Operators, who deploy and run targets:
  [Deployment checklist](https://docs.shirudo.dev/operate/deploy/deployment-checklist.html),
  then [Read shirudo status](https://docs.shirudo.dev/operate/run/read-status.html)
- upatch authors:
  [Your first upatch](https://docs.shirudo.dev/start/guides/first-upatch.html),
  then [From a kernel fix to a upatch](https://docs.shirudo.dev/upatches/learn/kernel-fix-tutorial.html)
- Security reviewers:
  [Security model](https://docs.shirudo.dev/security/security-model.html),
  then [Threat model](https://docs.shirudo.dev/security/threat-model.html)
- Contributors:
  [Develop locally](https://docs.shirudo.dev/contribute/code/develop-locally.html)

## Specifications

- [Beefile](https://docs.shirudo.dev/reference/formats/beefile.html):
  the Beefile that describes a package
- [.upatch format](https://docs.shirudo.dev/reference/formats/upatch-format.html):
  the little-endian container with an architecture-neutral signature
- [upatch tree](https://docs.shirudo.dev/reference/formats/upatch-tree.html):
  the operations, segments and publication document of a upatch tree
- [Keepalive](https://docs.shirudo.dev/reference/formats/keepalive.html):
  the record a target sends its collector, its
  [body](https://docs.shirudo.dev/reference/formats/keepalive.html#keepalive-body-format)
  and its TPM quote

## Releases

[main](https://github.com/shirudo-dev/shirudo/commits/main/) is the
development branch. Development packages are available as run artifacts
from the [Build packages](https://github.com/shirudo-dev/shirudo/actions/workflows/packages.yml)
workflow. Release tags publish their packages on
[GitHub Releases](https://github.com/shirudo-dev/shirudo/releases).

For upgrades of shirudo and the kernel on a target, consult
[Upgrade shirudo and the kernel](https://docs.shirudo.dev/operate/maintain/upgrade.html).

### Software Bill of Materials

Every package comes with a Software Bill of Materials (SBOM) in
[SPDX](https://spdx.dev/) format.

## License

shirudo is licensed under the [BSD-2-Clause License](LICENSE). BPF
programs are dual-licensed BSD/GPL. Each source file holds an SPDX
license identifier. The tree vendors a few source files from
third-party projects under different but compatible licenses; those
files retain their original SPDX identifier and copyright notices.
