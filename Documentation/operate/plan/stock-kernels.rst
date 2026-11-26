..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Stock kernels
=============

The stock-kernel profile runs shirudo's upatches and packages on a
distribution kernel without shirudo's kernel patches, from the BPF of
Linux 5.17 on: Ubuntu 24.04 and 26.04, Debian 12 and 13, the RHEL 9 and
10 rebuilds, Fedora, Amazon Linux 2023. It is a separate
build of the target binary. It loads the same signed ``.upatch`` and
``.bee`` files as a patched target, unchanged, and gives up every
guarantee that needs the patched kernel.

Read `What is lost, against upstream's threat model`_ before you deploy
it: on a stock kernel root can
unload, replace or bypass any upatch.

Install
-------

.. code-block:: console

   $ curl -fsSL https://shirudo.today/install | bash
   $ sudo shirudo status
   $ sudo shirudo-uninstall

The installer of shirudo.today runs as the user and asks for ``sudo``
only for the changes that need root. It installs the binary, its
signing certificate in ``/etc/shirudo/keys`` and a systemd unit that
runs ``shirudo init`` at every boot, as `Set up a target`_ describes,
and offers to enable the BPF LSM on the kernel command line; it reboots
only when you answer yes. ``shirudo-uninstall`` takes back every change it made. Shields
for kernel CVEs are published at https://registry.conformal.co.

Build
-----

.. code-block:: console

   $ make STOCK_KERNEL=1

The build goes through the target route, ``make target-deps`` first,
and writes the static PIE ``build/stock/shirudo``. It needs no
``vmlinux.h``: the profile embeds no BPF object. ``make
stock-unit-tests`` builds and runs the unit suites of the files the
profile changes or adds.

The profile leaves out ``shirudo attest``, ``keys``, ``image`` and
``config``. ``genkey`` and ``build`` still dispatch to
``shirudo-build`` on an operator host.

Set up a target
---------------

1. Put the operator's certificate, and any vendor certificate the host
   should trust, in ``/etc/shirudo/keys`` as DER files named ``*.der``,
   owned by root and writable by no one else. Every certificate there
   is trusted on its own, without a vouch; a certificate whose
   fingerprint ``/etc/shirudo/keys/revoked/<fingerprint>.der`` names is
   not. ``shirudo bpm key add <certificate>`` installs one as
   ``<fingerprint>.der``.
2. Enable the BPF LSM if any upatch you load is an ``lsm`` program
   (`The BPF LSM`_).
3. Run ``shirudo init --check-only``, then ``shirudo init``, from the
   root file system at every boot, before the first load. The profile
   refuses to run ``init`` from an initrd. The ``shirudo.service`` of
   the target package waits for the config image's runtime, which the
   profile does not have; a unit of your own runs it instead:

   .. code-block:: ini

      [Unit]
      Description=shirudo (stock kernel): restore signed upatches
      After=local-fs.target
      RequiresMountsFor=/var/lib/shirudo

      [Service]
      Type=oneshot
      RemainAfterExit=yes
      LimitMEMLOCK=infinity
      ExecStart=/usr/bin/shirudo init

      [Install]
      WantedBy=multi-user.target

``init`` mounts the private tmpfs at ``/run/shirudo`` and the bpffs at
``/run/shirudo/bpffs``, restores the archived upatches the eventlog
records as loaded, and appends this boot's ``init`` record to the
eventlog (`Measurement`_). A re-run of ``init`` in the same boot finds
that record and changes nothing.

Its pre-flight requires root, at least one certificate in
``/etc/shirudo/keys`` and the BPF of Linux 5.17, which it probes rather
than reading the kernel release: kernel BTF, a sleepable
``BPF_PROG_TYPE_SYSCALL`` program that calls ``bpf_sys_bpf()`` and
``bpf_kallsyms_lookup_name()``, BTF type tags and in-kernel CO-RE
relocation, which every payload load of the signed loader uses. RHEL 9's
5.14 carries them as backports and passes; Ubuntu 22.04's 5.15 does
not:

.. code-block:: console

   # shirudo init --check-only
   init: pre-flight failed, 1 of 3 checks
   Pre-flight checks:
     OK    root
     FAIL  signed_loader_kernel_abi: the kernel lacks bpf_kallsyms_lookup_name() in a BPF_PROG_TYPE_SYSCALL program, BTF type tags, in-kernel CO-RE relocation; the stock-kernel profile needs the BPF of Linux 5.17
     OK    trusted_certs
   2 of 3 passed

The BPF LSM and the attach kinds are not part of the pre-flight: a load
refuses only the kinds its upatch uses, and ``shirudo status`` says
whether the BPF LSM is active.

How a load works
----------------

``shirudo upatch load``, ``bpm install`` and ``bpm upgrade`` take the
same steps as on a patched kernel, with the signature checked in
userspace:

1. The name, the payload digest and the attach metadata are checked
   as before; a uprobe target is bound to its build ID.
2. The CMS signature is verified over the loader's instructions and
   data, the bytes the patched kernel verifies, against the
   certificates of ``/etc/shirudo/keys``. A signature none of them
   made refuses the load (``signature_rejected``); the log names the
   fingerprint of the certificate that signed.
3. An attach kind the kernel lacks refuses the load
   (``kernel_abi_unsupported``) before anything is loaded, and so does
   a upatch with policy labels: without the seal LSM no task carries a
   policy, and such a upatch would load and never act.
4. The loader map is created, filled, frozen and read back; bytes
   other than the verified ones stop the load (``tampered``). The
   loader is loaded without a signature and run.
5. An ``lsm`` program is refused unless the BPF LSM is active, as it
   would attach and never run.
6. Each link is compared with the site its signed metadata names, as
   far as the kernel reports it (`Minimum kernels`_).
7. The payload digest is recorded in ``/run/shirudo/pins/<name>.pin``,
   where a patched kernel keeps it in an xattr of the bpffs pin
   directory, which a stock kernel's bpffs does not take.

``shirudo upatch unload`` verifies the directive's signature the same
way, without loading it into the kernel. A package's ``cert.der`` must
be one of the trusted certificates, any of them, so packages from a
vendor's registry install beside the operator's; the index signature
is still checked against the certificate the source was registered
with.

The upatch tree
---------------

``shirudo bpm tree sync`` follows a upatch tree
(:doc:`/reference/formats/upatch-tree`) as on a patched kernel, with
one substitution: without a config image there is no BPF signer set,
so acceptance step 2 checks the publication's signature against the
certificates of ``/etc/shirudo/keys`` less the revoked, the set a load
checks a upatch against. Every other check is upstream's: the manifest
form, the generation, the parent and segment digests, the history
root, the operation digests and, for each operation applied, the
artifact's digests, name and kind, then the upatch's own signature at
its load or unload. An empty set refuses every publication
(``EKEYREJECTED``).

The configuration is read from the root file system:
``/etc/shirudo/bpm/upatch-tree.conf`` names the tree,

.. code-block:: text

   endpoint = oci://<registry-host>/<repository>
   reference = <reference>

and ``/etc/shirudo/node.labels``, one ``<key>=<value>`` per line, holds
the labels a ``labels`` selector reads. ``shirudo-bpm-tree-sync.timer``
of the target package runs the sync. As upstream, an operation whose
selector does not match is passed over for good, also when the kernel
or the labels change later, and the node records, measures and reports
each operation as upstream describes.

Any certificate of ``/etc/shirudo/keys`` can sign a publication, a
vendor's as well as the operator's; which tree a host follows is
root's choice in ``upatch-tree.conf``, as the index certificate of a
repository is.

Minimum kernels
---------------

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - What
     - Linux
     - Notes
   * - Signed loader
     - 5.17
     - ``BPF_PROG_TYPE_SYSCALL``, ``bpf_sys_bpf()`` and
       ``bpf_kallsyms_lookup_name()`` in a sleepable program, BTF
       (``CONFIG_DEBUG_INFO_BTF=y``), BTF type tags and in-kernel CO-RE
       relocation. ``init`` probes each.
   * - BPF instruction set v4
     - 6.6
     - Upatches are built with ``-mcpu=v4``. One that uses a v4
       instruction (sign extension, ``bswap``, signed division, a long
       jump) fails the verifier on an older kernel
       (``verifier_rejected``); rebuilding it changes the signed
       artifact.
   * - ``fentry``, ``fexit``, ``tp_btf``, raw tracepoints
     - 5.5
     -
   * - ``lsm``
     - 5.7
     - Only with ``bpf`` in the active LSM list (`The BPF LSM`_).
   * - ``fmod_ret``
     - 5.7
     - The function must allow error injection.
   * - ``kprobe``, ``kretprobe``, ``uprobe``, ``uretprobe``
     - 5.15
     - Before 6.6 the link does not report its site: the load checks
       the link's type, logs that the site is not checked, and goes on.
   * - ``kprobe.multi``, ``kretprobe.multi``
     - 5.18
     - Needs ``CONFIG_FPROBE``. Before 6.5 the link does not report its
       symbol count, which is then not checked.
   * - ``uprobe.multi``, ``uretprobe.multi``
     - 6.6
     - Before 6.8 the link does not report its offset count, which is
       then not checked.
   * - ``cgroup_skb``
     - 5.7
     - Needs the unified cgroup v2 hierarchy at ``/sys/fs/cgroup``.
   * - ``netfilter``
     - 6.4
     -
   * - ``xdp``
     - 5.9
     -
   * - Arena maps
     - 6.9
     - An upatch whose state lives in an arena fails to load before.

Enterprise kernels backport BPF features: Rocky and Alma 9 report 5.14
and carry much of 6.x's BPF. ``shirudo init --check-only`` and every
load probe what the running kernel has, which counts more than its
release; an attach kind the kernel lacks refuses the load that uses it.

A load that succeeds says that the kernel accepted the programs and
attached them, not that the path the upatch was written for still runs
through its hook on an older kernel. Test a upatch on each kernel
release it is meant for. For instance a upatch on ``lsm/socket_sendmsg``
that looks for ``MSG_SPLICE_PAGES`` sees ``splice()`` into a socket
from Linux 6.5 on; before 6.5 the data goes through the socket's
``sendpage`` operation, which calls no LSM hook, so such a upatch
loads on Debian 12, Amazon Linux 2023 and Alma 9 and never refuses
anything there.

The BPF LSM
-----------

Some distribution kernels build the BPF LSM but leave it out of the
active list: Ubuntu 24.04's 6.8 kernels (generic and the ``-lts-24.04``
cloud kernels) and Flatcar. Debian 12 and 13, RHEL 9 and 10 and their
rebuilds, Amazon Linux 2023, Fedora, openSUSE Leap, Ubuntu 26.04 and
Ubuntu 24.04's 7.0 HWE and cloud kernels have it active. Check it with:

.. code-block:: console

   $ cat /sys/kernel/security/lsm
   lockdown,capability,landlock,yama,apparmor

To enable it, append ``bpf`` to the list the kernel prints, keep the
order of the others, and pass the result as ``lsm=`` on the kernel
command line:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Distribution
     - Command line
   * - Ubuntu, Debian
     - Add ``lsm=<list>,bpf`` to ``GRUB_CMDLINE_LINUX`` in
       ``/etc/default/grub``, run ``update-grub``, reboot.
   * - Rocky and Alma 9, Amazon Linux 2023
     - ``grubby --update-kernel=ALL --args="lsm=<list>,bpf"``, reboot.

For Ubuntu 24.04 on a 6.8 kernel the list is
``lockdown,capability,landlock,yama,apparmor,bpf``; on Rocky 9 with
SELinux enforcing it is
``lockdown,capability,yama,selinux,bpf``. After the reboot
``/sys/kernel/security/lsm`` ends in ``bpf``.

Measurement
-----------

Every load, unload and ``init`` restore is still an event in the
eventlog, ``/var/lib/shirudo/eventlog``, with the same digests. There
is no register beside it: the value a patched kernel keeps in a TPM NV
index is this boot's records replayed, from the boot's ``init`` record
on, and ``--expect-chain`` compares with that. Each record's digest is
still checked against its fields when the loaded set is read. No TPM
is used: there is no PCR, no NV register bound to the boot and no
TPM-signed evidence, and ``shirudo attest`` is not part of the profile.
Root can rewrite the eventlog; it is a record, not evidence.

Status
------

``shirudo status`` reports ``"profile": "stock-kernel"`` and states what
the host does not guarantee:

.. code-block:: console

   # shirudo status
   Host:                  web-1
   Roles:                 target
   Status:                ok
   Version ID:            ...

   Profile:               stock kernel
   Guarantees:            signatures verified in userspace; root can unload or replace upatches; no kernel-enforced lockdown
   Trusted certs:         1 in /etc/shirudo/keys
   BPF LSM:               active

followed by the loaded upatches. Its status is ``ok``,
``uninitialized`` before ``init`` has run this boot, or ``drift`` when a
upatch is pinned without a record or this boot's eventlog records do
not verify; ``--check`` exits 1 for anything but ``ok``. ``--json``
gives ``profile`` (``stock-kernel``), ``status``, ``reason``,
``guarantees``, ``bpf_lsm``, the trusted certificates as ``certs`` and
``certs_revoked``, ``upatches``, and ``eventlog`` with its ``entries``
(and its ``events`` with ``--eventlog``). There is no keyring, tamper
counter, config image, TPM or keepalive view, and ``--otel`` and
``--keepalive`` are refused.

What is lost, against upstream's threat model
---------------------------------------------

On a patched kernel the kernel enforces what shirudo checks. On a stock
kernel nothing does. This section goes through the goals, adversaries,
threats and residual risks of :doc:`/security/threat-model` and says
what the stock-kernel profile keeps and what it loses.

In short: upstream is built against root on the target without the
signing key (ADV-B), and every mechanism it has against that adversary,
the ``lsm/bpf`` gate, the guards, the seal and the TPM register, needs
shirudo's kernel patches. On a stock kernel **none of the goals that are
about root holds**. What the profile keeps is the upatches themselves
against unprivileged local code (ADV-A), which cannot load BPF, detach a
link or read a map on a supported distribution, and the signature check
of everything shirudo itself loads. It keeps the mitigation and gives up
the tamper resistance: once something is root, the host is no more
protected than one without shirudo.

Goals
~~~~~

.. list-table::
   :header-rows: 1
   :widths: 22 30 30 18

   * - Goal
     - Upstream mechanism
     - Stock-kernel profile
     - Status
   * - G1: only signed BPF enters the kernel, root included
     - ``lsm/bpf`` and ``lsm/bpf_prog_load`` gates; the kernel verifies
       loaders against the sealed ``.bpf`` keyring
     - No gate. shirudo verifies the same CMS signature in userspace
       before it loads; any root process can still call ``bpf()``
       directly
     - **Lost** against root; kept for what shirudo loads: a tampered or
       foreign-signed package is refused
   * - G2: enforcement and upatches stay attached until shirudo removes
       them
     - Guards refuse detach, update and foreign attach; private bpffs
       and pins guarded
     - Links pinned in a private bpffs, without guards. Root can unpin,
       detach or replace them; unprivileged code cannot
     - **Lost** against root; kept against ADV-A
   * - G3: only shirudo changes its state, keyrings and processes
     - Seal LSM labels the state; sealed keyrings; authorized-task marks
     - Plain root-owned files; ``/etc/shirudo/keys`` is the trust anchor
     - **Lost** against root; file permissions keep ADV-A out
   * - G4: every change to the loaded set is measured in the TPM
     - TPM NV extend register, guarded writes, salted sessions
     - Eventlog only, root's to rewrite; no TPM
     - **Lost**: a log, not a measurement root cannot forge
   * - G5: a verifier tells a good target from a bad one by TPM-signed
       evidence
     - ``shirudo attest``, ``attest verify``
     - Not in the profile. ``shirudo status`` is the target's own account
     - **Lost**: a compromised host can report healthy upatches
   * - G6: a refused attempt leaves a trace
     - Frozen tamper counters
     - No guards, so no tamper counters. Upatches keep their own
       counters, which ``status`` and ``upatch map`` read
     - **Partly kept**: what an upatch refuses is counted; attempts to
       tamper with shirudo are not
   * - G7: accepted artifacts, packages, trees and configs are those the
       operator's keys signed
     - CMS signatures; the repository certificate from the signed config
       image; TLS 1.3
     - Same signatures, index and tree checks and TLS. Root registers
       the repository certificate and the tree in ``/etc/shirudo``; a
       tree publication is checked against ``/etc/shirudo/keys``
       (`The upatch tree`_); no config images
     - **Kept** against the network and registries (ADV-D); root can
       register its own repository or certificate
   * - G8: nobody without runtime authority reads or drains shirudo's
       maps and pins
     - Authority marks, guards
     - No runtime authority; root reads any map
     - **Lost** against root; kept against ADV-A (a map needs
       ``CAP_BPF``)

As upstream says of itself, shirudo establishes provenance, not
correctness: whether a upatch blocks what it is written for on a given
kernel is the upatch's evidence (`Minimum kernels`_).

Adversaries
~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Adversary
     - Stock-kernel profile
   * - ADV-A, unprivileged local code
     - No loss. Upstream adds nothing it needs; here the upatches are
       what constrains it. It cannot load, detach or read shirudo's BPF.
   * - ADV-B, root without the signing key
     - **Full loss.** It can load BPF, detach shirudo, change its state
       unnoticed and make a tampered target look healthy, as on a
       distribution without shirudo.
   * - ADV-C, root with mount-namespace and device control
     - Subsumed by ADV-B.
   * - ADV-D, network and registry
     - Unchanged: same ``bpm``, signatures and TLS. Withholding and
       replay (R8) remain as upstream.
   * - ADV-E, malicious collector
     - Not applicable: the profile has no keepalive or OTLP export.
   * - ADV-F, holder of a signing key
     - Same blast radius, without revocation by config: every host that
       trusts the certificate loads whatever its key signs until the
       certificate leaves ``/etc/shirudo/keys`` or is listed under
       ``revoked/``. A vendor key trusted by many hosts belongs in an
       HSM with a narrow signer role.
   * - ADV-G, physical access
     - Out of scope, as upstream.

The profile assumes none of upstream's platform assumptions (patched
kernel, module signatures, Secure Boot with a measured UKI, a dm-verity
runtime, a TPM), only a kernel with the BPF of Linux 5.17, the BPF LSM
active for ``lsm`` upatches, a root that is not compromised when shirudo
is installed and at each boot, and a signing key kept safe.

Threats
~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Threat
     - Stock-kernel profile
   * - T1, loading unsigned BPF
     - Root can. shirudo itself loads only verified loaders.
   * - T2, detaching or replacing enforcement
     - Root can.
   * - T3, tampering with shirudo's files and process
     - Root can.
   * - T4, substituting artifacts
     - Kept for what shirudo loads: name, payload digest and attach
       metadata are checked as upstream, and the loader map is read back
       once frozen (``tampered``). Root can still race the load between
       the check and ``BPF_PROG_LOAD``, which the kernel's check closes
       upstream.
   * - T5, silent state change
     - Eventlog only; root can rewrite it, and ``status`` reports a
       record that does not verify only when root has not fixed it up.
   * - T6, boot window
     - Wider: ``init`` runs from the root file system by a unit, not from
       the initrd, so upatches are absent from early boot until it runs.
   * - T7, delivery path
     - Kept: signed index, signed tree publications with their
       generations and history, digests, signed loaders, TLS.
   * - T8, quantum-capable adversaries
     - As upstream: the same algorithms.
   * - T9, a target lying about its state
     - Not addressed: no attestation.
   * - T10, an attempt without a trace
     - Upatch counters only.
   * - T11, config and executable substitution
     - No config images; the binary is a file root can replace.
   * - T12, interrupted image activation; T14, substituting the TPM
     - Not applicable.
   * - T13, reading or draining upatch state
     - Root can; unprivileged code cannot.
   * - T15, an unsigned Java agent
     - Java upatches are verified against the same certificates; root
       can still start a JVM with an agent of its own.

Residual risks that weigh more here
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **A failed or skipped init leaves the host unprotected (R6).** More
  likely on a stock kernel: a kernel update that changes a hook, a
  BPF LSM that is not active or a verifier difference makes a upatch
  fail to load at boot. ``status`` then shows it missing; nothing
  enforces its presence.
- **Every artifact ever signed loads at any time (R16).** There is no
  revocation by config: an old upatch version signed by a trusted key
  stays loadable.
- **upatches can be neutralized by changing their targets (R21).** As
  upstream; on a stock kernel root does not need to.
- **A upatch that loads is not a upatch that works.** A kernel may route
  the vulnerable path around the hook (`Minimum kernels`_); upstream's
  model, being about provenance, does not cover this either.

Policy labels are not carried to tasks either: the seal LSM that copies
a file's label into the task policy storage is not there, so a upatch
with policy labels is refused.

Use the profile to roll upatches out to hosts that cannot run a patched
kernel yet, not as a replacement for one.
