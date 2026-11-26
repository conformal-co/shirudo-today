..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Plan
====

Check what a target needs and what it costs before you deploy: the
kernel, boot chain and TPM shirudo requires, what it uses on a target,
how the pull from registries scales to a fleet, which other software
can run beside it, what a production target needs beyond the
requirements, and what remains on a stock kernel without shirudo's
patches.

.. toctree::
   :titlesonly:

   system-requirements
   stock-kernels
   overhead
   scalability
   interoperability
   hardening
