// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The target runs no other program: only the operator helper in
// tools/shirudo-build, the command that hands work to it, the signer of
// util/sign.c, which only the helper links, and the tests fork or
// execute one.

virtual report

@r@
attribute name SEC;
identifier f = {fork, vfork, clone, clone3, execv, execve, execvp, execvpe,
		execl, execle, execlp, fexecve, execveat, system, popen,
		posix_spawn, posix_spawnp};
position p;
@@
  f@p(...)

@script:python depends on report@
p << r.p;
f << r.f;
@@
if not p[0].file.startswith(("tools/shirudo-build/", "testing/")) and \
   p[0].file not in ("builtin-build.c", "util/sign.c"):
    coccilib.report.print_report(p[0], "%s() runs a program on the target" % f)
