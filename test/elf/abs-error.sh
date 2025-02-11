#!/bin/bash
. $(dirname $0)/common.inc

[ $MACHINE = aarch64 -o $MACHINE = ppc64le -o $MACHINE = s390x ] && skip

cat <<EOF | $CC -fPIC -c -o $t/a.o -xassembler -
.globl foo
foo = 3;
EOF

cat <<EOF | $CC -fno-PIC -c -o $t/b.o -xc -
#include <stdio.h>
extern char foo;
int main() { printf("foo=%p\n", &foo); }
EOF

! $CC -B. -o $t/exe -pie $t/a.o $t/b.o -Wl,-z,text >& $t/log
grep -q 'recompile with -fPIC' $t/log
