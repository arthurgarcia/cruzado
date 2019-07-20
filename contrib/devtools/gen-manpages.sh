#!/usr/bin/env bash

export LC_ALL=C
TOPDIR=${TOPDIR:-$(git rev-parse --show-toplevel)}
BUILDDIR=${BUILDDIR:-$TOPDIR}

BINDIR=${BINDIR:-$BUILDDIR/src}
MANDIR=${MANDIR:-$TOPDIR/doc/man}

CRUZADOD=${CRUZADOD:-$BINDIR/cruzadod}
CRUZADOCLI=${CRUZADOCLI:-$BINDIR/cruzado-cli}
CRUZADOTX=${CRUZADOTX:-$BINDIR/cruzado-tx}
CRUZADOQT=${CRUZADOQT:-$BINDIR/qt/cruzado-qt}

[ ! -x $CRUZADOD ] && echo "$CRUZADOD not found or not executable." && exit 1

# The autodetected version git tag can screw up manpage output a little bit
CRZVER=($($CRUZADOCLI --version | head -n1 | awk -F'[ -]' '{ print $6, $7 }'))

# Create a footer file with copyright content.
# This gets autodetected fine for cruzadod if --version-string is not set,
# but has different outcomes for cruzado-qt and cruzado-cli.
echo "[COPYRIGHT]" > footer.h2m
$CRUZADOD --version | sed -n '1!p' >> footer.h2m

for cmd in $CRUZADOD $CRUZADOCLI $CRUZADOTX $CRUZADOQT; do
  cmdname="${cmd##*/}"
  help2man -N --version-string=${CRZVER[0]} --include=footer.h2m -o ${MANDIR}/${cmdname}.1 ${cmd}
  sed -i "s/\\\-${CRZVER[1]}//g" ${MANDIR}/${cmdname}.1
done

rm -f footer.h2m
