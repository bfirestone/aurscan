#!/usr/bin/env bash
# Builds the release tarball that PKGBUILD downloads, byte for byte the same
# on every machine. The release PR's sync job runs it to compute the checksum
# it pins. The release workflow runs it again on the tag to build the asset.
#
#   release-tarball.sh <version> <tree-ish> <output.tar.gz>
#
# It archives a tree, not a commit, so no commit id gets embedded. --mtime
# (git 2.42+) replaces the archive time git would otherwise stamp on a tree.
# PKGBUILD and .SRCINFO are export-ignore in .gitattributes, so pinning the
# checksum doesn't change the bytes being checksummed.
#
# GNU gzip -n does the compression. git's built-in gzip goes through zlib,
# whose output differs between distro builds even when the tar stream is
# identical.
set -euo pipefail

version=$1
treeish=$2
out=$3

tree=$(git rev-parse --verify "$treeish^{tree}")
git archive --format=tar --prefix="aurscan-$version/" \
    --mtime='1970-01-01 00:00:00 +0000' "$tree" | gzip -9n > "$out"
