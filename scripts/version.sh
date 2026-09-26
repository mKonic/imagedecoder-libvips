#!/usr/bin/env bash
# The single source of this fork's version. Nothing is declared in a file: releasing is tagging.
#
#   scripts/version.sh name   git describe against the fork's semver tags: v1.0.0, v1.0.0-3-gabc1234,
#                             or a bare hash before the first one
#   scripts/version.sh code   10000 + commits on HEAD - monotonic, says which build is newer
#   scripts/version.sh both   "<name> <code>" (the default)
#
# Only v<major>.<minor>.<patch> tags count: upstream tags its releases with bare integers, which
# are not this fork's versions. Outside git the name is "unknown" and the code 0, and so is the code in a
# shallow clone, whose commit count would come out lower than the build before it.
set -euo pipefail
cd "$(dirname "$0")/.."

name() {
    git describe --tags --always --dirty --match 'v[0-9]*.[0-9]*.[0-9]*' 2> /dev/null || echo unknown
}

code() {
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        echo 0
    elif [ "$(git rev-parse --is-shallow-repository)" = true ]; then
        echo "version.sh: shallow clone, the commit count would be wrong - fetch with full depth" >&2
        echo 0
    else
        echo $((10000 + $(git rev-list --count HEAD)))
    fi
}

case "${1:-both}" in
    name) name ;;
    code) code ;;
    both) echo "$(name) $(code)" ;;
    *)
        echo "usage: $0 [name|code|both]" >&2
        exit 2
        ;;
esac
