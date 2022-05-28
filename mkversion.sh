#!/bin/sh
set -e

# debugging if anything fails is tricky as dh-golang eats up all output
# uncomment the lines below to get a useful trace if you have to touch
# this again (my advice is: DON'T)
#set -x
#logfile=/tmp/mkversions.log
#exec >> $logfile 2>&1
#echo "env: $(set)"
#echo "mkversion.sh run from: $0"
#echo "pwd: $(pwd)"

# we have two directories we need to care about:
# - our toplevel pkg builddir which is where "mkversion.sh" is located
#   and where "snap-confine" expects its cmd/VERSION file
# - the GO_GENERATE_BUILDDIR which may be the toplevel pkg dir. but
#   during "dpkg-buildpackage" it will become a different _build/ dir
#   that dh-golang creates and that only contains a subset of the
#   files of the toplevel buildir. 
PKG_BUILDDIR=$(dirname "$0")
GO_GENERATE_BUILDDIR="${GO_GENERATE_BUILDDIR:-$(pwd)}"

# run from "go generate" adjust path
if [ "$GOPACKAGE" = "snapdtool" ]; then
    GO_GENERATE_BUILDDIR="$(pwd)/.."
fi

OUTPUT_ONLY=false
if [ "$1" = "--output-only" ]; then
    OUTPUT_ONLY=true
    shift
fi

# If the version is passed in as an argument to mkversion.sh, let's use that.
if [ -n "$1" ]; then
    version_from_user="$1"
fi

DIRTY=false

# Let's try to derive the version from git only if the snapd source tree is
# tracked by git. The script can be invoked when building distro packages in
# which case, the source tree could be a tarball, but the distro packaging files
# can be in git, so try not to confuse the two.
if command -v git >/dev/null && [ -d "$(dirname "$0")/.git" ] ; then
    # don't include --dirty here as we independently track whether the tree is
    # dirty and append that last, including it here will make dirty trees 
    # directly on top of tags show up with version_from_git as 2.46-dirty which
    # will not match 2.46 from the changelog and then result in a final version
    # like 2.46+git2.46.2.46 which is silly and unhelpful
    # tracking the dirty independently like this will produce instead 2.46-dirty
    # for a dirty tree on top of a tag, and 2.46+git83.g1671726-dirty for a 
    # commit not directly on top of a tag
    version_from_git="$(git describe --always | sed -e 's/-/+git/;y/-/./' )"

    # check if we are using a dirty tree
    if git describe --always --dirty | grep -q dirty; then
        DIRTY=true
    fi
fi

# at this point we maybe in _build/src/github etc where we have no
# debian/changelog (dh-golang only exports the sources here)
# switch to the real source dir for the changelog parsing
if command -v dpkg-parsechangelog >/dev/null; then
    version_from_changelog="$(cd "$PKG_BUILDDIR"; dpkg-parsechangelog --show-field Version)";
fi

# select version based on priority
if [ -n "$version_from_user" ]; then
    # version from user always wins
    v="$version_from_user"
    o="user"
elif [ -n "$version_from_git" ]; then
    v="$version_from_git"
    o="git"
elif [ -n "$version_from_changelog" ]; then
    v="$version_from_changelog"
    o="changelog"
else
    echo "Cannot generate version"
    exit 1
fi

# if we don't have a user provided version and if the version is not
# a release (i.e. the git tag does not match the debian changelog
# version) then we need to construct the version similar to how we do
# it in a packaging recipe. We take the debian version from the changelog
# and append the git revno and commit hash. A simpler approach would be
# to git tag all pre/rc releases.
if [ -z "$version_from_user" ] && [ "$version_from_git" != "" ] && \
       [ -n "$version_from_changelog" ] && [ "$version_from_git" != "$version_from_changelog" ]; then
    # if the changelog version has "git" in it and we also have a git version
    # directly, that is a bad changelog version, so fail, otherwise the below
    # code will produce a duplicated git info
    if echo "$version_from_changelog" | grep -q git; then
        echo "Cannot generate version, there is a version from git and the changelog has a git version"
        exit 1
    else
        revno=$(git describe --always --abbrev=7|cut -d- -f2)
        commit=$(git describe --always --abbrev=7|cut -d- -f3)
        v="${version_from_changelog}+git${revno}.${commit}"
        o="changelog+git"
    fi
fi

# append dirty at the end if we had a dirty tree
if [ "$DIRTY" = "true" ]; then
    v="$v-dirty"
fi

if [ "$OUTPUT_ONLY" = true ]; then
    echo "$v"
    exit 0
fi

echo "*** Setting version to '$v' from $o." >&2

cat <<EOF > "$GO_GENERATE_BUILDDIR/snapdtool/version_generated.go"
package snapdtool

// generated by mkversion.sh; do not edit

func init() {
	Version = "$v"
}
EOF

cat <<EOF > "$PKG_BUILDDIR/cmd/VERSION"
$v
EOF

MOD=-mod=vendor
if [ "$GO111MODULE" = "off" ] ; then
    MOD=--
elif [ ! -d "$GO_GENERATE_BUILDDIR/vendor/github.com"  ] ; then
    MOD=--
fi
fmts=$(cd "$GO_GENERATE_BUILDDIR" ; go run $MOD ./asserts/info)

cat <<EOF > "$PKG_BUILDDIR/data/info"
VERSION=$v
SNAPD_APPARMOR_REEXEC=0
${fmts}
EOF
