#!/usr/bin/env python3

import argparse
import datetime
import os
import re
from typing import NamedTuple

import debian.changelog


def parse_arguments():
    parser = argparse.ArgumentParser(description="automatic changelog writer for snapd")
    parser.add_argument("version", type=str, help="new snapd version")
    parser.add_argument(
        "changelog",
        type=argparse.FileType("r"),
        help="path to new changelog entry as generated by snappy-dch",
    )
    return parser.parse_args()


class Distro(NamedTuple):
    name: str  # name of the distro in the packaging directory
    debian_name: str  # debian distribution name
    version_suffix: str  # suffix to add to the version number in changelogs


debianish_distros = [
    Distro("ubuntu-14.04", "trusty", "~14.04"),
    Distro("ubuntu-16.04", "xenial", ""),
    Distro("debian-sid", "unstable", "-1"),
]


other_distros = [
    "opensuse",
    "fedora",
    "arch",
]


def rewrite_version_number_file(file, pattern, version):
    # simple sed implementation, read all the lines first, then write them out
    # again, applying the given pattern to every line (the pattern is expected
    # to only ever match one line)
    with open(file, "r") as fh:
        lines = fh.readlines()
    with open(file, "w") as fh:
        for line in lines:
            fh.write(re.sub(pattern + ".+$", pattern + version, line))


def update_fedora_changelog(opts, snapd_packaging_dir, new_changelog_entry, maintainer):
    specFile = os.path.join(snapd_packaging_dir, "fedora", "snapd.spec")
    # rewrite the snapd.spec file with the right version
    rewrite_version_number_file(
        # meh this is terrible, to keep the right indentation level,
        # prepend the number of spaces we currently have in the file to
        # the version number
        specFile,
        "Version:",
        f"        {opts.version}",
    )

    # now we also need to add the changelog entry to the snapd.spec file
    # this is a bit tricky, since we want a different format for the
    # changelog in snapd.spec than we have for debian, but luckily it's
    # just trimming whitespace off the front of each line in the
    # changelog

    dedented_changelog_lines = []
    for line in new_changelog_entry.splitlines():
        # strip the first 3 characters which are space characters so
        # that we only have one single whitespace
        dedented_changelog_lines.append(line[3:] + "\n")

    date = datetime.datetime.now().strftime("%a %d %b %Y")

    date_and_maintainer_header = f"* {date} {maintainer[0]} <{maintainer[1]}>\n"
    changelog_header = f"- New upstream release {opts.version}\n"
    fedora_changelog_lines = [
        date_and_maintainer_header,
        changelog_header,
    ] + dedented_changelog_lines

    # now read all the existing lines of the snapd.spec file
    with open(specFile, "r") as fh:
        current_spec_lines = fh.readlines()

    # re-write them all out to the file again, inserting our new
    # changelog entryfiles when we get to that section
    with open(specFile, "w") as fh:
        for line in current_spec_lines:
            fh.write(line)
            # if this line was the start of the changelog section, then
            # we need to insert our change log entry lines
            if line.strip() == "%changelog":
                # before continuing to write the rest of the file,
                # insert our new changelog entry here
                for ch_line in fedora_changelog_lines:
                    fh.write(ch_line)
                fh.write("\n")


def update_opensuse_changlog(
    opts, snapd_packaging_dir, new_changelog_entry, maintainer
):
    specFile = os.path.join(snapd_packaging_dir, "opensuse", "snapd.spec")
    changesFile = os.path.join(snapd_packaging_dir, "opensuse", "snapd.changes")
    rewrite_version_number_file(
        # meh this is terrible, to keep the right indentation level,
        # prepend the number of spaces we currently have in the file to
        # the version number
        specFile,
        "Version:",
        "        " + opts.version,
    )

    # also add a template changelog to the changes file
    date = datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")

    email = maintainer[1]
    templ = f"""-------------------------------------------------------------------
{date} - {email}

- Update to upstream release {opts.version}

"""

    # first read the existing changelog lines
    with open(changesFile, "r") as fh:
        current = fh.read()
    with open(changesFile, "w") as fh:
        fh.write(templ)
        fh.write(current)


def main(opts):
    this_script = os.path.realpath(__file__)
    snapd_root_git_dir = os.path.dirname(os.path.dirname(this_script))
    snapd_packaging_dir = os.path.join(snapd_root_git_dir, "packaging")

    # read all the changelog entries, expected to be formatted by snappy-dch
    new_changelog_entry = opts.changelog.read()

    # verify that the changelog entry lines are all in the right format
    for line_number, line in enumerate(new_changelog_entry.splitlines(), start=1):
        # each line should start with either 4 spaces, a - and then another
        # space, or 6 spaces
        if not line.startswith("    - ") and not line.startswith("      "):
            raise RuntimeError(
                f"unexpected changelog line format in line {line_number}"
            )
        if len(line) >= 72:
            raise RuntimeError(
                f"line {line_number} too long, should wrap properly to next line"
            )

    # read the name and email of the person running the script using i.e. dch
    # conventions
    maintainer = debian.changelog.get_maintainer()

    # first handle all of the debian packaging files
    for distro in debianish_distros:
        debian_packaging_changelog = os.path.join(
            snapd_packaging_dir, distro.name, "changelog"
        )
        with open(debian_packaging_changelog) as fh:
            ch = debian.changelog.Changelog(fh)

        # setup a new block
        ch.new_block(
            package="snapd",
            version=opts.version + distro.version_suffix,
            distributions=distro.debian_name,
            urgency="medium",
            author=f"{maintainer[0]} <{maintainer[1]}>",
            date=debian.changelog.format_date(),
        )

        # add the new changelog entry with our standard header
        # the spacing here is manually adjusted, the top of the comment is always
        # the same
        templ = "\n  * New upstream release, LP: #1926005\n" + new_changelog_entry
        ch.add_change(templ)

        # write it out back to the changelog file
        with open(debian_packaging_changelog, "w") as fh:
            ch.write_to_open_file(fh)

    # now handle all of the non-debian packaging files
    for distro in other_distros:
        if distro == "arch":
            # for arch all we need to do is change the PKGBUILD "pkgver" key
            rewrite_version_number_file(
                os.path.join(snapd_packaging_dir, "arch", "PKGBUILD"),
                "pkgver=",
                opts.version,
            )
        elif distro == "fedora":
            update_fedora_changelog(
                opts, snapd_packaging_dir, new_changelog_entry, maintainer
            )

        elif distro == "opensuse":
            update_opensuse_changlog(
                opts, snapd_packaging_dir, new_changelog_entry, maintainer
            )


if __name__ == "__main__":
    opts = parse_arguments()
    main(opts)
