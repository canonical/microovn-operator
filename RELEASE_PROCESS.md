# MicroOVN Charm Release Process

## Release Strategy

MicroOVN charm feature development takes place on the "main" branch.

The main branch has `charmcraft.yaml` set up to use the base for the next major release version. This ensures the charm units are deployed as the expected ubuntu image.

Stable MicroOVN charm releases follow the [Ubuntu release cycle](https://ubuntu.com/about/release-cycle), and a new stable version is made shortly after each new Ubuntu LTS release.

The [Stable branches](##Stable-Branches) are named "branch-YY.MM", where the numbers come from the corresponding MicroOVN snap version string, for example: "branch-25.03".

## Stable Branches

We go out of our way to embed logic in the product itself, its test suite and CI pipeline to avoid manual effort on each new release.

Steps to cut a stable branch:

1. Create a branch "branch-YY.MM" at the commit agreed for version cutoff.
2. Create a commit "Prepare for YY.MM", This should:
    - Set the charmcraft base to `ubuntu@YY.MM`
    - Update MICROOVN_CHANNEL in microovn/src/charm.py to "YY.MM/stable"
3. Create a PR named "YY.MM Release" for the branch "branch-YY.MM" containing
    this commit.
4. Review and merge.
