Releasing
=========

A release starts with a tag, which defines ``bpfilter``'s version. Leave ``Version`` in ``tools/rpm/bpfilter.spec`` unchanged.

Fedora builds the package from its own spec file in `dist-git <https://src.fedoraproject.org/rpms/bpfilter>`_. `Release Monitoring <https://release-monitoring.org>`_ detects new versions and triggers `Packit <https://packit.dev/docs/fedora-releases-guide/dist-git-onboarding>`_. Packit updates the version, uploads the tarball, and opens release pull requests. Merging them triggers production builds and Bodhi updates.

Requirements
------------

You need to be a maintainer of the Fedora package. Release Monitoring must map the upstream project to Fedora's ``bpfilter`` package. Set the package's monitoring status in dist-git to ``Monitoring``.

Packit reads its configuration from dist-git's default branch, ``rawhide``, for every target branch. Copy this repository's ``.packit.yaml`` to the root of ``rawhide`` once to enable the jobs. Packit copies later configuration changes from each release tag into its release pull requests. Include those changes before tagging.

The configuration targets supported Fedora releases, EPEL 9, and active EPEL 10 branches. Keep the release jobs in GitHub's ``.packit.yaml`` so each copied configuration preserves the automation.

Publish a new version
---------------------

Let's say we want to release ``$VERSION`` (e.g. ``0.8.0``):

1. Make sure the ``CI`` and ``Package`` workflows are green on ``main``.
2. Push the ``v$VERSION`` tag and publish its GitHub release.
3. Wait for Release Monitoring to detect the version and Packit to open the dist-git pull requests.
4. Review each pull request. Wait for its scratch build and tests to pass, then merge it. Each merge triggers a production Koji build for that branch.
5. Monitor the builds and Bodhi updates. Packit creates updates after successful builds for stable Fedora and EPEL branches. Fedora creates Rawhide updates automatically. Request promotion to stable in Bodhi when eligible if automatic promotion does not handle it.

Change the package
------------------

Keep packaging changes in ``tools/rpm/bpfilter.spec`` and apply the same changes to ``bpfilter.spec`` in the affected dist-git branches. The ``pull_from_upstream`` job updates the existing downstream spec file rather than importing the upstream spec. Preserve each branch's version when applying packaging changes. If a fix lands in dist-git first, bring it back here too.
