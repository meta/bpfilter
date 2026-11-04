Releasing
=========

A release starts with a tag, which defines ``bpfilter``'s version. Leave ``Version`` in ``tools/rpm/bpfilter.spec`` unchanged.

``tools/rpm/bpfilter.spec`` is the source of truth for Fedora and EPEL packages. `Packit-as-a-Service <https://packit.dev/docs/packit-as-a-service/>`_ builds RPMs in Copr for upstream pull requests on both x86_64 and aarch64.

Publishing a GitHub release triggers Packit's ``propose_downstream`` job. Packit imports the upstream spec from the release tag into ``bpfilter.spec`` in `dist-git <https://src.fedoraproject.org/rpms/bpfilter>`_, sets the version, uploads the tarball, and opens release pull requests. Merging them triggers production builds and Bodhi updates.

Requirements
------------

Packit-as-a-Service must be enabled on the upstream GitHub repository.

The downstream Koji and Bodhi jobs use ``.packit.yaml`` from dist-git's default branch, ``rawhide``. This configuration applies to every target branch.

Packit copies this repository's ``.packit.yaml`` from each release tag into its release pull requests. Include configuration changes before tagging. The configuration targets supported Fedora releases, EPEL 9, and active EPEL 10 branches. Keep the downstream jobs in GitHub's ``.packit.yaml`` so each copied configuration preserves the automation.

Publish a new version
---------------------

Let's say we want to release ``$VERSION`` (e.g. ``0.8.0``):

1. Make sure the ``CI`` and ``Package`` workflows are green on ``main``.
2. Push the ``v$VERSION`` tag and publish its GitHub release. Pushing a tag alone does not trigger Packit.
3. Wait for Packit to open the dist-git pull requests.
4. Review each pull request. Wait for its scratch build and tests to pass, then merge it. Each merge triggers a production Koji build for that branch. If the scratch build fails, update the upstream spec before publishing another release, or fix the pull request and apply the same fix upstream.
5. Monitor the builds and Bodhi updates. Packit creates updates after successful builds for stable Fedora and EPEL branches. Fedora creates Rawhide updates automatically. Request promotion to stable in Bodhi when eligible if automatic promotion does not handle it.

Change the package
------------------

Keep packaging changes in ``tools/rpm/bpfilter.spec``. Packit builds them on upstream pull requests and imports them into dist-git with the next release. Do not maintain a separate downstream spec.

To retry an update for an existing release, use:

.. code-block:: shell

    packit propose-downstream https://github.com/meta/bpfilter.git $VERSION \
      --dist-git-branch fedora-all,epel-10-all,epel-9 \
      --pr

Packit uses the spec from the selected release tag. Commit packaging changes before tagging the next release.
