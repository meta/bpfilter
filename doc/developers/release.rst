Releasing
=========

A release starts with a tag: this is the only place ``bpfilter``'s version lives. CMake and Packit will both read it from there, so you don't have to update anything in the repository, not even ``Version`` in ``tools/rpm/bpfilter.spec``.

Fedora builds the package from its own copy of the spec file, in `dist-git <https://src.fedoraproject.org/rpms/bpfilter>`_. `Packit <https://packit.dev>`_ will carry the release there: it copies the spec file, sets ``Version``, uploads the tarball to the lookaside cache, and opens a pull request in dist-git.

Requirements
------------

You need to be a maintainer of the Fedora package, with ``packit`` and ``fedpkg`` installed.

Packit also needs an API token to open the pull request. Create one from your `src.fedoraproject.org settings <https://src.fedoraproject.org/settings>`_ with the ``fork_project``, ``pull_request_create``, and ``pull_request_update`` ACLs, and add it to ``~/.config/packit.yaml``:

.. code-block:: yaml

    fas_user: $FEDORA_USER
    authentication:
      src.fedoraproject.org:
        token: $API_TOKEN

Publish a new version
---------------------

Let's say we want to release ``$VERSION`` (e.g. ``0.8.0``):

1. Make sure the ``CI`` and ``Package`` workflows are green on ``main``.
2. Create the ``v$VERSION`` tag and publish the GitHub release. Packit will download the tarball from GitHub, so the tag has to be there first.
3. Get a Kerberos ticket, which you need to upload the tarball and to build the package:

   .. code-block:: shell

       fkinit -u $FEDORA_USER

4. From a clone of this repository, ask Packit to open the pull request:

   .. code-block:: shell

       packit propose-downstream . $VERSION --dist-git-branch rawhide

5. Review the pull request in dist-git and merge it. Then, from a clone of dist-git, build the package:

   .. code-block:: shell

       fedpkg switch-branch rawhide
       git pull
       fedpkg build

Once Rawhide is fine, repeat the last two steps for each stable branch (e.g. ``f44`` or ``epel10``), and use ``fedpkg update`` to create their Bodhi updates. Rawhide doesn't need one.

Change the package
------------------

Packit will overwrite the spec file in dist-git for each release, so packaging changes belong in ``tools/rpm/bpfilter.spec``. If a fix lands in dist-git first, bring it back here too.
