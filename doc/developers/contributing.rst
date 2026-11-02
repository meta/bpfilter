Contributing
============

Using AI to contribute to bpfilter
----------------------------------

.. admonition:: Why am I reading this?

   One of two reasons. Either you're thinking about contributing and want to know how AI fits in here, in which case read on, it's short. Or your PR was just closed with a link to this page, in which case the change looked like nobody wrote, understood, or tested it before sending it for review, or you used AI without saying so. Same document either way.

We have nothing against AI. We use it, and so do the regular contributors to this project. Autocomplete, LLMs, coding agents, all fine. You don't need to hide it or avoid it.

What we care about is time. Reviewing a change costs the reviewers time, and we're glad to spend it when the person who opened the PR spent theirs first: writing the code, understanding it, or testing it. When a PR is a prompt result its author never read, that trade is broken. You spent a few seconds and you're asking a reviewer for an hour. We don't care what you used. We care whether you did the work.

So before you open a PR:

**Understand what you're submitting.** You should be able to explain every line, why it's correct, and what you ruled out. If you can't review your own diff, don't send it. We won't do that review for you.

**Build and test it properly.** Configure and build with CMake the way the developer docs describe, run ``make -C $BUILD test`` (``make -C $BUILD fixstyle`` formats the code for you), and ``make -C $BUILD doc`` if you changed the documentation. The tests that cover your change matter most: the cmocka unit tests under ``tests/unit/``, plus the e2e suite where it applies. "I changed the code to fix X but didn't build or run it" is not a testing plan. If you're not a regular here yet, paste the test output into the PR. The summary line and pass counts are enough, and it's the fastest way to show us you actually ran it.

**Follow the style guide.** Formatting is enforced by ``.clang-format``, the rest is in :doc:`style`, and commits use ``component: subcomponent: short description``. Ignoring the style after it's been pointed out tells us the same thing an untested diff does: nobody looked.

**Say if you used AI.** A line in the PR is enough ("AI-drafted the tests and description, wrote the code by hand"). "None" is a fine answer. We may ask, so just be straight about it. Undisclosed AI is one of the things that gets a PR closed with a link to this page.

We close PRs, without a full review, when they were clearly never read by their author, weren't tested, or ignore the style guide after a heads-up. If it keeps happening we'll block you. We've spent more time on some of these review comments than the author spent opening the PR, and we won't keep making that trade.

If you're new and willing to put the work in, you're welcome here and we'll take the time to ramp you up. Pick something tagged `good first issue <https://github.com/meta/bpfilter/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22>`_, or email us (qde@naccy.de) and we'll find you a good starting task.

Where to start
--------------

If you want to start contributing to bpfilter, the best way to get to know the codebase would be to start with one of the ``@todo`` available in the code. Most of those tasks are small, self-contained, work trivial enough that they do not deserve their GitHub issue.

Once you know your way around the structure of the project, feel free to continue with the ``@todo``, or jump on a bigger issue in the `GitHub issues tracker <https://github.com/meta/bpfilter/issues>`_.

Join the `bpfilter Slack workspace <https://join.slack.com/t/bpfilter/shared_invite/zt-4d89whuae-JnJJ~h0zpdHwzP7wyYQpwA>`_ to ask questions or discuss contributions. You can also email qde@naccy.de.


To do
~~~~~

.. doxygenpage:: todo


Contributor License Agreement ("CLA")
-------------------------------------

In order to accept your pull request, you need to submit a CLA. You only need to do this once to work on any of Meta's open source projects.

Complete your CLA here: https://code.facebook.com/cla


Security
--------

We use GitHub issues to track public bugs. Please ensure your description is clear and has sufficient instructions to be able to reproduce the issue.

Meta has a `bounty program <https://www.facebook.com/whitehat>`_ for the safe disclosure of security bugs. In those cases, please go through the process outlined in that page and do not file a public issue.


License
-------

By contributing to bpfilter, you agree that your contributions will be licensed under the ``LICENSE`` file in the root directory of this source tree.
