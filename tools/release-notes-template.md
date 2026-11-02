<!--
Template for the release notes, based on the v0.7.0 release notes.

1. Collect the release data, e.g. `tools/release-data v0.8.0 > release.json`.
2. Replace each {{ field }} with the value of this field in release.json.
3. Write the entries of each section from the commit messages and the pull
   requests.
4. Remove the sections that have no entries.
5. Remove the comments of this template.

Rules for the entries:

- Write for system and network developers. Stay factual.
- Sort the changes into sections, not the pull requests. A pull request with
  a feature and a fix has an entry in New features and another in Bug fixes.
- Put each change in one section only. A change that requires users to act
  goes in Breaking changes.
- Describe what changed for the reader, not how the code changed.
- Start with the change in one short sentence. Then add what the reader
  needs: the new syntax, a limit, or how to migrate.
- Put matchers, keywords, options, functions, types, and files in `code`.
- Give an example of each new syntax, e.g. `tcp.sport not eq 80`.
- Link the pull request after the sentence it supports:
  ([#123](https://github.com/{{ repository }}/pull/123))
- Link the commit if the change has no pull request:
  ([`0123abcd`](https://github.com/{{ repository }}/commit/0123abcd))
- Credit the authors and co-authors of the change's commits. End the entry
  with their GitHub logins, after the final period: `... ([#123](...)). @a, @b`
- If a login is null in release.json, use the pull request author, or the
  author's name.
- Group related changes in one entry.
- Leave out the changes that neither users nor contributors will notice.
- Write each entry on one line. GitHub can render a newline as a line break.
- If the commits don't confirm a claim, add an HTML comment that starts with
  TODO under the entry.
-->

# bpfilter {{ end.ref }}

{{ stats.commits }} commits from {{ stats.contributors }} contributors since {{ start.ref }}, with {{ stats.lines_added }} lines added and {{ stats.lines_removed }} removed.

## Breaking changes

<!--
Changes that require users to act: removed or renamed syntax, options, or
API, and changed formats or defaults. Start the entry with the change in bold,
then say what to update, e.g.:

- **Hook rename:** `BF_HOOK_CGROUP_{INGRESS,EGRESS}` became `BF_HOOK_CGROUP_SKB_{INGRESS,EGRESS}` ([#455](https://github.com/meta/bpfilter/pull/455)). The old names are no longer accepted, so existing rulesets need updating. @yaakov-stein
-->

## New features

<!--
New hooks, verdicts, matchers, keywords, options, and API, e.g.:

- `REDIRECT` verdict, which sends the packet to another interface. It's supported on TC and XDP, but XDP can only redirect to egress ([#408](https://github.com/meta/bpfilter/pull/408)). @qdeslandes
-->

## Bug fixes

<!--
Say what was wrong, e.g.:

- The `ip6.dscp` matcher used the wrong byte order on little-endian ([#475](https://github.com/meta/bpfilter/pull/475)). @yaakov-stein
-->

## Misc.

<!--
The other changes that users or contributors will notice: performance,
documentation, tests, CI, build, packaging, and tools, e.g.:

- Map elements are loaded in batches ([#542](https://github.com/meta/bpfilter/pull/542)). @pzmarzly
-->

## Contributors

<!--
One line per contributor, in the order of release.json. If a login is null in
release.json, use the pull request author, or the contributor's name.
-->

- @{{ contributors[].login }}

## New contributors

<!--
One line per contributor with "first_time": true. Link the earliest merged
pull request that contains one of their commits.
-->

- @{{ contributors[].login }} made their first contribution in [#{{ pull_requests[].number }}](https://github.com/{{ repository }}/pull/{{ pull_requests[].number }})

**Full changelog**: https://github.com/{{ repository }}/compare/{{ start.ref }}...{{ end.ref }}
