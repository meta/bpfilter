---
name: release-notes
description: Write the Markdown release notes of a bpfilter release with tools/release-data and tools/release-notes-template.md. Use it whenever the user asks to write, draft, or update the release notes, the changelog, or the GitHub release text of a bpfilter version, tag, or commit range.
argument-hint: "[[START] END]"
---

# Write the release notes

Write the release notes of a bpfilter release to `release-notes-<END>.md`, at
the root of the repository. The skill takes the arguments of
`tools/release-data`:

- No argument: END is the tag on HEAD, and START is the previous tag.
- `END`: START is the previous tag.
- `START END`: both ends are given.

START is excluded from the release, and END is included.

Don't publish the release: the user reviews the notes first.

## 1. Collect the data

From the root of the repository, run:

```bash
data=$(mktemp --suffix=.json) && tools/release-data $ARGUMENTS > "$data" && echo "$data"
```

The command prints the path of the data file. Replace DATA with this path in
the next commands: shell variables don't persist between commands.

If the script fails, report its error and stop. For example, without an
argument, HEAD needs a tag.

The script can warn that some commits are not on GitHub. These commits have no
pull request, and their authors can have no login. Report the warning at the
end.

## 2. Read the template and the data

Read `tools/release-notes-template.md`. Its comments hold all the rules for the
notes: the sections, how to sort the changes, and how to write and credit an
entry. Follow them. This skill only adds the workflow around the template, so
the rules stay in one place.

Print the data in a compact form instead of reading the JSON file, which is
about four times larger:

```bash
# The release range and its stats.
jq '{repository, start, end, stats}' DATA

# The pull requests, newest first.
jq -r '.pull_requests[] | "#\(.number) \(.title) (author: \(.author))"' DATA

# The commits, newest first, with their pull requests, authors, and messages.
jq -r '.commits[] | "=== \(.sha[0:8]) \(.pull_requests | map("#\(.)") | join(" ")) \([.author, .co_authors[]] | map(if .login then "@\(.login)" else "\(.name) (no login)" end) | join(", "))\n\(.subject)\n\n\(.body)\n"' DATA
```

Read every commit message, body included. The bodies explain why a change was
made and what it changes for users, and the subjects often don't.

In the next steps, START and END are the `start.ref` and `end.ref` printed by
the first command.

## 3. Sort the changes

Sort each commit into a section of the template, or leave it out. Then group
the related commits of each section into entries.

- Breaking changes can hide in commits that don't mention them. List the
  public API headers that changed with
  `git diff --stat START END -- src/libbpfilter/include/bpfilter/`, then read
  their diff.
- If the commits of a pull request don't explain it, read its description with
  `gh pr view NUMBER --json body --jq .body`.
- Take the examples of new syntax from the reference documentation of the
  release, so they are correct:
  `git grep -n KEYWORD END -- doc/usage/reference/`.
- If an author has no login, the pull request author can be the same person.
  Compare the commit author name with `gh api users/LOGIN --jq .name` before
  you credit this login.

## 4. Write the notes

Write the notes with the structure of the template, without its comments. Fill
the placeholders with the values of the data.

Generate the two contributor sections instead of writing them by hand:

```bash
# Contributors.
jq -r '.contributors[] | if .login then "- @\(.login)" else "- \(.name) (no login)" end' DATA

# New contributors, with their earliest merged pull request.
jq -r -f .claude/skills/release-notes/new-contributors.jq DATA
```

Replace each "(no login)" marker with the login you confirmed in step 3. If
there is no such login, remove the marker and keep the name.

Write the notes to `release-notes-<END>.md`, where `<END>` is `end.ref` in the
data. If this file exists, ask the user before you overwrite it: it can hold
their edits.

Don't add any AI attribution to the notes.

## 5. Check the notes

Run these checks and fix what they find:

```bash
notes=release-notes-<END>.md data=DATA
links() { sed '/^## Contributors/,$d' "$notes" | grep -oE '/pull/[0-9]+' | cut -d/ -f3 | sort -u; }
prs() { jq -r '.pull_requests[].number' "$data" | sort -u; }

echo "Placeholders and template comments left (TODO comments are expected):"
grep -n '{{\|<!--' "$notes" | grep -v TODO

echo "Pull requests linked by the notes but absent from the data:"
comm -23 <(links) <(prs)

echo "Entries that don't end with a credit:"
sed -n '/^## Breaking changes/,/^## Contributors/p' "$notes" | grep '^- ' | grep -vE '@[A-Za-z0-9-]+$'

echo "Pull requests that the notes leave out:"
comm -13 <(links) <(prs) | while read -r n; do
    jq -r --argjson n "$n" '.pull_requests[] | select(.number == $n) | "#\(.number) \(.title)"' "$data"
done
```

An entry can end with a name instead of a login when the author has no login.
Leaving pull requests out is expected: the template leaves out the changes
that neither users nor contributors will notice.

Then report to the user:

1. The path of the notes.
2. The TODO comments: the claims to confirm.
3. The pull requests that the notes leave out, with their titles, so the user
   can check that none is missing.
4. The authors credited with the login of a pull request author.
5. The warnings of `tools/release-data`, if any.
