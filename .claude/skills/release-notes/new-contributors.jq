# Print the "New contributors" section of the release notes: one line per
# contributor with "first_time": true, linking the earliest merged pull request
# that contains one of their commits.
#
# Usage: jq -r -f new-contributors.jq release.json

. as $data
| $data.contributors[]
| select(.first_time)
| . as $contributor
| [$data.commits[]
   | select(any(.author, .co_authors[]; (.login // .email) == ($contributor.login // $contributor.email)))
   | .pull_requests[]] as $numbers
| ([$data.pull_requests[] | select(.number as $n | $numbers | index($n))] | min_by(.merged_at)) as $first
| (if .login then "@\(.login)" else "\(.name) (no login)" end) as $who
| if $first then "- \($who) made their first contribution in [#\($first.number)](\($first.url))"
  else "- \($who) <!-- TODO: no pull request found -->" end
