#!/usr/bin/env bash
# Commits files to a branch through the GitHub GraphQL API. GitHub signs the
# commits it creates, so they pass the main ruleset's verified-signature rule.
# A `git push` from a runner would land unsigned.
#
#   signed-commit.sh <branch> <expected-head-sha> <message> <file>...
#
# Needs GH_TOKEN and GH_REPO (owner/name). Prints the new commit's sha.
set -euo pipefail

branch=$1
head=$2
message=$3
shift 3

additions=$(for f in "$@"; do
    jq -n --arg path "$f" --rawfile contents <(base64 -w0 "$f") \
        '{path: $path, contents: $contents}'
done | jq -s .)

jq -n \
    --arg repo "$GH_REPO" \
    --arg branch "$branch" \
    --arg head "$head" \
    --arg message "$message" \
    --argjson additions "$additions" \
    '{
        query: "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid } } }",
        variables: {input: {
            branch: {repositoryNameWithOwner: $repo, branchName: $branch},
            expectedHeadOid: $head,
            message: {headline: $message},
            fileChanges: {additions: $additions}
        }}
    }' |
    gh api graphql --input - -q '.data.createCommitOnBranch.commit.oid'
