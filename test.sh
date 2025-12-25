#!/bin/sh

OWNER="flathub"
REPO="flathub"
PR_NUM=7408

gh api graphql \
  -f query='
    query($owner: String!, $repo: String!, $number: Int!) {
      repository(owner: $owner, name: $repo) {
        pullRequest(number: $number) {
          reviewThreads(first: 100) {
            nodes {
              isResolved
            }
          }
        }
      }
    }
  ' \
  -F owner="$OWNER" \
  -F repo="$REPO" \
  -F number="$PR_NUM"
