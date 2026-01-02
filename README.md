## Flathub submission validator action

Internal Flathub submission validator action to aid review of new
submission pull requests.

### Usage

```yaml
name: Check PRs

on:
  workflow_dispatch:
  schedule:
    - cron: '0 */2 * * *'

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  check-prs:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    permissions:
      pull-requests: write
    steps:
      - uses: flathub-infra/submission-validator-action@<sha>
```

### Development

```sh
uv run ruff format
uv run ruff check --fix --exit-non-zero-on-fix
uv run mypy .
```
