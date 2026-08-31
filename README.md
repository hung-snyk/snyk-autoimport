# snyk-autoimport

Bulk-import repositories from your source control management (SCM) provider into
a Snyk organization with a single command.

It resolves your Snyk organization and SCM integration, discovers repositories,
skips anything already imported, submits the import, and reports the outcome —
replacing the hand-authored JSON files, multi-step commands, and log-file
inspection that bulk importing otherwise requires.

**Self-contained.** The tool talks directly to Snyk's documented
[Import API](https://docs.snyk.io/developer-tools/snyk-api/reference/import-projects-v1)
and to each provider's public REST API. Three runtime dependencies, no HTTP
client or provider SDKs — discovery uses the Node runtime's built-in `fetch`.

> **Support notice** — an independent, community project. **Not** an official
> Snyk product, and not covered by Snyk support or any Snyk service agreement.
> Provided as-is for evaluation and internal automation use.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Commands](#commands)
- [Example](#example)
- [Credentials and configuration](#credentials-and-configuration)
- [Continuous integration](#continuous-integration)

## Requirements

| Requirement | Details |
|---|---|
| Node.js | 20 or later |
| Snyk API token | Classic `github` and `github-enterprise` need a **personal** token, not a service account — they authenticate through a personal GitHub OAuth link and return `401` otherwise. Everything else works with a service account. |
| SCM credential | Snyk cannot expose the credential stored on an integration, so discovery needs its own. |
| Configured Snyk integration | The target organization must already have the relevant SCM integration connected in Snyk. |

## Installation

Not published to npm, so clone and build:

```bash
git clone https://github.com/hung-snyk/snyk-autoimport.git
cd snyk-autoimport
npm install && npm run build
node dist/cli.js --help
```

Optionally expose it as a global command with `npm link` (`npm unlink -g
snyk-autoimport` to remove). Examples below use `snyk-autoimport`; substitute
`node dist/cli.js` if you did not link it.

## Commands

| Command | Description |
|---|---|
| `auth login` | Asks for your region, Snyk token, source, and that source's credential, checking each against a live API. Self-hosted sources are also asked for their server URL, which is stored. One source at a time — run it again to add another. Requires an interactive terminal. |
| `auth status` | Shows the config path, which credentials are set, and the region. Token values are never printed. |
| `auth logout` | Removes stored credentials. |
| `integrations --snyk-org "<name>"` | Lists the SCM integrations configured on an organization, with the `--source` value for each. Use it when unsure which to pass — an organization can have several from the same family, and `github` and `github-cloud-app` behave differently. |
| `import --snyk-org "<name>" --source <source> --source-org <org>` | Discovers repositories, skips those already imported, submits the rest, and prints a summary. |

`import` flags:

| Flag | Description |
|---|---|
| `--snyk-org` | Organization name or slug. An ambiguous name fails rather than resolving to an arbitrary match. |
| `--snyk-org-id` | Organization UUID. Skips name resolution; recommended for automation. |
| `--source` | **Required.** Never inferred, because one organization may have several integrations of the same family. |
| `--source-org` | The organization, group, workspace or project to import from, depending on the provider. `--github-org` is an accepted alias. |
| `--source-url` | Host for self-hosted providers. Only needed if `auth login` has not stored it. |
| `--region` | Overrides the stored region. |
| `--dry-run` | Show what would be imported and exit, changing nothing. |
| `--yes` | Skip the confirmation prompt. Required for non-interactive use. |

## Example

Log in once, interactively:

```text
$ snyk-autoimport auth login

Which Snyk region is your account on?
  [1] snyk-us-01  (default, current)
  [2] snyk-us-02
  [3] snyk-eu-01
  [4] snyk-au-01
Pick one (1-4 or name) [blank keeps snyk-us-01]:

Snyk API token: ***
  Checking token... ✓ valid (6 organizations visible)

Which source will you import from?
  [1] GitHub               --source github
  [2] GitHub Cloud App     --source github-cloud-app
  [3] GitHub Enterprise    --source github-enterprise
  [4] GitLab               --source gitlab
  [5] Azure Repos          --source azure-repos
  [6] Bitbucket Server     --source bitbucket-server
  [7] Bitbucket Cloud      --source bitbucket-cloud
  [8] Bitbucket Cloud App  --source bitbucket-connect-app
Pick one (1-8 or name): 2

GitHub token: ***

Checking github-cloud-app credentials...
  ✓ authenticated as your-github-username

✓ Stored 2 credential(s), chmod 600:
    /path/to/snyk-autoimport/.snyk-autoimport.json
    Environment variables override this file, so CI never needs it.
```

Then import. Re-running is safe — repositories already in Snyk are skipped, so a
partially failed run can simply be repeated.

```text
$ snyk-autoimport import --snyk-org "Acme Corp" --source github-cloud-app --source-org acme-corp

✓ Resolved "Acme Corp" → d2f6e6d5-a481-4d4f-977d-349d689207cf (group: Acme Ltd)
✓ Using github-cloud-app integration 0686349f-4442-415e-ae17-88713c79d964
Discovering repos in acme-corp...
✓ Found 24 repo(s)
✓ 21 already imported — 3 new to import
Import 3 repo(s) into Acme Corp? (Y/n)

Importing... Snyk clones each repo and scans it for manifests, which usually takes a few minutes.
  … still scanning (15s) — 0/3 repos done
  … still scanning (30s) — 1/3 repos done
  … still scanning (1m 15s) — 2/3 repos done

Done.
  3 of 3 repo(s) imported — 11 project(s) created

Re-run the same command any time — already-imported repos are skipped automatically.
```

Both counts are reported because they answer different questions: repositories
are what you asked to import, while projects are what Snyk created — one per
manifest it found. A repository with no supported manifests imports
successfully and produces none, which the summary calls out separately.

## Credentials and configuration

`auth login` writes `.snyk-autoimport.json` with `0600` permissions, resolved
from the installed package directory — so logging in once holds wherever you run
from. `auth status` prints the path. A second checkout (another clone, or a `git
worktree`) is a separate package directory and needs its own login.

> [!WARNING]
> This file holds live tokens inside a git working tree. Its `.gitignore` entry
> is load-bearing — do not remove it, and do not `git add -f` the file. If you
> fork or copy this repository, confirm the entry survived.

Environment variables always win over the file, so automation can supply secrets
without writing a token to disk — the recommended approach for CI and shared
machines:

| Source | Variables |
|---|---|
| Snyk | `SNYK_TOKEN`, `SNYK_API` |
| GitHub (all three) | `GITHUB_TOKEN` |
| GitLab | `GITLAB_TOKEN` |
| Azure Repos | `AZURE_TOKEN` |
| Bitbucket Cloud (both) | `BITBUCKET_CLOUD_USERNAME` + `BITBUCKET_CLOUD_PASSWORD` (Basic), or `BITBUCKET_CLOUD_API_TOKEN` / `BITBUCKET_CLOUD_OAUTH_TOKEN` (Bearer). `BITBUCKET_CLOUD_AUTH_METHOD` forces `user`, `api` or `oauth`. |
| Bitbucket Server | `BITBUCKET_SERVER_USERNAME` + `BITBUCKET_SERVER_PASSWORD` (Basic), or `BITBUCKET_SERVER_TOKEN` (Bearer) |

For Bitbucket Cloud, pair an Atlassian **email** with an **API token**, or a
Bitbucket **username** with an **app password** — crossing them over fails. For
Bitbucket Server, a username selects Basic, so a username with no password is an
error rather than a silent fall back to the token.

## Continuous integration

Pass credentials through the environment, target the organization by UUID, and
skip the prompt:

```bash
SNYK_TOKEN="$SNYK_TOKEN" GITHUB_TOKEN="$GITHUB_TOKEN" \
  snyk-autoimport import \
    --snyk-org-id 00000000-0000-0000-0000-000000000000 \
    --source github-cloud-app --source-org acme-corp --yes
```

Deduplication runs against live Snyk state every time, so this is safe to run on
a schedule to pick up new repositories. Budget wall-clock time rather than a
fixed timeout: the run lasts as long as Snyk takes to scan everything submitted.
