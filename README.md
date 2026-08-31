# snyk-autoimport

Bulk-import repositories from your source control management (SCM) provider into
a Snyk organization with a single command.

```bash
snyk-autoimport import --snyk-org "Acme Corp" --source github-cloud-app --source-org acme-corp
```

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
- [Quick start](#quick-start)
- [Commands](#commands)
- [What an import looks like](#what-an-import-looks-like)
- [Credentials and configuration](#credentials-and-configuration)
- [Continuous integration](#continuous-integration)
- [License](#license)

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

## Quick start

```bash
snyk-autoimport auth login                              # one time, interactive
snyk-autoimport integrations --snyk-org "Acme Corp"     # which --source to use
snyk-autoimport import --snyk-org "Acme Corp" \
  --source github-cloud-app --source-org acme-corp --dry-run
snyk-autoimport import --snyk-org "Acme Corp" \
  --source github-cloud-app --source-org acme-corp
```

Re-running is safe: repositories already in Snyk are skipped, so a partially
failed run can simply be repeated.

## Commands

### `auth`

| Command | Description |
|---|---|
| `auth login` | Asks for your region, Snyk token, source, and that source's credential. Requires an interactive terminal. |
| `auth status` | Shows the config path, which credentials are set, and the region. Token values are never printed. |
| `auth logout` | Removes stored credentials. |

`auth login` asks for one source at a time, so you only paste the credential you
need. Run it again to add another. Three things are checked against live APIs
before it finishes, so a problem surfaces here rather than mid-import:

- **Region first**, because the Snyk token is verified against that region's API
  — a token valid in `SNYK-EU-01` returns `401` against the US host.
- **The Snyk token**, by listing the organizations it can see.
- **The source credential**, against the provider. `azure-repos` is reported as
  "not checked" rather than guessed: a PAT scoped to Code alone is rejected by
  every account-level endpoint, so a result would mean nothing.

Self-hosted sources (`github-enterprise`, `bitbucket-server`) are also asked for
their server URL, which is stored — after that `--source-url` is only needed to
override it for one run.

### `integrations`

Lists the SCM integrations configured on an organization, with the `--source`
value for each. Use it when unsure which to pass — an organization can have
several from the same family, and `github` and `github-cloud-app` behave
differently.

```bash
snyk-autoimport integrations --snyk-org "Acme Corp"
```

### `import`

| Flag | Description |
|---|---|
| `--snyk-org` | Organization name or slug. An ambiguous name fails rather than resolving to an arbitrary match. |
| `--snyk-org-id` | Organization UUID. Skips name resolution; recommended for automation. |
| `--source` | **Required.** Never inferred, because one organization may have several integrations of the same family. |
| `--source-org` | What to import from, which differs per provider — see below. `--github-org` is an accepted alias. |
| `--source-url` | Host for self-hosted providers. Only needed if `auth login` has not stored it. |
| `--region` | Overrides the stored region. |
| `--dry-run` | Show what would be imported and exit, changing nothing. |
| `--yes` | Skip the confirmation prompt. Required for non-interactive use. |

`--source-org` is the flag most easily passed wrong:

| `--source` | Snyk UI name | `--source-org` is |
|---|---|---|
| `github`, `github-cloud-app`, `github-enterprise` | GitHub, GitHub Cloud App, GitHub Enterprise | a GitHub **organization** (personal accounts are not supported) |
| `gitlab` | GitLab | a GitLab **group**, possibly nested (`group/subgroup`) |
| `azure-repos` | Azure Repos | an Azure DevOps **organization** — every project inside it is discovered |
| `bitbucket-cloud`, `bitbucket-connect-app` | Bitbucket Cloud, Bitbucket Cloud App | a Bitbucket **workspace** |
| `bitbucket-server` | Bitbucket Server | a Bitbucket **project name** |

`bitbucket-connect-app` is the integration Snyk shows as **Bitbucket Cloud App**
and is what a recently-connected workspace will have; `bitbucket-cloud` is the
older username/app-password integration. `github-server-app` is not supported —
its project origin has no verified deduplication mapping.

If the `--source` you pass is not configured on the target organization, the
command stops before discovering anything and tells you to connect it in Snyk.
It deliberately does not offer one of the organization's other integrations
instead, which would risk importing the wrong repositories into the wrong place.

## What an import looks like

```text
✓ Resolved "Acme Corp" → d2f6e6d5-… (group: Acme Ltd)
✓ Using github-cloud-app integration 0686349f-…
Discovering repos in acme-corp...
✓ Found 24 repo(s)
✓ 21 already imported — 3 new to import

Importing... Snyk clones each repo and scans it for manifests, which usually takes a few minutes.
  … still scanning (15s) — 0/3 repos done
  … still scanning (1m 15s) — 2/3 repos done

Done.
  11 project(s) created
```

**Expect minutes, not seconds.** Snyk clones and scans each repository
server-side; one repository commonly takes one to three minutes and nothing on
the client can make that faster. The `… still scanning` line prints every 15
seconds so a long import is distinguishable from a stalled one.

**Repos and projects are different counts.** Projects are what Snyk creates, one
per manifest found — so one repository routinely produces several, and a
repository with no supported manifests produces none. `0 project(s) created` is a
normal, successful result for such a repository.

With `github-cloud-app`, a repository the Snyk GitHub App was not granted access
to is discovered but fails with `404` during import: discovery uses your own
token, which typically sees more than the App was granted.

## Credentials and configuration

`auth login` writes `.snyk-autoimport.json` with `0600` permissions, resolved
from the installed package directory — so logging in once holds wherever you run
the command from. Run `auth status` to print the path. One consequence: a second
checkout (a `git worktree`, or another clone) is a separate package directory and
needs its own login.

> [!WARNING]
> This file holds live tokens inside a git working tree. Its `.gitignore` entry
> is load-bearing — do not remove it, and do not `git add -f` the file. If you
> fork or copy this repository, confirm the entry survived.

Environment variables always win over the stored file, so automation can supply
secrets without ever writing a token to disk. This is the recommended approach
for CI and shared machines.

| Source | Variables |
|---|---|
| Snyk | `SNYK_TOKEN`, `SNYK_API` |
| GitHub (all three) | `GITHUB_TOKEN` |
| GitLab | `GITLAB_TOKEN` |
| Azure Repos | `AZURE_TOKEN` |
| Bitbucket Cloud (both) | `BITBUCKET_CLOUD_USERNAME` + `BITBUCKET_CLOUD_PASSWORD` (Basic), or `BITBUCKET_CLOUD_API_TOKEN` / `BITBUCKET_CLOUD_OAUTH_TOKEN` (Bearer). `BITBUCKET_CLOUD_AUTH_METHOD` forces one of `user`, `api`, `oauth`. |
| Bitbucket Server | `BITBUCKET_SERVER_USERNAME` + `BITBUCKET_SERVER_PASSWORD` (Basic), or `BITBUCKET_SERVER_TOKEN` (Bearer) |
| Pacing | `CONCURRENT_IMPORTS` (default 15) |

For Bitbucket Cloud Basic auth, pair an Atlassian account **email** with an **API
token**, or a Bitbucket **username** with an **app password** — crossing them
over fails. For Bitbucket Server, setting a username selects Basic, so a username
with no password is an error rather than a silent fall back to the token.

### Regions

Pass `--region`, or set it during `auth login`. Accepted values are
`snyk-us-01` (default), `snyk-us-02`, `snyk-eu-01` and `snyk-au-01` —
case-insensitive, and identical to the aliases `snyk config environment` takes.
See
[Regional hosting and data residency](https://docs.snyk.io/snyk-data-and-governance/regional-hosting-and-data-residency)
for which one you are on.

Note that recent US Enterprise and Pilot accounts are on **SNYK-US-02**, not the
default. SNYK-GOV-01 is not supported: it does not accept API keys.

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

## License

Licensed under the Apache License 2.0.
