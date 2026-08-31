# snyk-autoimport

Bulk-import repositories from your source control management (SCM) provider into
a Snyk organization with a single command.

`snyk-autoimport` resolves your Snyk organization and SCM integration, discovers
repositories, skips anything already imported, submits the import, and reports
the outcome — replacing the hand-authored JSON files, multi-step commands, and
log-file inspection that bulk importing otherwise requires.

```bash
node dist/cli.js import --snyk-org "Acme Corp" --source github-cloud-app --source-org acme-corp
```

**Self-contained.** The tool talks directly to Snyk's documented
[Import API](https://docs.snyk.io/developer-tools/snyk-api/reference/import-projects-v1)
and to each SCM provider's public REST API. It has three runtime dependencies
and no HTTP client or provider SDKs — repository discovery across every
supported provider uses the Node runtime's built-in `fetch`. Nothing here wraps another
CLI, so its behaviour is tied only to APIs Snyk and the providers publish and
version.

> **Support notice**
>
> This is an independent, community project. It is **not** an official Snyk
> product and is not covered by Snyk support or any Snyk service agreement. It
> is provided as-is for evaluation and internal automation use.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [What an import looks like](#what-an-import-looks-like)
- [Commands](#commands)
- [Supported sources](#supported-sources)
- [Regions](#regions)
- [Credentials and configuration](#credentials-and-configuration)
- [Continuous integration](#continuous-integration)
- [How it works](#how-it-works)
- [Known limitations](#known-limitations)
- [Development](#development)
- [License](#license)

## Requirements

| Requirement | Details |
|---|---|
| Node.js | 20 or later. The tool uses the runtime's built-in `fetch`. |
| npm registry access | Required during installation, for three runtime dependencies and the TypeScript build. |
| Snyk API token | Required. Token type depends on the integration — see [Supported sources](#supported-sources). |
| SCM access token | Required. Snyk cannot expose the credential stored on an SCM integration, so repository discovery needs its own token. |
| Configured Snyk integration | The target Snyk organization must already have the relevant SCM integration configured. |

## Installation

This project is not published to npm, so clone the repository and build it
locally.

```bash
git clone https://github.com/hung-snyk/snyk-autoimport.git
cd snyk-autoimport
npm install
npm run build
```

Run the CLI directly:

```bash
node dist/cli.js --help
```

Optionally, expose it as a global `snyk-autoimport` command:

```bash
npm link          # install the global command
npm unlink -g snyk-autoimport   # remove it later
```

All examples below use `node dist/cli.js`. Substitute `snyk-autoimport` if you
linked the command globally.

## Quick start

```bash
# 1. Store credentials and region (one time, interactive)
node dist/cli.js auth login

# 2. Confirm which integrations the target organization has configured
node dist/cli.js integrations --snyk-org "Acme Corp"

# 3. Preview the import — discovers and deduplicates, creates nothing
node dist/cli.js import \
  --snyk-org "Acme Corp" \
  --source github-cloud-app \
  --source-org acme-corp \
  --dry-run

# 4. Run the import
node dist/cli.js import \
  --snyk-org "Acme Corp" \
  --source github-cloud-app \
  --source-org acme-corp
```

Re-running the same command is safe. Repositories already present in Snyk are
skipped automatically, so a partially failed run can simply be repeated.

## What an import looks like

```text
✓ Resolved "Acme Corp" → d2f6e6d5-a481-4d4f-977d-349d689207cf (group: Acme Ltd)
✓ Using github-cloud-app integration 0686349f-4442-415e-ae17-88713c79d964
Discovering repos in acme-corp...
✓ Found 24 repo(s)
✓ 21 already imported — 3 new to import

Importing... Snyk clones each repo and scans it for manifests, which usually takes a few minutes.
  … still scanning (15s) — 0/3 repos done
  … still scanning (30s) — 1/3 repos done
  … still scanning (1m 15s) — 2/3 repos done

Done.
  11 project(s) created
```

**Expect the import step to take minutes, not seconds.** Snyk clones each
repository server-side and scans it for manifests; a single repository commonly
takes one to three minutes, and nothing on the client can make that faster. The
`… still scanning` line is printed every 15 seconds so a long import is
distinguishable from a stalled one.

The counts mean different things and are worth reading precisely:

- **repos** are what was discovered and submitted.
- **projects** are what Snyk created — one per manifest it found. One repository
  routinely produces several projects, and a repository with no supported
  manifests produces none. `0 project(s) created` is a normal, successful result
  for such a repository, not a failure.

## Commands

### `auth`

Manages locally stored credentials.

| Command | Description |
|---|---|
| `auth login` | Asks for the Snyk region, the Snyk API token (verified before continuing), which source you import from, and that source's credential. Requires an interactive terminal. |
| `auth status` | Shows the configuration file path, which credentials are set, and the configured region. Token values are never printed. |
| `auth logout` | Removes stored credentials. |

`auth login` prompts for one source's token rather than all of them, so you
only paste the credential you actually need:

```text
Which Snyk region is your account on?
  [1] snyk-us-01  (default, current)
  [2] snyk-us-02
  [3] snyk-eu-01
  [4] snyk-au-01
Pick one (1-4 or name) [blank keeps snyk-us-01]:

Snyk API token: ***
  Checking token... ✓ valid (6 organizations visible)

Which source will you import from?
  [1] github
  [2] github-cloud-app
  [3] github-enterprise  (needs --source-url)
  [4] gitlab
  [5] azure-repos
  [6] bitbucket-server  (needs --source-url)
  [7] bitbucket-cloud
  [8] bitbucket-connect-app
Pick one (1-8 or name): 4

Checking gitlab is configured in Snyk...
  ✓ configured in 4 organization(s): Acme Corp, Acme Labs, demo, sandbox

GitLab token: ***

Checking gitlab credentials...
  ✓ authenticated as gl-user

✓ Region set to snyk-eu-01.
✓ Stored 2 credential(s), chmod 600:
    /path/to/snyk-autoimport/.snyk-autoimport.json
    Environment variables override this file, so CI never needs it.
```

Three checks run against live APIs before the command finishes, so a problem
surfaces here rather than part-way through an import:

1. **The Snyk token** — verified against the chosen region.
2. **The integration** — the selected source must be configured on at least one
   organization the token can see. Connecting an integration is a Snyk-side
   action in the web UI, so if none is found the command stops and says so,
   rather than collecting a credential that cannot be used. The organizations
   that *do* have it are listed, which is also the answer to "where can I
   import this from".
3. **The source credential** — verified against the provider.

The region is asked first because the Snyk token is verified against that
region's API — a token valid in SNYK-EU-01 returns `401` against the US host,
so asking afterwards would make a correct token look broken.

Three sources report `– not checked` instead of a result, and say why:
`github-enterprise` and `bitbucket-server` need a host that is only supplied at
import time via `--source-url`, and an Azure PAT scoped to Code alone is
rejected by every account-level endpoint, so a check would prove nothing either
way.

Select the source by number or by its exact `--source` name; anything else is
rejected and re-prompted. Typed tokens are masked, and a prompt left blank keeps
whatever is already stored, so you can re-run the command to change one value.
Run it again to add a second source's token.

Selecting either Bitbucket Cloud source asks for two values rather than one,
because Bitbucket authenticates over HTTP Basic — see
[Bitbucket Cloud authentication](#bitbucket-cloud-authentication).

### `integrations`

Lists the SCM integrations configured on a Snyk organization, with the
corresponding `--source` value for each. Use this to confirm the correct
`--source` before importing.

```bash
node dist/cli.js integrations --snyk-org "Acme Corp"
```

| Flag | Description |
|---|---|
| `--snyk-org` | Snyk organization name or slug. |
| `--snyk-org-id` | Snyk organization UUID. |
| `--region` | Snyk region — see [Regions](#regions). Defaults to `snyk-us-01`. |

### `import`

Discovers repositories in the specified source organization, removes those
already imported, submits the remainder, and prints a summary.

| Flag | Description |
|---|---|
| `--snyk-org` | Snyk organization name or slug. An ambiguous name fails rather than resolving to an arbitrary match. |
| `--snyk-org-id` | Snyk organization UUID. Skips name resolution; recommended for automation. |
| `--source` | **Required.** SCM source type — see [Supported sources](#supported-sources). Never inferred, because one organization may have several integrations of the same family configured. |
| `--source-org` | The organization, group, project, or workspace to import from. `--github-org` is accepted as an alias. |
| `--source-url` | Host URL for self-hosted providers. Required for `github-enterprise` and `bitbucket-server`; optional override for other providers. |
| `--region` | Snyk region — see [Regions](#regions). Overrides the stored region. |
| `--dry-run` | Show the repositories that would be imported and exit without making changes. |
| `--yes` | Skip the confirmation prompt. Required for non-interactive use. |

## Supported sources

Verification status is stated per source, because it is the most useful thing to
know before pointing this at a production organization. "Verified end to end"
means a real import against a live instance, not test coverage alone.

| `--source` | Discovery credential | `--source-url` | Verification status |
|---|---|---|---|
| `github-cloud-app` | `GITHUB_TOKEN` | Not required | Verified end to end |
| `github` | `GITHUB_TOKEN` | Not required | Verified end to end |
| `azure-repos` | `AZURE_TOKEN` | Optional (defaults to dev.azure.com) | Verified end to end |
| `github-enterprise` | `GITHUB_TOKEN` | **Required** | Implemented and unit-tested; not exercised against a live instance |
| `gitlab` | `GITLAB_TOKEN` | Optional (defaults to gitlab.com) | Implemented and unit-tested; not exercised against a live instance |
| `bitbucket-server` | `BITBUCKET_SERVER_TOKEN` | **Required** | Implemented and unit-tested; not exercised against a live instance |
| `bitbucket-cloud` | See [below](#bitbucket-cloud-authentication) | Not required | Implemented and unit-tested; not exercised against a live instance |
| `bitbucket-connect-app` | See [below](#bitbucket-cloud-authentication) | Not required | Deduplication verified live; discovery and import not yet verified |

### Provider-specific notes

- **`github-cloud-app`** — Works with a Snyk service account token. The Snyk
  GitHub App installation must be granted access to each repository you intend
  to import. Discovery uses your own token, which typically sees more
  repositories than the App was granted, so repositories it cannot see are
  discovered but fail with a `404` during import.
- **`github` and `github-enterprise`** — Require a **personal** Snyk API token.
  These integrations authenticate through a personal GitHub OAuth link, so a
  service account token returns `401` when starting an import.
- **`gitlab`** — `--source-org` is a GitLab group name, and may be a nested path
  such as `group/subgroup`.
- **`azure-repos`** — `--source-org` is the Azure DevOps organization.
  Repositories across every project in that organization are discovered
  automatically; you do not name projects individually.
- **`bitbucket-cloud` vs `bitbucket-connect-app`** — Both are Bitbucket Cloud
  and both take a workspace as `--source-org`; they differ only in how Snyk is
  connected. `bitbucket-connect-app` is Snyk's Connect App integration and is
  what a recently-connected Bitbucket Cloud organization will have; the older
  `bitbucket-cloud` is the username/app-password integration. Run
  `integrations` to see which one your organization has — passing the wrong one
  fails with "integration not configured".
- **`bitbucket-server`** — `--source-org` is the Bitbucket project **name**.
  Import targets carry no branch information, so the repository default branch
  is always used.
- **`github-server-app`** — Not supported. This integration's project origin has
  no verified deduplication mapping, so enabling it could silently skip or
  duplicate repositories. The CLI rejects it explicitly.
- Personal (non-organization) accounts are not supported on any provider.
  Discovery uses each provider's organization, group, or workspace API.

### Bitbucket Cloud authentication

Both Bitbucket Cloud sources (`bitbucket-cloud` and `bitbucket-connect-app`)
use the same credentials for repository discovery.

The usual choice is HTTP Basic auth, which `auth login` stores for you. It takes
two values — an identity and a secret — in either of these pairings:

| Identity | Secret |
|---|---|
| Atlassian account **email** | **API token** (Atlassian account settings → Security → API tokens) |
| Bitbucket **username** | **App password** (Personal settings → App passwords, scope `Repositories: Read`) |

Note the email pairs with an API token and the username pairs with an app
password; crossing them over fails. Either pairing is stored as
`BITBUCKET_CLOUD_USERNAME` and `BITBUCKET_CLOUD_PASSWORD`.

Two Bearer-token methods are also accepted, from environment variables only,
since they are short-lived or narrowly scoped and not worth persisting:

| Method | Environment variable |
|---|---|
| Workspace / project / repository access token | `BITBUCKET_CLOUD_API_TOKEN` |
| OAuth access token | `BITBUCKET_CLOUD_OAUTH_TOKEN` |

Methods resolve in the order Basic → access token → OAuth. Set
`BITBUCKET_CLOUD_AUTH_METHOD` to `user`, `api`, or `oauth` to force one when
more than one is configured.

## Regions

If your Snyk account is not hosted on the default US instance, select the
matching region so requests reach the right API. Region names and hosts are
identical to the aliases accepted by `snyk config environment`, so a value that
works with the Snyk CLI works here too.

| `--region` | Snyk environment | API host |
|---|---|---|
| `snyk-us-01` (default) | SNYK-US-01 (US) | `https://api.snyk.io` |
| `snyk-us-02` | SNYK-US-02 (US) | `https://api.us.snyk.io` |
| `snyk-eu-01` | SNYK-EU-01 (Frankfurt) | `https://api.eu.snyk.io` |
| `snyk-au-01` | SNYK-AU-01 (Australia) | `https://api.au.snyk.io` |

Names are case-insensitive, so the uppercase spelling used in the Snyk
documentation can be pasted in directly:

```bash
node dist/cli.js import --region SNYK-EU-01 ...
```

Set the region once through `auth login` to store it, or pass `--region` per
command to override the stored value. `SNYK_API` set in the environment takes
precedence over both.

New Enterprise and Pilot accounts provisioned in the US through automated
provisioning are hosted on **SNYK-US-02**, not `snyk-us-01`. If you are unsure
which instance you are on, check the host in your Snyk web UI URL.

SNYK-GOV-01 (Snyk for Government) is not supported: it does not accept API
keys, and this tool authenticates with a `SNYK_TOKEN` API key.

See
[Regional hosting and data residency](https://docs.snyk.io/snyk-data-and-governance/regional-hosting-and-data-residency)
for the full list of regional URLs.

## Credentials and configuration

Credentials entered through `auth login` are written to `.snyk-autoimport.json`
with `0600` permissions. The path is the same on macOS, Linux, and Windows, so
it is predictable across customer environments. Run `auth status` to print it.

The location is resolved from the **installed package directory**, not the
current working directory, so logging in once holds wherever you run the command
from. One consequence worth knowing: a second checkout of this repository — a
`git worktree`, or a separate clone — is a separate package directory and needs
its own login.

> [!WARNING]
> This file holds live Snyk and SCM tokens inside a git working tree. It is
> listed in `.gitignore`, and that entry is load-bearing — do not remove it, and
> do not `git add -f` the file. If you fork or copy this repository, confirm the
> entry survived.

Environment variables always take precedence over stored credentials, so
automated environments can supply secrets without running `auth login` and
without writing a token to disk at all. This is the recommended approach for CI
and shared machines.

Releases before this change stored credentials in a per-user OS directory
(`~/Library/Preferences/` on macOS, `~/.config/` on Linux). That file is still
read if the package-directory one is absent, so an existing install keeps
working. Nothing is copied automatically; `auth status` reports when the old
location is in use, and the next `auth login` writes to the new path — delete
the old file afterwards.

## Continuous integration

Pass credentials through the environment, target the organization by UUID, and
skip the confirmation prompt:

```bash
SNYK_TOKEN="$SNYK_TOKEN" GITHUB_TOKEN="$GITHUB_TOKEN" \
  node dist/cli.js import \
    --snyk-org-id 00000000-0000-0000-0000-000000000000 \
    --source github-cloud-app \
    --source-org acme-corp \
    --yes
```

Because deduplication runs against live Snyk state on every execution, the
command is safe to run on a schedule to pick up newly created repositories.

Budget for wall-clock time rather than a fixed timeout: the run lasts as long as
Snyk takes to scan every submitted repository. `CONCURRENT_IMPORTS` (default
`15`) caps how many are submitted at once.

## How it works

1. **Resolve the organization.** `--snyk-org-id` is used directly. A name or
   slug is resolved against the organizations your token can see; ambiguous
   names fail rather than resolving arbitrarily, because Snyk organization names
   are not unique.
2. **Resolve the integration.** The `--source` value selects the integration
   configured on that organization.
3. **Discover repositories.** The provider's API is queried with your SCM token.
   Archived repositories, and repositories with no default branch, are excluded.
4. **Deduplicate.** Discovered repositories are compared against the projects
   already present in Snyk, and matches are removed. This runs against live Snyk
   state every time, never a cached list.
5. **Import and report.** The first repository is submitted alone as a canary,
   then the remainder. Each import job is polled to completion and the results
   are summarized, with provider-specific guidance for common failures such as
   `401` and `404` responses.

## Known limitations

- **Several providers are not fully verified against live instances** —
  `gitlab`, `bitbucket-server`, `bitbucket-cloud`, `bitbucket-connect-app`, and
  `github-enterprise`. They are implemented and covered by the maintainers'
  tests, but have not been exercised end to end against a real server. See
  [Supported sources](#supported-sources) for the status of each.
- **Repositories with no supported manifests** produce no Snyk project, so they
  are not recorded in the APIs used for deduplication and will be re-attempted
  on each run. This is harmless: re-importing an already-imported repository
  does not duplicate it, because Snyk deduplicates server-side.
- **A separate SCM token is always required.** Snyk's API does not return the
  credential stored on an SCM integration.
- **Imports are polled inline** with no overall timeout. There is no command to
  check the status of a previously started import, or to resume one.
- **Forked repositories are included** with no option to exclude them.
- **Not distributed through npm** or as a standalone binary.

## Development

```bash
npm run build   # compile TypeScript to dist/
npm run clean   # remove build output
```

All application code lives in `src/`, organized in two layers:

| Directory | Responsibility |
|---|---|
| `src/snyk/` | Everything the tool does against Snyk: submitting imports, polling jobs to completion, listing integrations, and the project lookup that backs deduplication. |
| `src/scm/` | Repository discovery, one module per provider, over each provider's public REST API. |
| `src/*.ts` | CLI, configuration, credential store, reporting, and the per-source adapters joining the two layers. |

Discovery uses the runtime's built-in `fetch`, so adding a provider costs no new
dependency. The maintainers' test suite is kept outside this repository, so
`npm run build` is the only step needed to produce a working command.

## License

Licensed under the Apache License 2.0.
