# snyk-autoimport

Bulk-import repositories from your source control management (SCM) provider into
a Snyk organization with a single command.

`snyk-autoimport` is a command-line wrapper around
[`snyk-api-import`](https://github.com/snyk/snyk-api-import). It resolves your
Snyk organization and SCM integration, discovers repositories, skips anything
already imported, submits the import, and reports the outcome — replacing the
hand-authored JSON files and log-file inspection the underlying tool requires.

> **Support notice**
>
> This is an independent, community project. It is **not** an official Snyk
> product and is not covered by Snyk support or any Snyk service agreement.
> It is provided as-is for evaluation and internal automation use.
>
> The project currently builds on `snyk-api-import`, which Snyk has placed in
> maintenance mode and plans to replace. `snyk-autoimport` isolates that
> dependency behind a single internal module, so the command-line interface and
> stored credentials are expected to remain stable if the underlying engine
> changes.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
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
| Node.js | 20 or later |
| npm registry access | Required during installation. Dependencies, including `snyk-api-import`, are downloaded from the public npm registry. |
| Snyk API token | Required. Token type depends on the integration — see [Supported sources](#supported-sources). |
| SCM access token | Required. Snyk cannot expose the credential stored on an SCM integration, so repository discovery needs its own token. |
| Configured Snyk integration | The target Snyk organization must already have the relevant SCM integration configured. |

## Installation

This project is not published to npm, so clone the repository and build it
locally. You do **not** need to install `snyk-api-import` separately — it is a
normal dependency and `npm install` fetches it automatically.

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

## Commands

### `auth`

Manages locally stored credentials.

| Command | Description |
|---|---|
| `auth login` | Asks for the Snyk API token, which source you import from, that source's token, and the Snyk region. Requires an interactive terminal. |
| `auth status` | Shows the configuration file path, which credentials are set, and the configured region. Token values are never printed. |
| `auth logout` | Removes stored credentials. |

`auth login` prompts for one source's token rather than all of them, so you
only paste the credential you actually need:

```text
Snyk API token: ***

Which source will you import from?
  [1] github
  [2] github-cloud-app
  [3] github-enterprise  (needs --source-url)
  [4] gitlab
  [5] azure-repos
  [6] bitbucket-server  (needs --source-url)
  [7] bitbucket-cloud
Pick one (1-7 or name): 4

GitLab token: ***
```

Select the source by number or by its exact `--source` name; anything else is
rejected and re-prompted. Typed tokens are masked, and a prompt left blank keeps
whatever is already stored, so you can re-run the command to change one value.
Run it again to add a second source's token.

Selecting `bitbucket-cloud` stores nothing, because its three authentication
methods are read from environment variables — see
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

| `--source` | Discovery credential | `--source-url` | Verification status |
|---|---|---|---|
| `github-cloud-app` | `GITHUB_TOKEN` | Not required | Verified end to end |
| `github` | `GITHUB_TOKEN` | Not required | Verified end to end |
| `github-enterprise` | `GITHUB_TOKEN` | **Required** | Implemented, not yet verified live |
| `gitlab` | `GITLAB_TOKEN` | Optional (defaults to gitlab.com) | Implemented, not yet verified live |
| `azure-repos` | `AZURE_TOKEN` | Optional (defaults to dev.azure.com) | Implemented, not yet verified live |
| `bitbucket-server` | `BITBUCKET_SERVER_TOKEN` | **Required** | Implemented, not yet verified live |
| `bitbucket-cloud` | See [below](#bitbucket-cloud-authentication) | Not required | Implemented, not yet verified live |

### Provider-specific notes

- **`github-cloud-app`** — Works with a Snyk service account token. The Snyk
  GitHub App installation must be granted access to each repository you intend
  to import; repositories it cannot see fail with a `404` during import.
- **`github` and `github-enterprise`** — Require a **personal** Snyk API token.
  These integrations authenticate through a personal GitHub OAuth link, so a
  service account token returns `401` when starting an import.
- **`gitlab`** — `--source-org` is a GitLab group name.
- **`azure-repos`** — Repositories across every project in the organization are
  discovered automatically.
- **`bitbucket-server`** — Import targets carry no branch information, so the
  repository default branch is always used.
- **`github-server-app`** — Not supported. `snyk-api-import` provides no
  deduplication support for this integration's project origin, so enabling it
  could produce duplicate imports. The CLI rejects it explicitly.
- Personal (non-organization) GitHub accounts are not supported. Discovery uses
  each provider's organization or group API.

### Bitbucket Cloud authentication

Bitbucket Cloud supports three authentication methods, so it is configured
through environment variables rather than `auth login`:

| Method | Environment variables |
|---|---|
| Username and app password | `BITBUCKET_CLOUD_USERNAME`, `BITBUCKET_CLOUD_PASSWORD` |
| API token | `BITBUCKET_CLOUD_API_TOKEN` |
| OAuth token | `BITBUCKET_CLOUD_OAUTH_TOKEN` |

Methods are resolved in the order listed above. Set
`BITBUCKET_CLOUD_AUTH_METHOD` to `user`, `api`, or `oauth` to force a specific
method when more than one is configured.

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

Credentials entered through `auth login` are written to
`.snyk-autoimport.json` in the project root with `0600` permissions. The path
is the same on macOS, Linux, and Windows, so it is predictable across customer
environments. Run `auth status` to print it.

The location is resolved from the installed package, not the current working
directory, so logging in once holds wherever you run the command from.

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
read if the project-root one is absent, so an existing install keeps working.
Nothing is copied automatically; `auth status` reports when the old location is
in use, and the next `auth login` writes to the new path — delete the old file
afterwards.

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

## How it works

1. **Resolve the organization.** `--snyk-org-id` is used directly. A name or
   slug is resolved against the organizations your token can see; ambiguous
   names fail rather than resolving arbitrarily.
2. **Resolve the integration.** The `--source` value selects the integration
   configured on that organization.
3. **Discover repositories.** The provider's API is queried with your SCM token.
   Archived repositories are excluded.
4. **Deduplicate.** Discovered repositories are compared against projects
   already present in Snyk, and matches are removed.
5. **Import and report.** Remaining repositories are submitted in batches and
   polled to completion, then summarized with provider-specific guidance for
   common failures such as `401` and `404` responses.

## Known limitations

- **Repositories with no supported manifests.** These produce no Snyk project,
  so they are not recorded in the APIs used for deduplication and will be
  re-attempted on each run. This is harmless and never creates duplicates.
- **A separate SCM token is always required.** Snyk's API does not return the
  credential stored on an SCM integration.
- **Systemic failures can terminate the process early.** `snyk-api-import`
  calls `process.exit(1)` after roughly 30 consecutive failed submissions,
  which prevents the summary from printing. To limit the impact, the first
  repository is imported alone as a canary, so configuration problems that
  affect every repository surface on the first failure. A failure pattern
  spread thinly across a very large batch can still reach the threshold.
- **Imports are polled inline** with no overall timeout. There is no command to
  check the status of a previously started import.
- **Only GitHub sources are verified end to end.** Other providers are
  implemented and covered by the maintainers' tests but have not been exercised
  against live instances.
- **Not distributed through npm** or as a standalone binary.

## Development

```bash
npm run build   # compile TypeScript to dist/
npm run clean   # remove build output
```

All application code lives in `src/`. The maintainers' test suite is kept
outside this repository, so `npm run build` is the only step needed to produce a
working command.

## License

Licensed under the Apache License 2.0.
