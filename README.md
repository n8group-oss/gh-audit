# gh-audit

**GitHub audit, governance, and inventory for organizations.**

gh-audit produces a comprehensive inventory of your GitHub organization --
repositories, members, Actions workflows, security posture, packages, and
projects -- and generates JSON, HTML, and Excel reports. It supports standard
(fast) and deep (thorough) scan profiles, multi-organization scanning via YAML
config, and both PAT and GitHub App authentication.

A free tool by [N8 Group](https://n8-group.com) -- DevOps Transformation.
Executed with Precision.

## Installation

### pip (Python 3.11+)

```bash
pip install gh-audit
gh-audit --version
```

### Homebrew (macOS / Linux)

```bash
brew tap n8group-oss/tap
brew install gh-audit
```

### Chocolatey (Windows)

```powershell
choco install gh-audit
```

New Chocolatey packages can take time to appear publicly while community
moderation completes. If `gh-audit` is not visible yet, download the `.nupkg`
asset from [GitHub Releases](https://github.com/n8group-oss/gh-audit/releases)
and install it from the folder where you saved it:

```powershell
choco install gh-audit --source="'C:\path\to\package-folder'"
```

### Direct download

Download standalone binaries, checksums, and release artifacts from
[GitHub Releases](https://github.com/n8group-oss/gh-audit/releases).
Standalone executables are available for Linux (amd64), macOS (amd64, arm64),
and Windows (amd64).

## Quick Start

### Single organization (PAT)

```bash
gh-audit discover --organization myorg --token ghp_xxxxx
```

### Single organization (GitHub App -- recommended)

```bash
gh-audit discover \
  --organization myorg \
  --app-id 12345 \
  --private-key-path /path/to/key.pem \
  --installation-id 67890
```

### Multi-organization (config file)

```bash
gh-audit discover --config gh-audit.yml --output-dir ./results
```

See [examples/gh-audit.yml](examples/gh-audit.yml) for the config format.

### Interactive setup

```bash
gh-audit init
```

Creates a `.env` file with your credentials. Then run:

```bash
gh-audit discover
```

## Scan Profiles

| Profile | Default | What it does |
|---------|---------|-------------|
| `standard` | Yes | Repository metadata, PR/issue/branch counts, workflow listing, security feature status, users, packages, projects |
| `deep` | No | Everything in standard + recursive tree walk (large file detection), workflow YAML parsing (action usage, self-hosted runners), exact security alert counts |

```bash
gh-audit discover --organization myorg --token ghp_xxx --scan-profile deep
```

Individual deep features can be toggled independently:

```bash
gh-audit discover --organization myorg --token ghp_xxx \
  --scan-large-files \
  --scan-workflow-contents \
  --security-alert-counts
```

## Output

Every scan produces three artifacts:

| Format | File | Purpose |
|--------|------|---------|
| JSON | `{org}-inventory.json` | Machine-readable inventory |
| HTML | `{org}-report.html` | Self-contained visual report (offline, no CDN) |
| Excel | `{org}-inventory.xlsx` | 10-sheet workbook for analysis and sharing |

Regenerate reports from an existing inventory:

```bash
gh-audit report --inventory myorg-inventory.json
```

## Authentication

### Personal Access Token (PAT)

Required scopes (classic): `repo`, `read:org`, `read:packages`, `read:project`, `security_events`

Set via CLI flag, environment variable, or `.env` file:

```bash
export GH_AUDIT_TOKEN=ghp_xxxxx
export GH_AUDIT_ORGANIZATION=myorg
```

### GitHub App (recommended)

Better rate limits (15,000 req/hr vs 5,000) and org-level permissions.

Required permissions: Repository metadata (read), Organization members (read),
Actions (read), Packages (read), Security events (read).

```bash
export GH_AUDIT_APP_ID=12345
export GH_AUDIT_PRIVATE_KEY_PATH=/path/to/key.pem
export GH_AUDIT_INSTALLATION_ID=67890
export GH_AUDIT_ORGANIZATION=myorg
```

### GitHub Enterprise Server

```bash
export GH_AUDIT_API_URL=https://github.mycompany.com/api/v3
```

## Multi-Organization Config

Scan multiple organizations with different credentials in one run:

```yaml
defaults:
  scan_profile: standard
  concurrency: 8

organizations:
  - name: org-one
    token: ${GH_TOKEN_ORG_ONE}

  - name: org-two
    app_id: 12345
    private_key_path: /path/to/key.pem
    installation_id: 67890
    scan_profile: deep
```

```bash
gh-audit discover --config gh-audit.yml --output-dir ./results
```

Each organization gets its own output directory. A cross-org summary
(`summary.json` + `summary.html`) is generated at the root.

## License

[Business Source License 1.1](LICENSE) -- free to use for internal purposes.
See LICENSE for full terms.

## Contact

**N8 Group** -- European leader in AI-powered DevOps solutions.

- Web: [n8-group.com](https://n8-group.com)
- Email: [sales@n8-group.com](mailto:sales@n8-group.com)
- LinkedIn: [N8 Group](https://www.linkedin.com/company/n8-group/)
- Phone: +48 12 300 25 80
