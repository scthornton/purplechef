# Getting Started

This guide walks you through running your first SEC598 Chef recipe.

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- Access to a Caldera server (SEC598 lab or standalone)
- LimaCharlie organization (free tier works)

## Installation

```bash
git clone https://github.com/scthornton/sec598-chef.git
cd sec598-chef
uv sync --all-packages
```

## Configuration

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

| Variable | Where to find it |
|----------|-----------------|
| `CHEF_CALDERA_URL` | Your Caldera server URL (e.g., `http://192.168.20.10:8888`) |
| `CHEF_CALDERA_API_KEY` | Caldera UI > Settings > API Key |
| `CHEF_LC_OID` | LimaCharlie > Organization > Settings > OID |
| `CHEF_LC_API_KEY` | LimaCharlie > Organization > REST API > Create Key |

## Your First Recipe

### 1. Lint the recipe

```bash
uv run chef recipe lint recipe_book/src/chef_recipes/recipes/credential-access/recipe.yml
```

This validates the YAML structure, checks MITRE technique IDs, and verifies Sigma rules exist.

### 2. Dry-run (default)

```bash
uv run chef recipe run recipe_book/src/chef_recipes/recipes/credential-access/recipe.yml
```

In dry-run mode, the orchestrator walks through all phases but stops before executing attacks. This lets you verify configuration without risk.

### 3. Live execution

```bash
uv run chef recipe run --live recipe_book/src/chef_recipes/recipes/credential-access/recipe.yml
```

This executes the full purple team cycle:
1. Resolves MITRE techniques to Caldera abilities
2. Creates an adversary and runs an operation
3. Waits for telemetry propagation
4. Queries LimaCharlie for matching detections
5. Produces a coverage report with evidence chains

### 4. View results

Reports are saved to `reports/` by default:

```bash
cat reports/lsass-memory-dump_*.json | python -m json.tool
```

## Writing Your Own Recipe

Copy the template:

```bash
cp -r recipe_book/src/chef_recipes/recipes/_template.yml \
      recipe_book/src/chef_recipes/recipes/my-technique/recipe.yml
```

Edit the recipe, then lint:

```bash
uv run chef recipe lint recipe_book/src/chef_recipes/recipes/my-technique/recipe.yml
```

See the [recipe template](../recipe_book/src/chef_recipes/recipes/_template.yml) for field-by-field documentation.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Recipe file not found" | Pass the full path to `recipe.yml`, not the directory |
| "Group not in allowlist" | Add the Caldera agent group to `CHEF_CALDERA_ALLOWED_GROUPS` in `.env` |
| "DryRunBlocked" | This is expected in dry-run mode. Use `--live` to execute |
| "CalderaError: 401" | Check your `CHEF_CALDERA_API_KEY` |
| "No Caldera abilities resolved" | Your Caldera server may not have the technique. The recipe will note this. |
