# PurpleChef

[![CI](https://github.com/scthornton/purplechef/actions/workflows/ci.yml/badge.svg)](https://github.com/scthornton/purplechef/actions/workflows/ci.yml)

**Purple team recipe platform — deploy, attack, detect, validate, report.**

## What is this?

PurpleChef is a structured automation framework for purple team exercises. You write declarative YAML "recipes" that describe an adversary technique, point Chef at your lab environment, and it handles the full lifecycle: spinning up infrastructure, executing the attack via Caldera, validating whether your detections fired in LimaCharlie, and producing an evidence-backed coverage report mapped to MITRE ATT&CK. If a technique was missed, Chef drafts a Sigma rule so you leave every exercise with better coverage than you started.


## Architecture

```
                         ┌──────────────────────────────┐
                         │         chef  CLI             │
                         │  recipe run | list | lint     │
                         │  detect generate              │
                         │  harden translate              │
                         └──────────┬───────────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                      │
    ┌─────────▼──────────┐ ┌───────▼─────────┐ ┌─────────▼──────────┐
    │   Recipe Book      │ │  Detection      │ │  Hardening         │
    │   (Phase 1)        │ │  Kitchen        │ │  Kitchen           │
    │                    │ │  (Phase 2)      │ │  (Phase 3)         │
    │  Orchestrator      │ │                 │ │                    │
    │  Recipe Loader     │ │  Sigma gen      │ │  Ansible → Chef    │
    │  YAML Recipes      │ │  Rule validate  │ │  InSpec profiles   │
    └─────────┬──────────┘ └─────────────────┘ └────────────────────┘
              │
    ┌─────────▼──────────────────────────────────────────────────────┐
    │                        Pantry  (shared library)                │
    │                                                                │
    │  Caldera Client  ·  LimaCharlie Client  ·  MITRE Resolver     │
    │  Pydantic Models ·  Audit Logger        ·  Config / .env      │
    └────────────────────────────────────────────────────────────────┘
```

The **Recipe Book** is the execution engine. The **Detection Kitchen** and **Hardening Kitchen** are planned extensions. The **Pantry** holds shared clients, models, and utilities that all kitchens depend on.


## Quick Start

**Prerequisites:** Python 3.12+, [uv](https://docs.astral.sh/uv/), a running Caldera server, and a LimaCharlie organization.

```bash
# Clone and install
git clone https://github.com/scthornton/purplechef.git
cd purplechef
uv sync

# Configure credentials
cp .env.example .env
# Edit .env with your Caldera API key, LimaCharlie OID, etc.

# List available recipes
chef recipe list recipe_book/src/chef_recipes/recipes/

# Validate a recipe before running
chef recipe lint recipe_book/src/chef_recipes/recipes/credential-access/recipe.yml

# Dry-run (default — no attacks execute)
chef recipe run recipe_book/src/chef_recipes/recipes/credential-access/recipe.yml

# Live execution (attacks WILL fire)
chef recipe run --live recipe_book/src/chef_recipes/recipes/credential-access/recipe.yml
```

Dry-run mode is on by default. Nothing touches your lab until you pass `--live`.


## The Recipe Format

Recipes are declarative YAML files that describe a complete purple team exercise. Each recipe lives in its own directory alongside any Sigma rules it references.

```yaml
name: lsass-memory-dump                     # Unique, hyphenated identifier
version: "1.0"
description: >
  Emulate OS credential dumping via LSASS     # What are we testing?
  memory access (T1003.001).

metadata:
  author: scott-thornton
  mitre_techniques:                           # ATT&CK technique IDs
    - T1003.001
  mitre_tactics:
    - credential-access
  difficulty: beginner                        # beginner | intermediate | advanced
  estimated_time: 15m

mise_en_place:                                # "Prep work" — infrastructure setup
  terraform_module: windows-target
  ansible_roles:
    - limacharlie-sensor
    - atomic-install

attack:                                       # How to execute the technique
  method: caldera                             # caldera | atomic | manual
  caldera:
    adversary_name: chef-lsass-dump
    abilities:
      - technique_id: T1003.001
        ability_id: auto                      # Auto-resolve from MITRE mapping
    group: chef-targets
    timeout: 300

validate:                                     # Did our detections catch it?
  detection_source: limacharlie
  wait_seconds: 120
  expected_rules:
    - name: LSASS Access
      tags: [t1003]
  sigma_rules:
    - path: sigma-rules/lsass-access.yml

report:                                       # Output formats
  format: [json, html, navigator]

advise:                                       # Gap remediation
  generate_sigma: true                        # Draft a rule if technique missed
```


## Key Concepts

| Kitchen Term | Technical Meaning |
|---|---|
| **Recipe** | A YAML file defining one purple team exercise end-to-end |
| **Mise en Place** | Infrastructure prerequisites — Terraform modules, Ansible roles, pre-checks |
| **Recipe Book** | The orchestration engine that runs recipes through the attack-validate-report lifecycle |
| **Pantry** | Shared library of API clients (Caldera, LimaCharlie), Pydantic models, and utilities |
| **Detection Kitchen** | (Phase 2) Sigma rule generation and validation tooling |
| **Hardening Kitchen** | (Phase 3) Ansible-to-Chef/InSpec translation for configuration hardening |
| **Evidence Chain** | Structured proof linking an emulated technique to the detections it triggered |
| **Coverage Result** | Aggregate report showing which techniques were detected vs. missed |
| **Dry Run** | Default safety mode — walks through the recipe without executing attacks |


## CLI Reference

```
chef recipe run <path>         Run a recipe through the full lifecycle
    --live                     Disable dry-run safety (execute for real)
    -o, --output <dir>         Output directory for reports (default: ./reports)

chef recipe list [directory]   List all recipes found in a directory

chef recipe lint <path>        Validate a recipe against the schema
                               Checks YAML syntax, technique IDs, attack spec
                               consistency, and Sigma rule file existence

chef detect generate <tid>     Generate a Sigma rule for a technique (Phase 2)

chef harden translate <path>   Translate an Ansible role to Chef + InSpec (Phase 3)
```

The orchestrator runs each recipe through a state machine:

```
LOAD → RESOLVE → EXECUTE → WAIT → VALIDATE → REPORT → DONE
```

**RESOLVE** maps ATT&CK technique IDs to Caldera abilities. **EXECUTE** runs the adversary operation. **WAIT** pauses for telemetry propagation. **VALIDATE** queries LimaCharlie for matching detections. **REPORT** calculates coverage and writes the evidence chain to disk.


## Project Structure

```
purplechef/
├── cli/                          # Click CLI — the `chef` command
│   └── src/chef_cli/main.py
├── recipe_book/                  # Phase 1 — orchestration engine
│   └── src/chef_recipes/
│       ├── orchestrator.py       # State machine (LOAD → DONE)
│       ├── recipe_loader.py      # YAML parsing and discovery
│       └── recipes/
│           ├── _template.yml     # Starting point for new recipes
│           └── credential-access/
│               ├── recipe.yml
│               └── sigma-rules/
├── detection_kitchen/            # Phase 2 — Sigma generation (planned)
│   └── src/chef_detection/
├── hardening_kitchen/            # Phase 3 — config hardening (planned)
│   └── src/chef_hardening/
├── pantry/                       # Shared library
│   └── src/chef_pantry/
│       ├── clients/              # Caldera + LimaCharlie API clients
│       ├── models/               # Pydantic models (Recipe, Evidence, Technique)
│       ├── mitre/                # ATT&CK resolver
│       ├── audit.py              # JSONL audit logger
│       ├── config.py             # Settings from .env
│       └── errors.py
├── infrastructure/               # Terraform + Ansible for lab setup
├── tests/                        # pytest + respx async tests
├── docs/
├── pyproject.toml                # uv workspace root
└── .env.example                  # Configuration template
```


## Roadmap

| Phase | Name | Status | Description |
|---|---|---|---|
| 1 | Recipe Book | Active | Orchestrator, recipe format, Caldera + LimaCharlie integration, evidence chains, coverage reports |
| 2 | Detection Kitchen | Planned | Sigma rule generation from missed techniques, rule validation against telemetry, LLM-assisted rule drafting |
| 3 | Hardening Kitchen | Planned | Translate Ansible hardening roles to Chef recipes + InSpec compliance profiles |


## Contributing a Recipe

1. Copy the template:
   ```bash
   cp recipe_book/src/chef_recipes/recipes/_template.yml \
      recipe_book/src/chef_recipes/recipes/your-technique/recipe.yml
   ```

2. Fill in the YAML fields. The template is fully annotated — every field has a comment explaining what it expects.

3. Add any Sigma rules to a `sigma-rules/` subdirectory alongside your recipe.

4. Validate:
   ```bash
   chef recipe lint recipe_book/src/chef_recipes/recipes/your-technique/recipe.yml
   ```

5. Open a PR. The linter checks YAML syntax, technique ID format, attack spec consistency, and Sigma rule file existence.


## Built With

- **Python 3.12** — async throughout, type-annotated
- **Pydantic v2** — schema validation for recipes and evidence models
- **Click + Rich** — CLI framework with formatted terminal output
- **HTTPX** — async HTTP client for Caldera and LimaCharlie APIs
- **uv** — fast workspace-aware dependency management
- **pytest + respx** — async test suite with HTTP mocking
- **Ruff** — linting and formatting


## License

MIT License. See [LICENSE](LICENSE) for details.


## Acknowledgments

- [SANS SEC598](https://www.sans.org/cyber-security-courses/security-automation-with-ai/) — the course that inspired this framework
- [MITRE ATT&CK](https://attack.mitre.org/) — technique taxonomy and coverage mapping
- [Caldera](https://caldera.mitre.org/) — adversary emulation platform
- [LimaCharlie](https://limacharlie.io/) — endpoint detection and response
- [Sigma](https://sigmahq.io/) — open detection rule format
