"""PurpleChef — unified CLI for purple team automation.

Usage:
    chef recipe run <path>      Run a purple team recipe
    chef recipe list [dir]      List available recipes
    chef recipe lint <path>     Validate a recipe file
    chef recipe report <dir>    Generate aggregate coverage report
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

console = Console()

BANNER = r"""[cyan]
  ____              _       ____ _          __
 |  _ \ _   _ _ __ | |__   / ___| |__   ___/ _|
 | |_) | | | | '_ \| '_ \ | |   | '_ \ / _ \ |_
 |  __/| |_| | |  | | | | | |___| | | |  __/  _|
 |_|    \__,_|_|  |_|_| |_|\____|_| |_|\___|_|
[/cyan][dim]  Purple Team Recipe Platform[/dim]
"""


@click.group()
@click.version_option(version="0.1.0", prog_name="purplechef")
def cli() -> None:
    """PurpleChef — deploy, attack, detect, validate, report."""
    pass


@cli.group()
def recipe() -> None:
    """Manage and execute purple team recipes."""
    pass


@recipe.command("run")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--live", is_flag=True, help="Disable dry-run safety (execute for real)")
@click.option(
    "--output", "-o", type=click.Path(path_type=Path), default=None, help="Output directory"
)
def recipe_run(path: Path, live: bool, output: Path | None) -> None:
    """Run a purple team recipe end-to-end."""
    console.print(BANNER)
    asyncio.run(_run_recipe(path, dry_run=not live, output_dir=output))


async def _run_recipe(path: Path, *, dry_run: bool, output_dir: Path | None) -> None:
    from chef_pantry.audit import AuditLogger
    from chef_pantry.clients.caldera import CalderaClient
    from chef_pantry.clients.limacharlie import LimaCharlieClient
    from chef_pantry.config import get_settings
    from chef_pantry.mitre.resolver import MitreResolver
    from chef_recipes.orchestrator import RecipeOrchestrator
    from chef_recipes.recipe_loader import load_recipe

    settings = get_settings()
    effective_dry_run = dry_run or settings.safety.dry_run

    if effective_dry_run:
        console.print(
            "[yellow]🔒 Dry-run mode[/] — no attacks will execute. Use --live to run for real.\n"
        )
    else:
        console.print("[red]⚡ LIVE mode[/] — attacks WILL execute against targets.\n")

    recipe_model = load_recipe(path)

    audit = AuditLogger(settings.safety.audit_log)
    async with (
        CalderaClient(
            base_url=settings.caldera.url,
            api_key=settings.caldera.api_key,
            allowed_groups=settings.caldera.allowed_groups,
            dry_run=effective_dry_run,
            audit_logger=audit,
        ) as caldera,
        LimaCharlieClient(
            oid=settings.limacharlie.oid,
            api_key=settings.limacharlie.api_key,
            audit_logger=audit,
        ) as lc,
    ):
        resolver = MitreResolver(caldera_client=caldera)
        orchestrator = RecipeOrchestrator(
            caldera=caldera, limacharlie=lc, resolver=resolver, audit=audit
        )
        result = await orchestrator.run(recipe_model)

    # Write results using recipe's report spec
    out = output_dir or Path("reports")
    out.mkdir(parents=True, exist_ok=True)

    from chef_detection.coverage_reporter import save_report

    formats = recipe_model.report.format
    saved = save_report(result, out, formats)
    for p in saved:
        console.print(f"[green]📄 Report saved:[/] {p}")
    audit.close()


@recipe.command("list")
@click.argument("directory", type=click.Path(exists=True, path_type=Path), default=".")
def recipe_list(directory: Path) -> None:
    """List all recipes found in a directory."""
    from chef_recipes.recipe_loader import discover_recipes, load_recipe

    recipes = discover_recipes(directory)
    if not recipes:
        console.print("[yellow]No recipes found.[/]")
        return

    table = Table(title="Available Recipes", border_style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Techniques")
    table.add_column("Difficulty")
    table.add_column("Time")
    table.add_column("Path", style="dim")

    for path in recipes:
        try:
            r = load_recipe(path)
            table.add_row(
                r.name,
                ", ".join(r.metadata.mitre_techniques),
                r.metadata.difficulty,
                r.metadata.estimated_time,
                str(path.relative_to(directory)),
            )
        except Exception as exc:
            table.add_row("[red]ERROR[/]", str(exc)[:50], "", "", str(path))

    console.print(table)


@recipe.command("lint")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def recipe_lint(path: Path) -> None:
    """Validate a recipe file against the schema."""
    from chef_pantry.mitre.resolver import MitreResolver
    from chef_recipes.recipe_loader import load_recipe

    console.print(f"[bold]Linting:[/] {path}\n")
    issues: list[str] = []

    # Schema validation
    try:
        r = load_recipe(path)
        console.print("  [green]✓[/] YAML syntax valid")
        console.print("  [green]✓[/] Schema validation passed")
    except Exception as exc:
        console.print(f"  [red]✗[/] {exc}")
        sys.exit(1)
        return  # unreachable but appeases type checker

    # Technique ID validation
    for tid in r.metadata.mitre_techniques:
        if MitreResolver.validate_technique_id(tid):
            console.print(f"  [green]✓[/] {tid} — valid technique ID")
        else:
            issues.append(f"Invalid technique ID: {tid}")
            console.print(f"  [red]✗[/] {tid} — invalid technique ID format")

    # Attack spec consistency
    if r.attack.method == "caldera" and r.attack.caldera is None:
        issues.append("method is 'caldera' but no caldera spec provided")
        console.print("  [red]✗[/] Missing caldera attack specification")
    elif r.attack.method == "atomic" and r.attack.atomic is None:
        issues.append("method is 'atomic' but no atomic spec provided")
        console.print("  [red]✗[/] Missing atomic attack specification")
    else:
        console.print("  [green]✓[/] Attack spec consistent with method")

    # Sigma rule files exist
    for rule in r.validate_spec.sigma_rules:
        rule_path = path.parent / rule.get("path", "")
        if rule_path.exists():
            console.print(f"  [green]✓[/] Sigma rule exists: {rule_path.name}")
        else:
            issues.append(f"Sigma rule not found: {rule_path}")
            console.print(f"  [red]✗[/] Sigma rule missing: {rule_path}")

    if issues:
        console.print(f"\n[red]✗ {len(issues)} issue(s) found[/]")
        sys.exit(1)
    else:
        console.print("\n[green]✓ Recipe is valid[/]")


@cli.group()
def detect() -> None:
    """Detection Kitchen — generate, validate, and test detection rules."""
    pass


@detect.command("generate")
@click.argument("technique_id")
@click.option("--llm", is_flag=True, help="Use LLM if no deterministic template exists")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def detect_generate(technique_id: str, llm: bool, output: Path | None) -> None:
    """Generate a Sigma detection rule for a MITRE technique."""
    asyncio.run(_detect_generate(technique_id, use_llm=llm, output_path=output))


async def _detect_generate(technique_id: str, *, use_llm: bool, output_path: Path | None) -> None:
    from chef_detection.rule_generator import generate_rule
    from chef_detection.rule_validator import validate_sigma
    from chef_detection.sigma_templates import has_template, render_sigma_yaml

    console.print(f"\n[bold]Generating Sigma rule for[/] [cyan]{technique_id}[/]\n")

    llm_client = None
    if use_llm and not has_template(technique_id):
        from chef_pantry.clients.llm import LLMClient
        from chef_pantry.config import get_settings

        settings = get_settings()
        llm_client = LLMClient(
            base_url=settings.llm.base_url,
            api_key=settings.llm.api_key,
            model=settings.llm.model,
        )

    try:
        rule_dict, source = await generate_rule(technique_id, llm_client=llm_client)
    except ValueError as exc:
        console.print(f"[red]✗[/] {exc}")
        console.print("[dim]Tip: use --llm to generate via LLM when no template exists[/]")
        sys.exit(1)
        return
    finally:
        if llm_client:
            await llm_client.close()

    # Validate
    validation = validate_sigma(rule_dict)
    source_label = "[green]template[/]" if source == "template" else "[yellow]LLM draft[/]"
    console.print(f"  Source: {source_label}")

    if validation.is_valid:
        console.print("  [green]✓[/] Sigma validation passed")
    else:
        for err in validation.errors:
            console.print(f"  [red]✗[/] {err}")
    for warn in validation.warnings:
        console.print(f"  [yellow]⚠[/] {warn}")

    # Output
    yaml_str = render_sigma_yaml(rule_dict)
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(yaml_str, encoding="utf-8")
        console.print(f"\n[green]📄 Saved:[/] {output_path}")
    else:
        console.print("\n[bold]Generated rule:[/]")
        console.print(f"[dim]{'─' * 60}[/]")
        console.print(yaml_str)
        console.print(f"[dim]{'─' * 60}[/]")


@detect.command("validate")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def detect_validate(path: Path) -> None:
    """Validate a Sigma rule file."""
    from chef_detection.rule_validator import validate_sigma_yaml

    console.print(f"\n[bold]Validating:[/] {path}\n")
    yaml_str = path.read_text(encoding="utf-8")
    result = validate_sigma_yaml(yaml_str)

    if result.is_valid:
        console.print("  [green]✓[/] Sigma rule is valid")
    for err in result.errors:
        console.print(f"  [red]✗[/] {err}")
    for warn in result.warnings:
        console.print(f"  [yellow]⚠[/] {warn}")

    if not result.is_valid:
        sys.exit(1)


@detect.command("templates")
def detect_templates() -> None:
    """List available deterministic Sigma templates."""
    from chef_detection.sigma_templates import list_templates
    from chef_pantry.mitre.resolver import MitreResolver

    templates = list_templates()
    table = Table(title="Available Sigma Templates", border_style="cyan")
    table.add_column("Technique", style="bold")
    table.add_column("Name")
    table.add_column("Tactic", style="dim")

    for tid in templates:
        technique = MitreResolver.build_technique(tid)
        table.add_row(tid, technique.name, technique.tactic)

    console.print(table)
    console.print(
        f"\n[dim]{len(templates)} templates available. Use `chef detect generate <ID>` to render.[/]"
    )


@detect.command("test-data")
@click.argument("technique_id")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def detect_test_data(technique_id: str, output: Path | None) -> None:
    """Generate synthetic test events for a technique."""
    asyncio.run(_detect_test_data(technique_id, output_path=output))


async def _detect_test_data(technique_id: str, *, output_path: Path | None) -> None:
    from chef_detection.sigma_templates import get_template
    from chef_detection.test_data_generator import generate_test_data_deterministic, to_jsonl

    console.print(f"\n[bold]Generating test data for[/] [cyan]{technique_id}[/]\n")

    template_fn = get_template(technique_id)
    if template_fn is None:
        console.print(f"[yellow]⚠[/] No template for {technique_id} — generating minimal test data")
        rule_dict = {}
    else:
        rule_dict = template_fn(technique_id)

    test_data = generate_test_data_deterministic(technique_id, rule_dict)

    console.print(f"  Positive events: {len(test_data.positive_events)}")
    console.print(f"  Negative events: {len(test_data.negative_events)}")

    jsonl = to_jsonl(test_data)
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(jsonl, encoding="utf-8")
        console.print(f"\n[green]📄 Saved:[/] {output_path}")
    else:
        console.print("\n[bold]Test events:[/]")
        for line in jsonl.strip().split("\n")[:6]:
            console.print(f"  [dim]{line[:100]}{'...' if len(line) > 100 else ''}[/]")
        total = len(test_data.positive_events) + len(test_data.negative_events)
        if total > 6:
            console.print(f"  [dim]... and {total - 6} more[/]")


@detect.command("report")
@click.argument("results_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "-f", "fmt", multiple=True, default=["html", "navigator"])
def detect_report(results_dir: Path, fmt: tuple[str, ...]) -> None:
    """Generate coverage report from recipe run results."""
    import json as json_mod

    from chef_detection.coverage_reporter import save_report
    from chef_pantry.models.evidence import CoverageResult

    json_files = sorted(results_dir.glob("*.json"))
    if not json_files:
        console.print("[yellow]No JSON result files found.[/]")
        sys.exit(1)

    loaded = 0
    for jf in json_files:
        # Skip generated artifacts (navigator layers, non-coverage JSON)
        if jf.name.endswith("_navigator.json"):
            continue
        data = json_mod.loads(jf.read_text())
        # Only process files that look like CoverageResults
        if "evidence_chains" not in data:
            console.print(f"  [dim]Skipping non-coverage file: {jf.name}[/]")
            continue
        result = CoverageResult.model_validate(data)
        paths = save_report(result, results_dir, list(fmt))
        for p in paths:
            console.print(f"[green]📄 Generated:[/] {p}")
        loaded += 1

    if loaded == 0:
        console.print("[yellow]No coverage result files found (need evidence_chains field).[/]")
        sys.exit(1)


@detect.command("convert")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--to", "target", type=click.Choice(["kql", "splunk"]), required=True)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def detect_convert(path: Path, target: str, output: Path | None) -> None:
    """Convert a Sigma rule to KQL or Splunk SPL."""
    import yaml as yaml_mod
    from chef_detection.sigma_converter import convert_to_kql, convert_to_splunk

    rule = yaml_mod.safe_load(path.read_text(encoding="utf-8"))
    console.print(f"\n[bold]Converting[/] {path.name} → [cyan]{target.upper()}[/]\n")

    result = convert_to_kql(rule) if target == "kql" else convert_to_splunk(rule)

    for note in result.notes:
        console.print(f"  [yellow]⚠[/] {note}")

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result.query, encoding="utf-8")
        console.print(f"\n[green]📄 Saved:[/] {output}")
    else:
        console.print(f"\n[bold]{target.upper()} query:[/]")
        console.print(f"[dim]{'─' * 60}[/]")
        console.print(result.query)
        console.print(f"[dim]{'─' * 60}[/]")


# --- Recipe: init, diff, report-only ---


@recipe.command("init")
@click.argument("technique_id")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--method", type=click.Choice(["caldera", "atomic", "manual"]), default="caldera")
def recipe_init(technique_id: str, output: Path | None, method: str) -> None:
    """Scaffold a new recipe for a MITRE technique."""
    from chef_detection.sigma_templates import get_template, has_template, render_sigma_yaml
    from chef_pantry.mitre.resolver import MitreResolver

    if not MitreResolver.validate_technique_id(technique_id):
        console.print(f"[red]✗[/] Invalid technique ID: {technique_id}")
        sys.exit(1)

    technique = MitreResolver.build_technique(technique_id)
    safe_name = technique.name.lower().replace(" ", "-").replace("/", "-").replace(":", "")
    out_dir = output or Path(f"recipes/{safe_name}")
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"\n[bold]Scaffolding recipe for[/] [cyan]{technique_id}[/] ({technique.name})\n")

    # Generate recipe.yml
    recipe_data = {
        "name": safe_name,
        "version": "1.0",
        "description": f"Purple team exercise for {technique_id} ({technique.name}).",
        "metadata": {
            "author": "your-github-handle",
            "mitre_techniques": [technique_id],
            "mitre_tactics": [technique.tactic],
            "difficulty": "beginner",
            "estimated_time": "15m",
            "tags": [technique.tactic, "purple-team", "purplechef"],
        },
        "mise_en_place": {
            "terraform_module": "windows-target",
            "ansible_roles": ["limacharlie-sensor"],
        },
        "attack": {"method": method},
        "validate": {
            "detection_source": "limacharlie",
            "wait_seconds": 120,
        },
        "report": {"format": ["json", "html"]},
        "advise": {"generate_sigma": True},
    }

    if method == "caldera":
        recipe_data["attack"]["caldera"] = {
            "adversary_name": f"chef-{safe_name}",
            "abilities": [{"technique_id": technique_id, "ability_id": "auto"}],
            "group": "chef-targets",
            "timeout": 300,
        }
    elif method == "atomic":
        recipe_data["attack"]["atomic"] = {
            "technique_id": technique_id,
            "test_numbers": [1],
        }

    import yaml as yaml_mod

    recipe_path = out_dir / "recipe.yml"
    recipe_path.write_text(yaml_mod.dump(recipe_data, sort_keys=False, default_flow_style=False))
    console.print(f"  [green]✓[/] Created {recipe_path}")

    # Generate Sigma rule if template exists
    if has_template(technique_id):
        sigma_dir = out_dir / "sigma-rules"
        sigma_dir.mkdir(exist_ok=True)
        template_fn = get_template(technique_id)
        rule_dict = template_fn(technique_id)
        sigma_path = sigma_dir / f"{safe_name}.yml"
        sigma_path.write_text(render_sigma_yaml(rule_dict))
        console.print(f"  [green]✓[/] Created {sigma_path} (from template)")

        # Update recipe to reference the sigma rule
        recipe_data["validate"]["sigma_rules"] = [{"path": f"sigma-rules/{safe_name}.yml"}]
        recipe_data["validate"]["expected_rules"] = [{"name": rule_dict.get("title", safe_name)}]
        recipe_path.write_text(
            yaml_mod.dump(recipe_data, sort_keys=False, default_flow_style=False)
        )
    else:
        console.print(f"  [dim]No Sigma template for {technique_id} — add one manually[/]")

    console.print(f"\n[green]Recipe scaffolded at[/] {out_dir}")
    console.print("[dim]Edit recipe.yml, then run: chef recipe lint " + str(recipe_path) + "[/]")


@recipe.command("diff")
@click.argument("run_a", type=click.Path(exists=True, path_type=Path))
@click.argument("run_b", type=click.Path(exists=True, path_type=Path))
def recipe_diff(run_a: Path, run_b: Path) -> None:
    """Compare two recipe run results and show coverage delta."""
    import json as json_mod

    from chef_pantry.models.evidence import CoverageResult

    a = CoverageResult.model_validate(json_mod.loads(run_a.read_text()))
    b = CoverageResult.model_validate(json_mod.loads(run_b.read_text()))

    a_status = {c.technique.id: c.status for c in a.evidence_chains}
    b_status = {c.technique.id: c.status for c in b.evidence_chains}

    all_techs = sorted(set(a_status) | set(b_status))

    table = Table(title="Coverage Diff", border_style="cyan")
    table.add_column("Technique", style="bold")
    table.add_column(f"Run A ({a.run_id[:8]})")
    table.add_column(f"Run B ({b.run_id[:8]})")
    table.add_column("Delta")

    regressions = 0
    improvements = 0
    for tid in all_techs:
        sa = a_status.get(tid, "—")
        sb = b_status.get(tid, "—")
        if sa == sb:
            delta = "[dim]unchanged[/]"
        elif sb == "detected" and sa != "detected":
            delta = "[green]+ NEW DETECTION[/]"
            improvements += 1
        elif sa == "detected" and sb != "detected":
            delta = "[red]- REGRESSION[/]"
            regressions += 1
        else:
            delta = f"[yellow]{sa} → {sb}[/]"

        sa_fmt = "[green]detected[/]" if sa == "detected" else f"[red]{sa}[/]"
        sb_fmt = "[green]detected[/]" if sb == "detected" else f"[red]{sb}[/]"
        table.add_row(tid, sa_fmt, sb_fmt, delta)

    console.print(table)
    console.print(
        f"\n  Improvements: [green]{improvements}[/]  "
        f"Regressions: [red]{regressions}[/]  "
        f"Coverage: {a.coverage_percentage:.0f}% → {b.coverage_percentage:.0f}%"
    )


@recipe.command("report-only")
@click.argument("result_path", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "-f", "fmt", multiple=True, default=["html", "navigator"])
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def recipe_report_only(result_path: Path, fmt: tuple[str, ...], output: Path | None) -> None:
    """Re-generate reports from an existing coverage result JSON."""
    import json as json_mod

    from chef_detection.coverage_reporter import save_report
    from chef_pantry.models.evidence import CoverageResult

    data = json_mod.loads(result_path.read_text())
    result = CoverageResult.model_validate(data)
    out_dir = output or result_path.parent
    paths = save_report(result, out_dir, list(fmt))
    for p in paths:
        console.print(f"[green]📄 Generated:[/] {p}")


# --- Dashboard: aggregate multiple runs ---


@cli.command("dashboard")
@click.argument("results_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def dashboard(results_dir: Path, output: Path | None) -> None:
    """Generate aggregate coverage dashboard from multiple recipe runs."""
    import json as json_mod

    from chef_detection.coverage_reporter import generate_html_report, generate_navigator_json
    from chef_pantry.models.evidence import CoverageResult, EvidenceChain

    json_files = sorted(results_dir.glob("*.json"))
    all_chains: list[EvidenceChain] = []
    recipe_names: list[str] = []

    for jf in json_files:
        if jf.name.endswith("_navigator.json") or jf.name.startswith("dashboard"):
            continue
        data = json_mod.loads(jf.read_text())
        if "evidence_chains" not in data:
            continue
        result = CoverageResult.model_validate(data)
        all_chains.extend(result.evidence_chains)
        recipe_names.append(result.recipe_name)

    if not all_chains:
        console.print("[yellow]No coverage results found.[/]")
        sys.exit(1)

    # Deduplicate: keep best status per technique
    best: dict[str, EvidenceChain] = {}
    for chain in all_chains:
        tid = chain.technique.id
        if tid not in best or (chain.status == "detected" and best[tid].status != "detected"):
            best[tid] = chain

    from datetime import UTC, datetime

    aggregate = CoverageResult(
        recipe_name=f"Dashboard ({', '.join(sorted(set(recipe_names)))})",
        run_id="dashboard",
        timestamp=datetime.now(UTC),
        evidence_chains=list(best.values()),
    )

    out_dir = output or results_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write dashboard files
    nav = generate_navigator_json(aggregate)
    nav_path = out_dir / "dashboard_navigator.json"
    nav_path.write_text(json_mod.dumps(nav, indent=2))
    console.print(f"[green]📄 Navigator:[/] {nav_path}")

    html = generate_html_report(aggregate)
    html_path = out_dir / "dashboard.html"
    html_path.write_text(html)
    console.print(f"[green]📄 Dashboard:[/] {html_path}")

    console.print(
        f"\n  Recipes: {len(set(recipe_names))}  "
        f"Techniques: {aggregate.total_count}  "
        f"Coverage: {aggregate.coverage_percentage:.0f}%"
    )


# --- Webhook ---


@recipe.command("notify")
@click.argument("result_path", type=click.Path(exists=True, path_type=Path))
@click.option("--webhook", required=True, help="Webhook URL")
@click.option("--slack", is_flag=True, help="Format as Slack Block Kit")
def recipe_notify(result_path: Path, webhook: str, slack: bool) -> None:
    """Send a coverage result to a webhook (Slack, Teams, etc.)."""
    asyncio.run(_recipe_notify(result_path, webhook, slack))


async def _recipe_notify(result_path: Path, webhook_url: str, slack: bool) -> None:
    import json as json_mod

    from chef_pantry.models.evidence import CoverageResult
    from chef_recipes.webhooks import WebhookConfig, send_webhook

    data = json_mod.loads(result_path.read_text())
    result = CoverageResult.model_validate(data)
    config = WebhookConfig(url=webhook_url)

    console.print(f"[bold]Sending to[/] {webhook_url}")
    success = await send_webhook(config, result)
    if success:
        console.print("[green]✓[/] Webhook delivered")
    else:
        console.print("[red]✗[/] Webhook failed")
        sys.exit(1)


# --- Navigator import ---


@recipe.command("import-navigator")
@click.argument("layer_path", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=Path("recipes"))
@click.option("--threshold", type=int, default=50, help="Score threshold for 'uncovered'")
def recipe_import_navigator(layer_path: Path, output: Path, threshold: int) -> None:
    """Import ATT&CK Navigator layer and generate recipes for uncovered techniques."""
    from chef_recipes.navigator_import import (
        analyze_coverage,
        generate_recipe_stubs,
        load_navigator_layer,
    )

    console.print(f"\n[bold]Importing Navigator layer:[/] {layer_path}\n")
    layer = load_navigator_layer(layer_path)
    analysis = analyze_coverage(layer, score_threshold=threshold)

    console.print(f"  Total techniques: {analysis.total_techniques}")
    console.print(f"  Covered (score >= {threshold}): [green]{analysis.covered}[/]")
    console.print(f"  Uncovered: [red]{analysis.uncovered}[/]")

    if not analysis.gap_technique_ids:
        console.print("\n[green]No gaps found — full coverage![/]")
        return

    created = generate_recipe_stubs(analysis.gap_technique_ids, output)
    console.print(f"\n  [green]Created {len(created)} recipe stubs in {output}[/]")
    for p in created[:10]:
        console.print(f"    {p}")
    if len(created) > 10:
        console.print(f"    ... and {len(created) - 10} more")


# --- Harden (Phase 3 stub) ---


@cli.group()
def harden() -> None:
    """Hardening Kitchen — translate Ansible roles to Chef + InSpec."""
    pass


@harden.command("translate")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def harden_translate(path: Path) -> None:
    """Translate an Ansible role to Chef recipe + InSpec profile. (Phase 3)"""
    console.print("[yellow]Hardening Kitchen is coming in Phase 3.[/]")
    console.print(f"Will translate {path}")


if __name__ == "__main__":
    cli()
