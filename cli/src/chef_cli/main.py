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
