"""SEC598 Chef — unified CLI for purple team automation.

Usage:
    chef recipe run <path>      Run a purple team recipe
    chef recipe list [dir]      List available recipes
    chef recipe lint <path>     Validate a recipe file
    chef recipe report <dir>    Generate aggregate coverage report
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

BANNER = r"""[cyan]
   _____ ______ _____ ______ ___   ___
  / ____|  ____/ ____|  ____/ _ \ / _ \
 | (___ | |__ | |    | |__ | (_) | (_) |
  \___ \|  __|| |    |__  |\__, |> _ <
  ____) | |___| |___ | |___  / /| (_) |
 |_____/|______\_____|______/_/  \___/
            [bold white]C · H · E · F[/bold white]
[/cyan][dim]  Purple Team Recipe Platform[/dim]
"""


@click.group()
@click.version_option(version="0.1.0", prog_name="sec598-chef")
def cli() -> None:
    """SEC598 Chef — deploy, attack, detect, validate, report."""
    pass


@cli.group()
def recipe() -> None:
    """Manage and execute purple team recipes."""
    pass


@recipe.command("run")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--live", is_flag=True, help="Disable dry-run safety (execute for real)")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None, help="Output directory")
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
    effective_dry_run = dry_run or settings.dry_run

    if effective_dry_run:
        console.print("[yellow]🔒 Dry-run mode[/] — no attacks will execute. Use --live to run for real.\n")
    else:
        console.print("[red]⚡ LIVE mode[/] — attacks WILL execute against targets.\n")

    recipe_model = load_recipe(path)

    audit = AuditLogger(Path(settings.audit_log))
    async with (
        CalderaClient(
            base_url=settings.caldera_url,
            api_key=settings.caldera_api_key,
            allowed_groups=settings.caldera_allowed_groups,
            dry_run=effective_dry_run,
            audit_logger=audit,
        ) as caldera,
        LimaCharlieClient(
            oid=settings.lc_oid,
            api_key=settings.lc_api_key,
            audit_logger=audit,
        ) as lc,
    ):
        resolver = MitreResolver(caldera_client=caldera)
        orchestrator = RecipeOrchestrator(
            caldera=caldera, limacharlie=lc, resolver=resolver, audit=audit
        )
        result = await orchestrator.run(recipe_model)

    # Write results
    out = output_dir or Path("reports")
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / f"{recipe_model.name}_{orchestrator.run_id}.json"
    report_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    console.print(f"\n[green]📄 Report saved:[/] {report_path}")
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
            table.add_row(f"[red]ERROR[/]", str(exc)[:50], "", "", str(path))

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
    for rule in r.validate.sigma_rules:
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
        console.print(f"\n[green]✓ Recipe is valid[/]")


@cli.group()
def detect() -> None:
    """Detection Kitchen — generate, validate, and test detection rules."""
    pass


@detect.command("generate")
@click.argument("technique_id")
def detect_generate(technique_id: str) -> None:
    """Generate a Sigma detection rule for a MITRE technique. (Phase 2)"""
    console.print("[yellow]Detection Kitchen is coming in Phase 2.[/]")
    console.print(f"Will generate Sigma rule for {technique_id}")


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
