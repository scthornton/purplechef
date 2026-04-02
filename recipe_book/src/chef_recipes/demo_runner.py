"""Demo runner — simulates a realistic purple team recipe execution.

Produces convincing output without any live backend (Caldera, LimaCharlie).
Used for screenshots, presentations, and README demos.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

from chef_pantry.mitre.resolver import MitreResolver
from chef_pantry.models.evidence import CoverageResult, DetectionMatch, EvidenceChain
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()

# Simulated detection data — what a real run would produce
_DEMO_DETECTIONS: dict[str, list[dict]] = {
    "T1003.001": [
        {
            "rule": "LSASS Memory Access",
            "alert_id": "det-7a8b9c",
            "confidence": 0.95,
            "delay_s": 38,
        },
    ],
    "T1059.001": [
        {
            "rule": "Obfuscated PowerShell",
            "alert_id": "det-ps4d2f",
            "confidence": 0.90,
            "delay_s": 12,
        },
        {
            "rule": "Encoded Command Execution",
            "alert_id": "det-ps8e1a",
            "confidence": 0.85,
            "delay_s": 14,
        },
    ],
    "T1053.005": [
        {
            "rule": "Scheduled Task Creation",
            "alert_id": "det-st3b7c",
            "confidence": 0.88,
            "delay_s": 45,
        },
    ],
    "T1566.001": [],  # missed — no detections
    "T1550.002": [],  # missed
    "T1018": [
        {
            "rule": "Remote System Discovery",
            "alert_id": "det-rd9f2e",
            "confidence": 0.82,
            "delay_s": 22,
        },
    ],
    "T1003.002": [],  # missed
}


async def run_demo(
    technique_ids: list[str], *, recipe_name: str = "demo-purple-exercise"
) -> CoverageResult:
    """Run a simulated purple team exercise with realistic timing and output."""
    run_id = uuid.uuid4().hex[:12]
    now = datetime.now(UTC)

    console.print(
        Panel(
            f"[bold cyan]🍳 Cooking:[/] {recipe_name}\n[dim]Run ID: {run_id}  |  Demo Mode[/]",
            title="PurpleChef",
            border_style="cyan",
        )
    )

    # Phase: Resolve
    console.print("\n[bold]📋 Resolve[/] — mapping techniques to Caldera abilities")
    resolver = MitreResolver()
    for tid in technique_ids:
        tech = resolver.build_technique(tid)
        await asyncio.sleep(0.15)
        console.print(f"  [green]✓[/] {tid} → {tech.name} [cyan][caldera][/cyan]")

    # Phase: Execute
    console.print("\n[bold]⚔️  Execute[/] — running adversary emulation")
    adversary = f"chef-{recipe_name}-{run_id}"
    console.print(f"  Creating adversary: [cyan]{adversary}[/]")
    await asyncio.sleep(0.3)
    console.print(
        f"  Starting operation: [cyan]chef-op-{run_id}[/] against group [cyan]chef-targets[/]"
    )

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
    ) as progress:
        task = progress.add_task("Executing techniques...", total=len(technique_ids))
        for _i, tid in enumerate(technique_ids):
            tech = resolver.build_technique(tid)
            await asyncio.sleep(0.4)
            progress.update(task, advance=1, description=f"Executed {tech.name} ({tid})")
        progress.update(task, description="[green]Operation complete")

    console.print(f"  [green]✓[/] Operation finished — {len(technique_ids)} steps executed")

    # Phase: Wait
    console.print("\n[bold]⏳ Wait[/] — 5s for telemetry propagation")
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
    ) as progress:
        task = progress.add_task("Waiting...", total=5)
        for i in range(5):
            await asyncio.sleep(0.3)
            progress.update(task, advance=1, description=f"Waiting... {4 - i}s remaining")
    console.print("  [green]✓[/] Wait complete")

    # Phase: Validate
    console.print("\n[bold]🔍 Validate[/] — checking LimaCharlie for detections")
    chains: list[EvidenceChain] = []
    exec_start = now - timedelta(minutes=5)

    for tid in technique_ids:
        tech = resolver.build_technique(tid)
        demo_dets = _DEMO_DETECTIONS.get(tid, [])
        await asyncio.sleep(0.2)

        matches = [
            DetectionMatch(
                rule_name=d["rule"],
                source="limacharlie",
                timestamp=exec_start + timedelta(seconds=d["delay_s"]),
                alert_id=d["alert_id"],
                tags=[tid.lower()],
                confidence=d["confidence"],
            )
            for d in demo_dets
        ]

        status = "detected" if matches else "missed"
        chain = EvidenceChain(
            technique=tech,
            emulation_id=f"op-{run_id}",
            execution_start=exec_start,
            execution_end=exec_start + timedelta(minutes=2),
            detection_window_start=exec_start,
            detection_window_end=now,
            detections=matches,
            status=status,
        )
        chains.append(chain)

        if status == "detected":
            det_names = ", ".join(d["rule"] for d in demo_dets)
            console.print(
                f"  [green]✓[/] {tid} ({tech.name}): "
                f"[green]detected[/] ({len(matches)} alert{'s' if len(matches) > 1 else ''}: {det_names})"
            )
        else:
            console.print(f"  [red]✗[/] {tid} ({tech.name}): [red]missed[/] (0 alerts)")

    # Phase: Report
    result = CoverageResult(
        recipe_name=recipe_name,
        run_id=run_id,
        timestamp=now,
        evidence_chains=chains,
    )

    detected = result.detected_count
    missed = result.missed_count
    total = result.total_count
    pct = result.coverage_percentage

    console.print(f"\n[bold]📊 Report[/] — {detected}/{total} techniques detected ({pct:.0f}%)")

    if missed > 0:
        console.print("\n  [yellow]Detection gaps (consider writing rules):[/]")
        for c in chains:
            if c.status == "missed":
                console.print(f"    [red]•[/] {c.technique.id} — {c.technique.name}")

    # Summary table
    console.print()
    table = Table(title="Evidence Chain Summary", border_style="cyan", show_lines=True)
    table.add_column("Technique", style="bold")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Alerts")
    table.add_column("Rules Matched")

    for c in chains:
        status_fmt = "[green]DETECTED[/]" if c.status == "detected" else "[red]MISSED[/]"
        rules = ", ".join(d.rule_name for d in c.detections) or "—"
        table.add_row(
            c.technique.id,
            c.technique.name,
            status_fmt,
            str(c.detection_count),
            rules,
        )

    console.print(table)

    return result
