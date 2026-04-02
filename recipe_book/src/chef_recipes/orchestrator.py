"""Recipe orchestrator — state machine that runs a complete purple team exercise.

States: LOAD → RESOLVE → EXECUTE → WAIT → VALIDATE → REPORT → DONE
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from chef_pantry.audit import AuditLogger
from chef_pantry.clients.caldera import CalderaClient
from chef_pantry.clients.limacharlie import LimaCharlieClient
from chef_pantry.errors import DryRunBlockedError
from chef_pantry.mitre.resolver import MitreResolver
from chef_pantry.models.evidence import CoverageResult, DetectionMatch, EvidenceChain
from chef_pantry.models.recipe import Recipe
from chef_pantry.models.technique import ResolvedTechnique
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class Phase(StrEnum):
    LOAD = "load"
    RESOLVE = "resolve"
    EXECUTE = "execute"
    WAIT = "wait"
    VALIDATE = "validate"
    REPORT = "report"
    DONE = "done"
    FAILED = "failed"


class RecipeOrchestrator:
    """Runs a recipe through the full purple team lifecycle."""

    def __init__(
        self,
        caldera: CalderaClient,
        limacharlie: LimaCharlieClient,
        resolver: MitreResolver,
        audit: AuditLogger | None = None,
    ) -> None:
        self._caldera = caldera
        self._lc = limacharlie
        self._resolver = resolver
        self._audit = audit
        self._phase = Phase.LOAD
        self._run_id = uuid.uuid4().hex[:12]

    @property
    def phase(self) -> Phase:
        return self._phase

    @property
    def run_id(self) -> str:
        return self._run_id

    async def run(self, recipe: Recipe) -> CoverageResult:
        """Execute the full recipe lifecycle. Returns a CoverageResult."""
        console.print(
            Panel(
                f"[bold cyan]🍳 Cooking:[/] {recipe.name} v{recipe.version}\n"
                f"[dim]Run ID: {self._run_id}[/]",
                title="PurpleChef",
                border_style="cyan",
            )
        )

        try:
            resolved = await self._phase_resolve(recipe)
            emulation = await self._phase_execute(recipe, resolved)
            await self._phase_wait(recipe)
            evidence = await self._phase_validate(recipe, emulation)
            result = self._phase_report(recipe, evidence)
            self._phase = Phase.DONE
            return result
        except DryRunBlockedError as exc:
            console.print(f"\n[yellow]⏸ Dry-run blocked:[/] {exc.detail}")
            self._log("dry_run_blocked", detail=str(exc))
            self._phase = Phase.DONE
            return self._empty_result(recipe)
        except Exception as exc:
            self._phase = Phase.FAILED
            console.print(f"\n[red]✗ Failed in {self._phase.value}:[/] {exc}")
            self._log("recipe_failed", detail=str(exc), success=False)
            raise

    async def _phase_resolve(self, recipe: Recipe) -> list[ResolvedTechnique]:
        self._phase = Phase.RESOLVE
        console.print("\n[bold]📋 Resolve[/] — mapping techniques to abilities")
        technique_ids = recipe.metadata.mitre_techniques
        resolved = await self._resolver.resolve_many(technique_ids)
        for r in resolved:
            source_label = r.resolution_source
            if r.caldera_ability_id:
                source_label += f" ({r.caldera_ability_id})"
            console.print(f"  [green]✓[/] {r.technique.id} → {r.technique.name} [{source_label}]")
        self._log("resolved", detail={"count": len(resolved)})
        return resolved

    async def _phase_execute(
        self, recipe: Recipe, resolved: list[ResolvedTechnique]
    ) -> dict[str, Any]:
        self._phase = Phase.EXECUTE
        console.print("\n[bold]⚔️  Execute[/] — running adversary emulation")

        if recipe.attack.method == "caldera":
            return await self._execute_caldera(recipe, resolved)
        elif recipe.attack.method == "atomic":
            console.print("  [yellow]⚠[/] Atomic execution not yet implemented")
            return {"method": "atomic", "status": "skipped"}
        else:
            console.print("  [dim]Manual execution — no automated attack[/]")
            return {"method": "manual", "status": "skipped"}

    async def _execute_caldera(
        self, recipe: Recipe, resolved: list[ResolvedTechnique]
    ) -> dict[str, Any]:
        spec = recipe.attack.caldera
        if spec is None:
            raise ValueError("Caldera attack spec missing")

        # Collect ability IDs
        ability_ids = []
        for r in resolved:
            if r.caldera_ability_id:
                ability_ids.append(r.caldera_ability_id)

        if not ability_ids:
            console.print("  [yellow]⚠[/] No Caldera abilities resolved — skipping execution")
            return {"method": "caldera", "status": "no_abilities"}

        # Create adversary
        adversary_name = f"chef-{recipe.name}-{self._run_id}"
        console.print(f"  Creating adversary: [cyan]{adversary_name}[/]")
        adversary = await self._caldera.create_adversary(
            name=adversary_name,
            description=f"Auto-generated by PurpleChef for recipe '{recipe.name}'",
            ability_ids=ability_ids,
        )
        adversary_id = adversary["adversary_id"]

        # Create and run operation
        op_name = f"chef-op-{self._run_id}"
        console.print(
            f"  Starting operation: [cyan]{op_name}[/] against group [cyan]{spec.group}[/]"
        )
        operation = await self._caldera.create_operation(
            name=op_name, adversary_id=adversary_id, group=spec.group
        )
        operation_id = operation["id"]

        # Poll until complete
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
        ) as progress:
            task = progress.add_task("Waiting for operation to complete...", total=None)
            result = await self._caldera.poll_operation(operation_id, timeout=spec.timeout)
            progress.update(task, description="[green]Operation complete")

        chain = result.get("chain", [])
        console.print(f"  [green]✓[/] Operation finished — {len(chain)} steps executed")
        self._log("executed", detail={"operation_id": operation_id, "steps": len(chain)})
        return {
            "method": "caldera",
            "operation_id": operation_id,
            "steps_executed": len(chain),
            "start_time": datetime.now(UTC).isoformat(),
        }

    async def _phase_wait(self, recipe: Recipe) -> None:
        self._phase = Phase.WAIT
        wait = recipe.validate_spec.wait_seconds
        console.print(f"\n[bold]⏳ Wait[/] — {wait}s for telemetry propagation")
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
        ) as progress:
            task = progress.add_task(f"Waiting {wait}s...", total=wait)
            for i in range(wait):
                await asyncio.sleep(1)
                progress.update(
                    task, advance=1, description=f"Waiting... {wait - i - 1}s remaining"
                )
        console.print("  [green]✓[/] Wait complete")

    async def _phase_validate(
        self, recipe: Recipe, emulation: dict[str, Any]
    ) -> list[EvidenceChain]:
        self._phase = Phase.VALIDATE
        console.print("\n[bold]🔍 Validate[/] — checking for detections")

        now = datetime.now(UTC)
        # Look back over the execution + wait window
        lookback_seconds = recipe.validate_spec.wait_seconds + 600
        window_start = datetime.fromtimestamp(now.timestamp() - lookback_seconds, tz=UTC)

        chains: list[EvidenceChain] = []
        for tid in recipe.metadata.mitre_techniques:
            technique = self._resolver.build_technique(tid)
            detections = await self._lc.find_detections_for_technique(
                tid, start=window_start, end=now
            )

            matches = [
                DetectionMatch(
                    rule_name=d.get("detect", {}).get("detect_mtd", {}).get("name", "unknown"),
                    source="limacharlie",
                    timestamp=self._lc.detection_timestamp(d),
                    alert_id=d.get("detect_id", "unknown"),
                    tags=self._lc.extract_technique_tags(d),
                    confidence=0.9 if detections else 0.0,
                )
                for d in detections
            ]

            status = "detected" if matches else "missed"
            chain = EvidenceChain(
                technique=technique,
                emulation_id=emulation.get("operation_id", self._run_id),
                execution_start=window_start,
                execution_end=now,
                detection_window_start=window_start,
                detection_window_end=now,
                detections=matches,
                status=status,
            )
            chains.append(chain)

            icon = "[green]✓[/]" if status == "detected" else "[red]✗[/]"
            console.print(f"  {icon} {tid} ({technique.name}): {status} ({len(matches)} alerts)")

        self._log("validated", detail={"chains": len(chains)})
        return chains

    def _phase_report(self, recipe: Recipe, chains: list[EvidenceChain]) -> CoverageResult:
        self._phase = Phase.REPORT
        result = CoverageResult(
            recipe_name=recipe.name,
            run_id=self._run_id,
            timestamp=datetime.now(UTC),
            evidence_chains=chains,
        )
        detected = result.detected_count
        total = result.total_count
        pct = result.coverage_percentage

        console.print(f"\n[bold]📊 Report[/] — {detected}/{total} techniques detected ({pct:.0f}%)")

        if result.missed_count > 0:
            console.print("\n  [yellow]Missed techniques (consider writing detections):[/]")
            for chain in chains:
                if chain.status == "missed":
                    console.print(f"    • {chain.technique.id} — {chain.technique.name}")

        self._log("reported", detail={"coverage": pct, "detected": detected, "total": total})
        return result

    def _empty_result(self, recipe: Recipe) -> CoverageResult:
        return CoverageResult(
            recipe_name=recipe.name,
            run_id=self._run_id,
            timestamp=datetime.now(UTC),
            evidence_chains=[],
        )

    def _log(self, action: str, detail: Any = None, success: bool = True) -> None:
        if self._audit:
            self._audit.log(
                event_type="recipe_orchestrator",
                actor="orchestrator",
                action=action,
                target=self._run_id,
                detail=detail if isinstance(detail, dict) else {"info": str(detail)},
                success=success,
            )
