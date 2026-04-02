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

            # Only validate if something actually executed
            if emulation.get("status") in ("skipped", "no_abilities"):
                console.print("\n[yellow]⏭ Skipping validation[/] — no attack was executed")
                evidence = self._build_not_executed_chains(recipe)
            else:
                await self._phase_wait(recipe)
                evidence = await self._phase_validate(recipe, emulation)

            result = self._phase_report(recipe, evidence)
            self._phase = Phase.DONE
            return result
        except DryRunBlockedError as exc:
            console.print(f"\n[yellow]⏸ Dry-run blocked:[/] {exc}")
            self._log("dry_run_blocked", detail=str(exc))
            self._phase = Phase.DONE
            # Return explicit dry-run chains instead of empty result
            return self._phase_report(
                recipe,
                self._build_not_executed_chains(recipe, reason="Blocked by dry-run mode"),
            )
        except Exception as exc:
            failed_phase = self._phase.value  # capture before overwriting
            self._phase = Phase.FAILED
            console.print(f"\n[red]✗ Failed in {failed_phase}:[/] {exc}")
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

        # Collect ability IDs — honor explicit recipe ability_ids, fall back to resolver
        ability_ids = []
        recipe_abilities = {a.technique_id: a.ability_id for a in spec.abilities}
        for r in resolved:
            explicit_id = recipe_abilities.get(r.technique.id, "auto")
            if explicit_id != "auto" and explicit_id:
                ability_ids.append(explicit_id)
            elif r.caldera_ability_id:
                ability_ids.append(r.caldera_ability_id)

        if not ability_ids:
            console.print("  [yellow]⚠[/] No Caldera abilities resolved — skipping execution")
            return {"method": "caldera", "status": "no_abilities"}

        # Honor recipe's adversary_name, fall back to auto-generated
        adversary_name = spec.adversary_name or f"chef-{recipe.name}-{self._run_id}"
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

        # Enforce detection_source contract
        source = recipe.validate_spec.detection_source
        if source != "limacharlie":
            raise NotImplementedError(
                f"Detection source '{source}' is not yet supported. "
                f"Only 'limacharlie' is currently implemented. "
                f"Set validate.detection_source to 'limacharlie' in your recipe."
            )

        now = datetime.now(UTC)
        # Use execution start time if available, else look back from now
        exec_start_str = emulation.get("start_time")
        if exec_start_str:
            window_start = datetime.fromisoformat(exec_start_str)
        else:
            lookback = recipe.validate_spec.wait_seconds + 600
            window_start = datetime.fromtimestamp(now.timestamp() - lookback, tz=UTC)

        # Build expected rule patterns for flexible matching.
        # Supports exact names, regex patterns (prefix with "re:"), and
        # Sigma-style title matching via substring containment.
        expected_patterns: list[tuple[str, str]] = []  # (mode, value)
        for r in recipe.validate_spec.expected_rules:
            name = r.get("name", "")
            if not name:
                continue
            if name.startswith("re:"):
                expected_patterns.append(("regex", name[3:]))
            else:
                # Use substring match (case-insensitive) rather than exact match
                # to tolerate drift between recipe names and Sigma titles.
                expected_patterns.append(("substring", name.lower()))

        def _rule_matches(rule_name: str) -> bool:
            """Check if a detection rule name matches any expected pattern."""
            if not expected_patterns:
                return True  # No filter — accept all detections
            name_lower = rule_name.lower()
            for mode, value in expected_patterns:
                if mode == "regex":
                    import re

                    if re.search(value, rule_name, re.IGNORECASE):
                        return True
                elif mode == "substring":
                    if value in name_lower:
                        return True
            return False

        chains: list[EvidenceChain] = []
        for tid in recipe.metadata.mitre_techniques:
            technique = self._resolver.build_technique(tid)
            detections = await self._lc.find_detections_for_technique(
                tid, start=window_start, end=now
            )

            # Filter by expected_rules using flexible matching
            matches = []
            for d in detections:
                rule_name = d.get("detect", {}).get("detect_mtd", {}).get("name", "unknown")
                if not _rule_matches(rule_name):
                    continue  # Skip detections that don't match any expected pattern
                matches.append(
                    DetectionMatch(
                        rule_name=rule_name,
                        source="limacharlie",
                        timestamp=self._lc.detection_timestamp(d),
                        alert_id=d.get("detect_id", "unknown"),
                        tags=self._lc.extract_technique_tags(d),
                        confidence=0.9,
                    )
                )

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

    def _build_not_executed_chains(
        self, recipe: Recipe, *, reason: str = "Attack was not executed"
    ) -> list[EvidenceChain]:
        """Build evidence chains marked as 'error' when no attack executed."""
        now = datetime.now(UTC)
        chains = []
        for tid in recipe.metadata.mitre_techniques:
            technique = self._resolver.build_technique(tid)
            chains.append(
                EvidenceChain(
                    technique=technique,
                    emulation_id=self._run_id,
                    execution_start=now,
                    execution_end=now,
                    detection_window_start=now,
                    detection_window_end=now,
                    detections=[],
                    status="error",
                    notes=reason,
                )
            )
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
