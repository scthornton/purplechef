"""Atomic Red Team executor via WinRM/PowerShell.

Executes Invoke-AtomicTest commands on remote Windows targets
using PowerShell remoting over WinRM.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from chef_pantry.models.emulation import EmulationRecord


class AtomicRunner:
    """Execute Atomic Red Team tests on remote Windows hosts via WinRM.

    Uses PowerShell Invoke-Command with Invoke-AtomicTest from the
    Atomic Red Team framework (https://github.com/redcanaryco/invoke-atomicredteam).
    """

    def __init__(
        self,
        target_host: str,
        *,
        username: str | None = None,
        password: str | None = None,
        use_ssl: bool = False,
        audit_logger: Any | None = None,
    ) -> None:
        self._host = target_host
        self._username = username
        self._password = password
        self._use_ssl = use_ssl
        self._audit = audit_logger

    def _build_invoke_command(
        self,
        technique_id: str,
        test_numbers: list[int] | None = None,
        *,
        get_prereqs: bool = True,
        cleanup: bool = False,
    ) -> str:
        """Build the PowerShell command string for Invoke-AtomicTest."""
        parts = [f"Invoke-AtomicTest {technique_id}"]
        if test_numbers:
            nums = ",".join(str(n) for n in test_numbers)
            parts.append(f"-TestNumbers {nums}")
        if get_prereqs:
            parts.append("-GetPrereqs")
        if cleanup:
            parts.append("-Cleanup")
        return " ".join(parts)

    def _build_remote_command(self, ps_command: str) -> list[str]:
        """Build the full command to execute PowerShell remotely."""
        # Use pwsh for cross-platform, fall back to powershell.exe on Windows
        inner = (
            f"Import-Module C:\\AtomicRedTeam\\invoke-atomicredteam\\"
            f"Invoke-AtomicRedTeam.psd1 -Force; {ps_command}"
        )
        cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"Invoke-Command -ComputerName {self._host} -ScriptBlock {{ {inner} }}",
        ]
        if self._username and self._password:
            cred_block = (
                f"$cred = New-Object System.Management.Automation.PSCredential("
                f"'{self._username}', (ConvertTo-SecureString '{self._password}' "
                f"-AsPlainText -Force)); "
            )
            cmd[4] = cred_block + cmd[4] + " -Credential $cred"
        return cmd

    async def execute_technique(
        self,
        technique_id: str,
        test_numbers: list[int] | None = None,
        *,
        timeout: int = 300,
    ) -> EmulationRecord:
        """Execute an Atomic Red Team technique on the remote host.

        Returns an EmulationRecord with execution details.
        """
        start = datetime.now(UTC)
        self._audit_log("execute_technique", target=f"{self._host}:{technique_id}")

        ps_cmd = self._build_invoke_command(technique_id, test_numbers)
        full_cmd = self._build_remote_command(ps_cmd)

        try:
            proc = await asyncio.create_subprocess_exec(
                *full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            success = proc.returncode == 0
            status = "completed" if success else "failed"
        except TimeoutError:
            status = "failed"
            success = False
        except FileNotFoundError:
            # PowerShell not available (e.g., running on Linux without pwsh)
            status = "failed"
            success = False

        end = datetime.now(UTC)
        self._audit_log(
            "execute_complete",
            detail={"technique": technique_id, "status": status},
            success=success,
        )

        return EmulationRecord(
            method="atomic",
            techniques_attempted=[technique_id],
            techniques_succeeded=[technique_id] if success else [],
            start_time=start,
            end_time=end,
            status=status,
        )

    async def cleanup_technique(
        self, technique_id: str, test_numbers: list[int] | None = None
    ) -> bool:
        """Run cleanup for a previously executed technique."""
        ps_cmd = self._build_invoke_command(
            technique_id, test_numbers, cleanup=True, get_prereqs=False
        )
        full_cmd = self._build_remote_command(ps_cmd)
        try:
            proc = await asyncio.create_subprocess_exec(
                *full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
            return proc.returncode == 0
        except (TimeoutError, FileNotFoundError):
            return False

    def _audit_log(self, action: str, **kwargs: Any) -> None:
        if self._audit:
            self._audit.log(
                event_type="atomic_runner",
                actor="atomic_runner",
                action=action,
                **kwargs,
            )
