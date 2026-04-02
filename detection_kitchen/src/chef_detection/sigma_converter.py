"""Sigma rule converter for Azure Sentinel (KQL) and Splunk (SPL).

Pragmatic converters targeting the field patterns used in PurpleChef's
seven Sigma templates. Does not attempt full Sigma specification coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class SigmaConversionResult:
    """Container for a converted Sigma rule query."""

    original_format: str = "sigma"
    target_format: str = ""
    query: str = ""
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# KQL table mapping
# ---------------------------------------------------------------------------

_KQL_TABLE_MAP: dict[str, str] = {
    "process_creation": "SysmonEvent",
    "process_access": "SysmonEvent",
    "file_event": "SysmonEvent",
    "registry_event": "SysmonEvent",
    "network_connection": "SysmonEvent",
    "dns_query": "SysmonEvent",
    "image_load": "SysmonEvent",
}

_KQL_FALLBACK_TABLE = "SecurityEvent"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_field_and_modifier(key: str) -> tuple[str, str]:
    """Split a Sigma field key like 'Image|endswith' into (field, modifier)."""
    parts = key.split("|", 1)
    return parts[0], parts[1] if len(parts) > 1 else ""


def _kql_condition_for_value(field_name: str, modifier: str, value: str) -> str:
    """Build a single KQL condition from a Sigma field, modifier, and value."""
    val = value.replace("\\", "\\\\").replace("'", "\\'")

    if modifier == "endswith":
        return f'{field_name} endswith @"{val}"'
    elif modifier == "contains":
        return f'{field_name} contains @"{val}"'
    elif modifier == "startswith":
        return f'{field_name} startswith @"{val}"'
    elif "contains|all" in modifier or modifier == "contains|all":
        # Handled at the list level
        return f'{field_name} contains @"{val}"'
    else:
        return f'{field_name} == @"{val}"'


def _splunk_condition_for_value(field_name: str, modifier: str, value: str) -> str:
    """Build a single SPL condition from a Sigma field, modifier, and value."""
    val = value.replace('"', '\\"')

    if modifier == "endswith":
        return f'{field_name}="*{val}"'
    elif modifier == "contains" or modifier == "contains|all":
        return f'{field_name}="*{val}*"'
    elif modifier == "startswith":
        return f'{field_name}="{val}*"'
    else:
        return f'{field_name}="{val}"'


def _build_selection_clauses(
    selection: dict[str, Any],
    formatter: callable,
) -> list[str]:
    """Convert a Sigma selection dict into a list of condition strings.

    Each key in the selection maps to one or more values.  Multiple values
    for the same field are OR'd; multiple keys within a selection are AND'd
    (unless the modifier is 'contains|all', in which case all values are AND'd).
    """
    and_parts: list[str] = []

    for raw_key, raw_value in selection.items():
        field_name, modifier = _extract_field_and_modifier(raw_key)
        values = raw_value if isinstance(raw_value, list) else [raw_value]

        is_all = "all" in modifier  # contains|all

        conditions = [formatter(field_name, modifier.split("|")[0], str(v)) for v in values]

        if is_all:
            and_parts.append("(" + " and ".join(conditions) + ")")
        elif len(conditions) == 1:
            and_parts.append(conditions[0])
        else:
            and_parts.append("(" + " or ".join(conditions) + ")")

    return and_parts


# ---------------------------------------------------------------------------
# Condition parser (lightweight)
# ---------------------------------------------------------------------------


def _resolve_condition(
    condition: str,
    named_clauses: dict[str, str],
) -> str:
    """Replace Sigma condition identifiers with their rendered query fragments.

    Handles: ``and``, ``or``, ``not``, parentheses, and bare identifiers.
    """
    result = condition

    # Sort by length descending so longer names are replaced first
    for name in sorted(named_clauses, key=len, reverse=True):
        result = result.replace(name, f"({named_clauses[name]})")

    return result


# ---------------------------------------------------------------------------
# Public API — KQL
# ---------------------------------------------------------------------------


def convert_to_kql(sigma_rule: dict[str, Any]) -> SigmaConversionResult:
    """Convert a Sigma rule dict to an Azure Sentinel KQL query string."""
    notes: list[str] = []
    detection = sigma_rule.get("detection", {})
    logsource = sigma_rule.get("logsource", {})
    condition_str = detection.get("condition", "")

    # Determine KQL table
    category = logsource.get("category", "")
    table = _KQL_TABLE_MAP.get(category, _KQL_FALLBACK_TABLE)
    if table == _KQL_FALLBACK_TABLE and category:
        notes.append(
            f"Approximate mapping: logsource category '{category}' mapped to {_KQL_FALLBACK_TABLE}."
        )

    # Build named clause fragments
    named_clauses: dict[str, str] = {}
    for section_name, section_body in detection.items():
        if section_name == "condition":
            continue
        if not isinstance(section_body, dict):
            continue

        parts = _build_selection_clauses(section_body, _kql_condition_for_value)
        named_clauses[section_name] = " and ".join(parts) if parts else "true"

    # Resolve the condition
    where_clause = _resolve_condition(condition_str, named_clauses)

    query = f"{table}\n| where {where_clause}"

    # Add EventID filter if present in logsource hints
    event_id = None
    for _name, body in detection.items():
        if isinstance(body, dict) and "EventID" in body:
            event_id = body["EventID"]
            break
    if event_id:
        notes.append(f"EventID {event_id} included in selection clauses.")

    return SigmaConversionResult(
        original_format="sigma",
        target_format="kql",
        query=query,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Public API — Splunk SPL
# ---------------------------------------------------------------------------

_SPLUNK_SOURCETYPE_MAP: dict[str, str] = {
    "process_creation": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "process_access": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "file_event": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "registry_event": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "network_connection": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "dns_query": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "image_load": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
}

_SPLUNK_FALLBACK_SOURCETYPE = "WinEventLog:Security"


def convert_to_splunk(sigma_rule: dict[str, Any]) -> SigmaConversionResult:
    """Convert a Sigma rule dict to a Splunk SPL query string."""
    notes: list[str] = []
    detection = sigma_rule.get("detection", {})
    logsource = sigma_rule.get("logsource", {})
    condition_str = detection.get("condition", "")

    # Determine sourcetype
    category = logsource.get("category", "")
    sourcetype = _SPLUNK_SOURCETYPE_MAP.get(category, _SPLUNK_FALLBACK_SOURCETYPE)
    if sourcetype == _SPLUNK_FALLBACK_SOURCETYPE and category:
        notes.append(
            f"Approximate mapping: logsource category '{category}' "
            f"mapped to sourcetype={_SPLUNK_FALLBACK_SOURCETYPE}."
        )

    # Build named clause fragments
    named_clauses: dict[str, str] = {}
    for section_name, section_body in detection.items():
        if section_name == "condition":
            continue
        if not isinstance(section_body, dict):
            continue

        parts = _build_selection_clauses(section_body, _splunk_condition_for_value)
        named_clauses[section_name] = " ".join(parts) if parts else "*"

    # Resolve the condition — SPL uses different boolean syntax
    spl_condition = _resolve_condition(condition_str, named_clauses)

    # Normalise boolean operators for SPL
    spl_condition = spl_condition.replace(" and ", " AND ")
    spl_condition = spl_condition.replace(" or ", " OR ")
    spl_condition = spl_condition.replace("not ", "NOT ")

    query = f'index=* sourcetype="{sourcetype}" {spl_condition}'

    return SigmaConversionResult(
        original_format="sigma",
        target_format="splunk",
        query=query,
        notes=notes,
    )
