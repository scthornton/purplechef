"""Deterministic Sigma rule template engine.

Provides pre-built Sigma rule templates for common MITRE ATT&CK techniques.
This is the foundation layer -- works without any LLM dependency.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import date
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Individual template functions
# ---------------------------------------------------------------------------


def _t1003_001(
    technique_id: str, author: str = "PurpleChef", rule_date: str | None = None
) -> dict[str, Any]:
    """T1003.001 - LSASS Memory access via process_access."""
    return {
        "title": "LSASS Memory Access - Credential Dumping",
        "id": f"purplechef-{technique_id.lower().replace('.', '-')}",
        "status": "experimental",
        "description": (
            "Detects process access to lsass.exe with suspicious access rights "
            "commonly associated with credential dumping tools such as Mimikatz."
        ),
        "author": author,
        "date": rule_date or date.today().isoformat(),
        "references": [
            f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        ],
        "tags": [
            "attack.credential_access",
            f"attack.{technique_id.lower()}",
        ],
        "logsource": {
            "category": "process_access",
            "product": "windows",
        },
        "detection": {
            "selection": {
                "TargetImage|endswith": "\\lsass.exe",
                "GrantedAccess|contains": [
                    "0x1010",
                    "0x1038",
                    "0x1410",
                    "0x1438",
                    "0x143a",
                ],
            },
            "filter_known": {
                "SourceImage|endswith": [
                    "\\wmiprvse.exe",
                    "\\taskmgr.exe",
                    "\\procexp64.exe",
                    "\\MsMpEng.exe",
                ],
            },
            "condition": "selection and not filter_known",
        },
        "falsepositives": [
            "Legitimate security tools that access LSASS",
            "Windows Defender and other AV products",
        ],
        "level": "high",
    }


def _t1003_002(
    technique_id: str, author: str = "PurpleChef", rule_date: str | None = None
) -> dict[str, Any]:
    """T1003.002 - SAM registry hive access."""
    return {
        "title": "SAM Registry Hive Access - Credential Dumping",
        "id": f"purplechef-{technique_id.lower().replace('.', '-')}",
        "status": "experimental",
        "description": (
            "Detects access to the SAM registry hive via reg.exe save or "
            "direct registry access, indicative of offline credential extraction."
        ),
        "author": author,
        "date": rule_date or date.today().isoformat(),
        "references": [
            f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        ],
        "tags": [
            "attack.credential_access",
            f"attack.{technique_id.lower()}",
        ],
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection_reg_save": {
                "Image|endswith": "\\reg.exe",
                "CommandLine|contains|all": [
                    "save",
                ],
                "CommandLine|contains": [
                    "hklm\\sam",
                    "hklm\\system",
                    "hklm\\security",
                ],
            },
            "selection_esentutl": {
                "Image|endswith": "\\esentutl.exe",
                "CommandLine|contains": [
                    "\\windows\\ntds",
                    "\\config\\sam",
                ],
            },
            "condition": "selection_reg_save or selection_esentutl",
        },
        "falsepositives": [
            "Legitimate backup or disaster recovery tools",
        ],
        "level": "high",
    }


def _t1059_001(
    technique_id: str, author: str = "PurpleChef", rule_date: str | None = None
) -> dict[str, Any]:
    """T1059.001 - Obfuscated PowerShell execution (obfuscation score >= 5)."""
    return {
        "title": "Obfuscated PowerShell Execution",
        "id": f"purplechef-{technique_id.lower().replace('.', '-')}",
        "status": "experimental",
        "description": (
            "Detects PowerShell command lines with high obfuscation indicators "
            "including backtick, percent, and caret characters. Triggers when "
            "the combined obfuscation score meets or exceeds the threshold."
        ),
        "author": author,
        "date": rule_date or date.today().isoformat(),
        "references": [
            f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            "https://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation",
        ],
        "tags": [
            "attack.execution",
            "attack.defense_evasion",
            f"attack.{technique_id.lower()}",
        ],
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection_powershell": {
                "Image|endswith": [
                    "\\powershell.exe",
                    "\\pwsh.exe",
                ],
            },
            "obfuscation_backtick": {
                "CommandLine|contains": "`",
            },
            "obfuscation_caret": {
                "CommandLine|contains": "^",
            },
            "obfuscation_percent": {
                "CommandLine|contains": "%",
            },
            "obfuscation_encoding": {
                "CommandLine|contains": [
                    "-enc",
                    "-EncodedCommand",
                    "FromBase64String",
                ],
            },
            "obfuscation_invoke": {
                "CommandLine|contains": [
                    "Invoke-Expression",
                    "iex ",
                    ".Invoke(",
                    "ICAgI",
                ],
            },
            "condition": (
                "selection_powershell and "
                "(obfuscation_backtick and obfuscation_caret) or "
                "(obfuscation_encoding and obfuscation_invoke) or "
                "(obfuscation_backtick and obfuscation_percent and obfuscation_caret)"
            ),
        },
        "falsepositives": [
            "Legitimate admin scripts with encoded parameters",
            "Software installers using PowerShell with encoded commands",
        ],
        "level": "high",
    }


def _t1053_005(
    technique_id: str, author: str = "PurpleChef", rule_date: str | None = None
) -> dict[str, Any]:
    """T1053.005 - Scheduled task creation via schtasks.exe."""
    return {
        "title": "Scheduled Task Creation via schtasks.exe",
        "id": f"purplechef-{technique_id.lower().replace('.', '-')}",
        "status": "experimental",
        "description": (
            "Detects creation of scheduled tasks via schtasks.exe, which may "
            "indicate persistence or privilege escalation attempts."
        ),
        "author": author,
        "date": rule_date or date.today().isoformat(),
        "references": [
            f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        ],
        "tags": [
            "attack.execution",
            "attack.persistence",
            f"attack.{technique_id.lower()}",
        ],
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection": {
                "Image|endswith": "\\schtasks.exe",
                "CommandLine|contains": "/create",
            },
            "filter_system": {
                "User|contains": [
                    "SYSTEM",
                    "LOCAL SERVICE",
                ],
                "ParentImage|endswith": [
                    "\\svchost.exe",
                    "\\msiexec.exe",
                ],
            },
            "condition": "selection and not filter_system",
        },
        "falsepositives": [
            "Legitimate administrative task scheduling",
            "Software installation creating scheduled tasks",
        ],
        "level": "medium",
    }


def _t1018(
    technique_id: str, author: str = "PurpleChef", rule_date: str | None = None
) -> dict[str, Any]:
    """T1018 - Remote system discovery via nltest, net group, dsquery."""
    return {
        "title": "Remote System Discovery - Domain Enumeration",
        "id": f"purplechef-{technique_id.lower().replace('.', '-')}",
        "status": "experimental",
        "description": (
            "Detects execution of common domain and remote system enumeration "
            "tools such as nltest, net group, and dsquery that are frequently "
            "used during reconnaissance in Active Directory environments."
        ),
        "author": author,
        "date": rule_date or date.today().isoformat(),
        "references": [
            f"https://attack.mitre.org/techniques/{technique_id}/",
        ],
        "tags": [
            "attack.discovery",
            f"attack.{technique_id.lower()}",
        ],
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection_nltest": {
                "Image|endswith": "\\nltest.exe",
                "CommandLine|contains": [
                    "/dclist",
                    "/domain_trusts",
                    "/dsgetdc",
                ],
            },
            "selection_net": {
                "Image|endswith": "\\net.exe",
                "CommandLine|contains": [
                    'group "domain',
                    'group "enterprise',
                    "view /domain",
                ],
            },
            "selection_dsquery": {
                "Image|endswith": "\\dsquery.exe",
                "CommandLine|contains": [
                    "computer",
                    "server",
                    "subnet",
                ],
            },
            "condition": "selection_nltest or selection_net or selection_dsquery",
        },
        "falsepositives": [
            "Legitimate domain administration scripts",
            "IT asset management tools",
        ],
        "level": "medium",
    }


def _t1550_002(
    technique_id: str, author: str = "PurpleChef", rule_date: str | None = None
) -> dict[str, Any]:
    """T1550.002 - Pass-the-Hash via sekurlsa in command line."""
    return {
        "title": "Pass-the-Hash - Sekurlsa Module Detected",
        "id": f"purplechef-{technique_id.lower().replace('.', '-')}",
        "status": "experimental",
        "description": (
            "Detects command lines containing sekurlsa references, which are "
            "strongly indicative of Mimikatz pass-the-hash or credential "
            "extraction activity."
        ),
        "author": author,
        "date": rule_date or date.today().isoformat(),
        "references": [
            f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        ],
        "tags": [
            "attack.lateral_movement",
            f"attack.{technique_id.lower()}",
        ],
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "sekurlsa",
                    "sekurlsa::logonpasswords",
                    "sekurlsa::pth",
                    "sekurlsa::krbtgt",
                ],
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Penetration testing tools used by authorized teams",
        ],
        "level": "critical",
    }


def _t1566_001(
    technique_id: str, author: str = "PurpleChef", rule_date: str | None = None
) -> dict[str, Any]:
    """T1566.001 - Spearphishing attachment with suspicious Office child process."""
    return {
        "title": "Suspicious Office Child Process - Spearphishing",
        "id": f"purplechef-{technique_id.lower().replace('.', '-')}",
        "status": "experimental",
        "description": (
            "Detects Microsoft Office applications spawning suspicious child "
            "processes that are commonly associated with spearphishing payload "
            "execution, such as cmd.exe, powershell.exe, or mshta.exe."
        ),
        "author": author,
        "date": rule_date or date.today().isoformat(),
        "references": [
            f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        ],
        "tags": [
            "attack.initial_access",
            f"attack.{technique_id.lower()}",
        ],
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection_parent": {
                "ParentImage|endswith": [
                    "\\winword.exe",
                    "\\excel.exe",
                    "\\powerpnt.exe",
                    "\\outlook.exe",
                    "\\msaccess.exe",
                ],
            },
            "selection_child": {
                "Image|endswith": [
                    "\\cmd.exe",
                    "\\powershell.exe",
                    "\\pwsh.exe",
                    "\\mshta.exe",
                    "\\wscript.exe",
                    "\\cscript.exe",
                    "\\regsvr32.exe",
                    "\\rundll32.exe",
                    "\\certutil.exe",
                ],
            },
            "condition": "selection_parent and selection_child",
        },
        "falsepositives": [
            "Office add-ins that legitimately spawn processes",
            "Macros in trusted internal documents",
        ],
        "level": "high",
    }


# ---------------------------------------------------------------------------
# Template registry
# ---------------------------------------------------------------------------

TemplateFunc = Callable[[str, str, str | None], dict[str, Any]]

SIGMA_TEMPLATES: dict[str, TemplateFunc] = {
    "T1003.001": _t1003_001,
    "T1003.002": _t1003_002,
    "T1059.001": _t1059_001,
    "T1053.005": _t1053_005,
    "T1018": _t1018,
    "T1550.002": _t1550_002,
    "T1566.001": _t1566_001,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_template(technique_id: str) -> TemplateFunc | None:
    """Return the template function for a technique ID, or None if not found."""
    return SIGMA_TEMPLATES.get(technique_id)


def has_template(technique_id: str) -> bool:
    """Check whether a deterministic template exists for the given technique."""
    return technique_id in SIGMA_TEMPLATES


def list_templates() -> list[str]:
    """Return a sorted list of technique IDs that have templates."""
    return sorted(SIGMA_TEMPLATES.keys())


def render_sigma_yaml(rule_dict: dict[str, Any]) -> str:
    """Convert a Sigma rule dict to a valid YAML string.

    Uses block style for readability and preserves key ordering that
    matches the conventional Sigma rule layout.
    """
    # Sigma rules follow a conventional key order for readability.
    key_order = [
        "title",
        "id",
        "status",
        "description",
        "author",
        "date",
        "references",
        "tags",
        "logsource",
        "detection",
        "falsepositives",
        "level",
    ]

    ordered: dict[str, Any] = {}
    for key in key_order:
        if key in rule_dict:
            ordered[key] = rule_dict[key]
    # Append any extra keys not in the canonical order.
    for key, value in rule_dict.items():
        if key not in ordered:
            ordered[key] = value

    return yaml.dump(
        ordered,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=120,
    )
