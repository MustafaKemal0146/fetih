"""Skill validator: health check for all SKILL.md files.

Scans the skills directory and validates every SKILL.md for:
  - Valid YAML frontmatter
  - Required fields (name, description, triggers, category)
  - Valid MITRE ATT&CK IDs (T####.### format)
  - Duplicate triggers across skills
  - Duplicate names across skills
  - Broken /references/ links
  - Translation artifacts (common pattern from language models)
  - Tags that are strings (not numeric)

Usage:
  fetih validate-skills               Scan all skills
  fetih validate-skills --category X  Scan specific category
  fetih validate-skills --fix         Auto-fix correctable issues
  fetih validate-skills --report      Generate detailed markdown report
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SKILLS_DIR = Path(os.environ.get(
    "FETIH_SKILLS_DIR",
    str(Path(__file__).resolve().parent.parent / "skills")
))

# Valid MITRE ATT&CK ID pattern: T#### or T####.###
MITRE_ID_RE = re.compile(r'^T\d{4}(\.\d{3})?$')

# Valid NIST CSF ID pattern
NIST_ID_RE = re.compile(r'^[A-Z]{2,3}\.(?:[A-Z]{2,3}-\d+|[A-Z]{2,3})$')

# Translation artifact patterns (concerning signals from LLM-generated content)
ARTIFACT_PATTERNS = [
    (re.compile(r'\b(Tespit et:|Detection etme:|Tespit etmek)', re.IGNORECASE),
     "Translation artifact: Turkish-English mix"),
    (re.compile(r'\b(İlk olarak|Öncelikle|Sonuç olarak|Bu nedenle)\b', re.IGNORECASE),
     "Filler phrase (consider removing)"),
]

# Required frontmatter fields
REQUIRED_FIELDS = {"name", "description", "triggers"}

# Recommended frontmatter fields
RECOMMENDED_FIELDS = {"category", "tags", "mitre_ids", "nist_ids", "references"}


# ---------------------------------------------------------------------------
# Validation result types
# ---------------------------------------------------------------------------

class SkillIssue:
    """A single validation issue."""
    __slots__ = ("level", "skill_path", "field", "message", "fixable")

    def __init__(self, level: str, skill_path: str, field: str, message: str, fixable: bool = False):
        self.level = level       # "error", "warning", "info"
        self.skill_path = skill_path
        self.field = field
        self.message = message
        self.fixable = fixable


class ValidationResult:
    """Aggregate result for a single skill."""
    __slots__ = ("skill_path", "name", "category", "issues", "frontmatter")

    def __init__(self, skill_path: str):
        self.skill_path = skill_path
        self.name = ""
        self.category = ""
        self.issues: List[SkillIssue] = []
        self.frontmatter: Dict[str, Any] = {}

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.level == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.level == "warning")

    @property
    def has_errors(self) -> bool:
        return any(i.level == "error" for i in self.issues)


# ---------------------------------------------------------------------------
# YAML frontmatter parser (no PyYAML dependency needed for simple checks)
# ---------------------------------------------------------------------------

def _parse_frontmatter(content: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Parse YAML frontmatter from SKILL.md content.

    Returns (parsed_dict, error_message). Uses simple regex-based parsing
    for basic type inference; doesn't require PyYAML.
    """
    # Match ---\n...\n---
    match = re.match(r'^---\s*\n(.*?)\n---\s*\n', content, re.DOTALL)
    if not match:
        return None, "No YAML frontmatter (--- blocks) found"

    yaml_text = match.group(1)

    data: Dict[str, Any] = {}
    current_key = None
    current_list: List[str] = []

    for line in yaml_text.split("\n"):
        # Skip empty lines and comments
        if not line.strip() or line.strip().startswith("#"):
            if current_list and current_key:
                data[current_key] = current_list
                current_list = []
                current_key = None
            continue

        # List item
        list_match = re.match(r'^\s+-\s+(.+)', line)
        if list_match:
            current_list.append(list_match.group(1).strip())
            continue

        # Flush current list
        if current_list and current_key:
            data[current_key] = current_list
            current_list = []
            current_key = None

        # Key: value
        kv_match = re.match(r'^(\w[\w_-]*)\s*:\s*(.*)', line)
        if kv_match:
            key = kv_match.group(1)
            value = kv_match.group(2).strip()

            # Unquoted null/true/false
            if value.lower() in ("true", "yes", "on"):
                value_parsed: Any = True
            elif value.lower() in ("false", "no", "off"):
                value_parsed = False
            elif value.lower() in ("null", "~", ""):
                value_parsed = None
            else:
                # Remove surrounding quotes
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value_parsed = value[1:-1]
                else:
                    value_parsed = value

            data[key] = value_parsed
            current_key = key

    # Flush remaining list
    if current_list and current_key:
        data[current_key] = current_list

    return data, None


# ---------------------------------------------------------------------------
# Validation checks
# ---------------------------------------------------------------------------

def _validate_skill(skill_path: Path) -> ValidationResult:
    """Validate a single SKILL.md file."""
    result = ValidationResult(str(skill_path))

    try:
        content = skill_path.read_text(encoding="utf-8")
    except Exception as e:
        result.issues.append(SkillIssue("error", str(skill_path), "file", f"Cannot read: {e}"))
        return result

    # Parse frontmatter
    frontmatter, fm_error = _parse_frontmatter(content)
    if fm_error:
        result.issues.append(SkillIssue("error", str(skill_path), "frontmatter", fm_error, True))
        return result

    if frontmatter is None:
        result.issues.append(SkillIssue("error", str(skill_path), "frontmatter", "Empty or missing frontmatter"))
        return result

    result.frontmatter = frontmatter

    # Required fields
    result.name = frontmatter.get("name", "")
    for field in REQUIRED_FIELDS:
        if field not in frontmatter or not frontmatter[field]:
            result.issues.append(SkillIssue(
                "error", str(skill_path), field,
                f"Missing required field: '{field}'",
                fixable=(field == "category"),
            ))

    # Category auto-inference
    if "category" not in frontmatter or not frontmatter.get("category"):
        # Try to infer from path
        path_str = str(skill_path)
        for cat in ["cybersecurity", "ctf", "osint", "pentest", "exploitation",
                     "malware-analysis", "cloud-security", "web-security",
                     "steganography", "cryptography", "forensics", "reversing",
                     "mobile-security", "iot-security", "network-security"]:
            if cat in path_str.lower():
                result.issues.append(SkillIssue(
                    "warning", str(skill_path), "category",
                    f"Missing category — auto-detected as '{cat}'",
                    fixable=True,
                ))
                result.category = cat
                break
        else:
            result.category = ""
    else:
        result.category = str(frontmatter.get("category", ""))

    # Description quality
    desc = str(frontmatter.get("description", ""))
    if desc and len(desc) < 10:
        result.issues.append(SkillIssue(
            "warning", str(skill_path), "description",
            f"Description too short ({len(desc)} chars)",
        ))

    # MITRE ATT&CK ID validation
    mitre_ids = frontmatter.get("mitre_ids")
    if mitre_ids is None:
        mitre_ids = []
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]
    for mid in mitre_ids:
        if not MITRE_ID_RE.match(str(mid)):
            result.issues.append(SkillIssue(
                "warning", str(skill_path), "mitre_ids",
                f"Invalid MITRE ATT&CK ID format: '{mid}' (expected T####.###)",
            ))

    # NIST CSF ID validation
    nist_ids = frontmatter.get("nist_ids")
    if nist_ids is None:
        nist_ids = []
    if isinstance(nist_ids, str):
        nist_ids = [nist_ids]
    for nid in nist_ids:
        if not NIST_ID_RE.match(str(nid)):
            result.issues.append(SkillIssue(
                "info", str(skill_path), "nist_ids",
                f"Possibly invalid NIST CSF ID: '{nid}'",
            ))

    # Trigger validation
    triggers = frontmatter.get("triggers")
    if triggers is None:
        triggers = []
    if isinstance(triggers, str):
        triggers = [triggers]
    if not triggers:
        result.issues.append(SkillIssue(
            "error", str(skill_path), "triggers",
            "No triggers defined",
        ))
    else:
        # Check for empty triggers
        for t in triggers:
            if not str(t).strip():
                result.issues.append(SkillIssue(
                    "error", str(skill_path), "triggers",
                    "Empty trigger string found",
                ))

    # Tags validation
    tags = frontmatter.get("tags")
    if tags is None:
        tags = []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    for tag in tags:
        tag_str = str(tag)
        if tag_str.isdigit():
            result.issues.append(SkillIssue(
                "warning", str(skill_path), "tags",
                f"Numeric tag found: '{tag_str}' (should be a string keyword)",
                fixable=True,
            ))

    # Translation artifact check
    for pattern, label in ARTIFACT_PATTERNS:
        if pattern.search(content):
            result.issues.append(SkillIssue(
                "info", str(skill_path), "content",
                f"Translation artifact detected: {label}",
            ))

    # Reference link validation
    ref_links = re.findall(r'\[.*?\]\((\.?/?references/[^)]+)\)', content)
    for link in ref_links:
        ref_path = (skill_path.parent / link).resolve()
        if not ref_path.exists():
            result.issues.append(SkillIssue(
                "warning", str(skill_path), "references",
                f"Broken reference link: {link}",
            ))

    return result


# ---------------------------------------------------------------------------
# Cross-skill validation
# ---------------------------------------------------------------------------

def _cross_validate(results: List[ValidationResult]) -> List[SkillIssue]:
    """Check for duplicate names and triggers across skills."""
    issues: List[SkillIssue] = []

    # Duplicate names
    name_counter = Counter(r.name for r in results if r.name)
    for name, count in name_counter.items():
        if count > 1:
            dupes = [r.skill_path for r in results if r.name == name]
            issues.append(SkillIssue(
                "error", dupes[0], "name",
                f"Duplicate skill name '{name}' in {count} files: {', '.join(dupes)}",
            ))

    # Duplicate triggers
    trigger_map: Dict[str, List[str]] = defaultdict(list)
    for r in results:
        triggers = r.frontmatter.get("triggers")
        if triggers is None:
            triggers = []
        if isinstance(triggers, str):
            triggers = [triggers]
        for t in triggers:
            t_lower = str(t).lower().strip()
            if t_lower:
                trigger_map[t_lower].append(r.skill_path)

    for trigger, paths in trigger_map.items():
        if len(paths) > 3:  # More than 3 skills sharing same trigger
            issues.append(SkillIssue(
                "warning", paths[0], "triggers",
                f"Trigger '{trigger}' shared by {len(paths)} skills — consider making more specific",
            ))

    # Ambiguous triggers (too short)
    for trigger, paths in trigger_map.items():
        if len(trigger) < 5 and len(paths) > 1:
            issues.append(SkillIssue(
                "info", paths[0], "triggers",
                f"Very short trigger '{trigger}' ({len(trigger)} chars) shared by {len(paths)} skills",
            ))

    return issues


# ---------------------------------------------------------------------------
# Auto-fix
# ---------------------------------------------------------------------------

def _auto_fix_skill(skill_path: Path, result: ValidationResult) -> int:
    """Auto-fix fixable issues in a skill. Returns number of fixes applied."""
    fixes = 0
    fixable_issues = [i for i in result.issues if i.fixable]

    if not fixable_issues:
        return 0

    try:
        content = skill_path.read_text(encoding="utf-8")
        new_content = content

        for issue in fixable_issues:
            if issue.field == "category" and result.category:
                # Add category field to frontmatter
                new_content = re.sub(
                    r'(^---\s*\n)',
                    f'\\1category: {result.category}\n',
                    new_content,
                    count=1,
                )
                fixes += 1

            if issue.field == "tags" and "numeric tag" in issue.message:
                # Convert numeric tags to strings
                # This requires more careful editing; skip for now
                pass

        if new_content != content:
            skill_path.write_text(new_content, encoding="utf-8")
            logger.info("Auto-fixed %d issues in %s", fixes, skill_path)
    except Exception as e:
        logger.warning("Auto-fix failed for %s: %s", skill_path, e)

    return fixes


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------

def validate_skills(
    category: str = "",
    auto_fix: bool = False,
    skills_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Validate all SKILL.md files.

    Returns a summary dict with total stats, issues by level, and a detailed
    report if --report is passed.
    """
    base_dir = skills_dir or SKILLS_DIR
    if not base_dir.exists():
        return {"error": f"Skills directory not found: {base_dir}", "total": 0}

    # Find all SKILL.md files
    skill_files = list(base_dir.glob("**/SKILL.md"))

    if category:
        skill_files = [f for f in skill_files if category in str(f).lower()]

    total = len(skill_files)
    results: List[ValidationResult] = []
    error_count = 0
    warning_count = 0
    info_count = 0
    total_fixes = 0

    # Validate each skill
    for skill_path in skill_files:
        result = _validate_skill(skill_path)
        results.append(result)

        error_count += result.error_count
        warning_count += result.warning_count

        if auto_fix and result.has_errors:
            fixes = _auto_fix_skill(skill_path, result)
            total_fixes += fixes

    # Cross-validation
    cross_issues = _cross_validate(results)
    for issue in cross_issues:
        if issue.level == "error":
            error_count += 1
        elif issue.level == "warning":
            warning_count += 1
        else:
            info_count += 1

    # Build result
    error_skills = [r for r in results if r.has_errors]
    warning_skills = [r for r in results if r.warning_count > 0]

    return {
        "total": total,
        "passed": total - len(error_skills),
        "errors": error_count,
        "warnings": warning_count,
        "info": info_count,
        "fixes_applied": total_fixes,
        "error_skills": [
            {"path": r.skill_path, "name": r.name, "count": r.error_count}
            for r in error_skills
        ],
        "warning_skills": [
            {"path": r.skill_path, "name": r.name, "count": r.warning_count}
            for r in warning_skills[:20]  # Top 20
        ],
        "cross_issues": [
            {"level": i.level, "field": i.field, "message": i.message}
            for i in cross_issues
        ],
        "detailed_issues": [
            {
                "level": i.level,
                "skill": os.path.relpath(r.skill_path, str(base_dir)),
                "field": i.field,
                "message": i.message,
            }
            for r in error_skills
            for i in r.issues
            if i.level in ("error", "warning")
        ][:100],  # Cap at 100 detailed issues
    }


def generate_report(summary: Dict[str, Any], output_path: Optional[Path] = None) -> str:
    """Generate a detailed markdown validation report."""
    lines = [
        f"# FETIH Skill Validation Report",
        f"**Generated:** {datetime.now().isoformat()[:19]}",
        f"",
        f"## Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total skills scanned | {summary.get('total', 0)} |",
        f"| Passed ✅ | {summary.get('passed', 0)} |",
        f"| Errors ❌ | {summary.get('errors', 0)} |",
        f"| Warnings ⚠️ | {summary.get('warnings', 0)} |",
        f"| Info ℹ️ | {summary.get('info', 0)} |",
        f"| Auto-fixes applied | {summary.get('fixes_applied', 0)} |",
        f"",
    ]

    # Error skills
    if summary.get("error_skills"):
        lines.append("## Skills with Errors ❌")
        lines.append("")
        for sk in summary["error_skills"]:
            lines.append(f"- **{sk['name'] or 'unnamed'}** ({sk['count']} errors): `{sk['path']}`")
        lines.append("")

    # Warning skills
    if summary.get("warning_skills"):
        lines.append("## Skills with Warnings ⚠️")
        lines.append("")
        for sk in summary["warning_skills"]:
            lines.append(f"- **{sk['name'] or 'unnamed'}** ({sk['count']} warnings): `{sk['path']}`")
        lines.append("")

    # Cross-validation issues
    if summary.get("cross_issues"):
        lines.append("## Cross-Skill Issues 🔗")
        lines.append("")
        for issue in summary["cross_issues"]:
            emoji = {"error": "❌", "warning": "⚠️", "info": "ℹ️"}.get(issue["level"], "•")
            lines.append(f"- {emoji} **{issue['field']}**: {issue['message']}")
        lines.append("")

    # Detailed issues
    if summary.get("detailed_issues"):
        lines.append("## Detailed Issues (first 100)")
        lines.append("")
        lines.append("| Level | Skill | Field | Issue |")
        lines.append("|-------|-------|-------|-------|")
        for issue in summary["detailed_issues"]:
            emoji = {"error": "❌", "warning": "⚠️", "info": "ℹ️"}.get(issue["level"], "•")
            skill_short = issue["skill"].split("/")[-2] if "/" in issue["skill"] else issue["skill"]
            lines.append(
                f"| {emoji} | {skill_short} | {issue['field']} | "
                f"{issue['message'][:100]} |"
            )
        lines.append("")

    report = "\n".join(lines)

    if output_path:
        try:
            output_path.write_text(report, encoding="utf-8")
            logger.info("Report written to %s", output_path)
        except Exception as e:
            logger.warning("Failed to write report: %s", e)

    return report


# ---------------------------------------------------------------------------
# CLI entry point (called by cli.py's _handle_validate_skills_command)
# ---------------------------------------------------------------------------

def handle_validate_skills_slash(cmd: str) -> int:
    """Handle /validate-skills slash command. Returns exit code (0=clean)."""
    parts = cmd.strip().split()
    category = ""
    auto_fix = False
    do_report = False

    i = 1
    while i < len(parts):
        if parts[i] == "--category" and i + 1 < len(parts):
            category = parts[i + 1]
            i += 2
        elif parts[i] == "--fix":
            auto_fix = True
            i += 1
        elif parts[i] == "--report":
            do_report = True
            i += 1
        elif parts[i] == "--json":
            i += 1  # Handled in caller
        elif parts[i] in (
            "malware-analysis", "cloud-security", "threat-hunting",
            "web-application-security", "network-security", "incident-response",
            "vulnerability-assessment", "penetration-testing", "exploitation",
        ):
            category = parts[i]
            i += 1
        else:
            i += 1

    print("═══ FETIH Skill Validator ═══")
    summary = validate_skills(category=category, auto_fix=auto_fix)

    total = summary.get("total", 0)
    errors = summary.get("errors", 0)
    warnings = summary.get("warnings", 0)
    passed = summary.get("passed", 0)

    # Progress
    pct = (passed / total * 100) if total > 0 else 0
    print(f"Toplam skill: {total}")
    print(f"✓ Gecen: {passed} ({pct:.1f}%)")
    if errors > 0:
        print(f"✗ Hata: {errors}")
    if warnings > 0:
        print(f"⚠ Uyari: {warnings}")
    if summary.get("fixes_applied", 0) > 0:
        print(f"🔧 Otomatik duzeltme: {summary['fixes_applied']}")

    # Show error skills
    if summary.get("error_skills"):
        print("\n─── Hatalı Skill'ler ✗ ───")
        for sk in summary["error_skills"]:
            print(f"  ✗ {sk['name'] or 'unnamed'}: {sk['path']}")

    # Cross-issues
    if summary.get("cross_issues"):
        print("\n─── Çapraz Sorunlar ───")
        for issue in summary["cross_issues"][:10]:
            emoji = {"error": "✗", "warning": "⚠", "info": "ℹ️"}.get(issue["level"], "•")
            print(f"  {emoji} {issue['message'][:120]}")

    # Generate report if requested
    if do_report:
        output_path = Path(os.environ.get("FETIH_HOME", os.path.expanduser("~/.fetih"))) / "skill_validation_report.md"
        report = generate_report(summary, output_path)
        print(f"\nDetayli rapor: {output_path}")

    return 0 if errors == 0 else 1
