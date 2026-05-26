"""FETIH Skill Validator — 754 SKILL.md dosyasini tarar, hatalari tespit eder, raporlar.

Kontroller:
  - YAML frontmatter gecerliligi
  - Zorunlu alanlar (name, description, triggers)
  - MITRE ATT&CK ID formati (T\\d{4}(\\.\\d{3})?)
  - NIST CSF ID formati
  - Duplicate name/trigger tespiti
  - Tag tip kontrolu (string olmali)
  - Reference link gecerliligi
  - Ceviri artifact'leri ("Tespit et:", "Detection etme")

Kullanim:
  fetih validate-skills                         -> tum skill'leri tara
  fetih validate-skills --category malware-analysis -> tek kategori
  fetih validate-skills --fix                   -> otomatik duzelt
  fetih validate-skills --report                -> markdown rapor olustur
  fetih validate-skills --json                  -> JSON cikti
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from fetih_constants import get_skills_dir

# ---------------------------------------------------------------------------
# Renk sabitleri
# ---------------------------------------------------------------------------
_RED    = "\033[0;31m"
_GREEN  = "\033[0;32m"
_YELLOW = "\033[0;33m"
_BLUE   = "\033[0;34m"
_CYAN   = "\033[0;36m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_NC     = "\033[0m"

def _c(color: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"{color}{text}{_NC}"
    return text

# ---------------------------------------------------------------------------
# Pattern'ler
# ---------------------------------------------------------------------------
_VALID_MITRE_PATTERN = re.compile(r'^T\d{4}(\.\d{3})?$')

_ARTIFACT_PATTERNS = [
    (re.compile(r'\bTespit\s+et:', re.IGNORECASE), 'tr:Tespit et:'),
    (re.compile(r'\bDetection\s+etme\b', re.IGNORECASE), 'tr:Detection etme'),
    (re.compile(r'\bBul:', re.IGNORECASE), 'tr:Bul:'),
    (re.compile(r'\bSunu\s+olustur:', re.IGNORECASE), 'tr:Sunu olustur:'),
    (re.compile(r'\bBelirle:', re.IGNORECASE), 'tr:Belirle:'),
    (re.compile(r'\bDagit:', re.IGNORECASE), 'tr:Dagit:'),
    (re.compile(r'\bKullanma:', re.IGNORECASE), 'tr:Kullanma:'),
    (re.compile(r'\bBilgi:', re.IGNORECASE), 'tr:Bilgi:'),
    (re.compile(r'\bYeterli\b', re.IGNORECASE), 'tr:Yeterli'),
    (re.compile(r'\bAdim\b', re.IGNORECASE), 'tr:Adim'),
]


# ---------------------------------------------------------------------------
# Check fonksiyonlari
# ---------------------------------------------------------------------------

def _check_yaml_valid(frontmatter: Dict, content: str) -> Tuple[bool, str]:
    if not content.startswith('---'):
        return False, "Frontmatter YAML baslangici (---) bulunamadi"
    end_match = re.search(r'\n---\s*\n', content[3:])
    if not end_match:
        return False, "Frontmatter YAML sonu (---) bulunamadi"
    if not frontmatter:
        return False, "Frontmatter bos veya parse edilemedi"
    return True, ""


def _check_name(frontmatter: Dict) -> Tuple[bool, str]:
    name = frontmatter.get('name')
    if not name:
        return False, "Eksik 'name' alani"
    if not isinstance(name, str):
        return False, f"'name' string olmali, su an: {type(name).__name__}"
    if len(name.strip()) < 3:
        return False, f"'name' cok kisa: '{name}'"
    return True, ""


def _check_description(frontmatter: Dict) -> Tuple[bool, str]:
    desc = frontmatter.get('description')
    if not desc:
        return False, "Eksik 'description' alani"
    if not isinstance(desc, str):
        return False, f"'description' string olmali, su an: {type(desc).__name__}"
    if len(desc.strip()) < 10:
        return False, f"'description' cok kisa ({len(desc)} karakter)"
    return True, ""


def _check_triggers(frontmatter: Dict) -> Tuple[bool, str]:
    triggers = frontmatter.get('triggers', [])
    if not triggers:
        return False, "Eksik veya bos 'triggers' listesi"
    if not isinstance(triggers, list):
        return False, f"'triggers' liste olmali, su an: {type(triggers).__name__}"
    if len(triggers) == 0:
        return False, "'triggers' listesi bos"
    return True, ""


def _check_category(frontmatter: Dict) -> Tuple[bool, str]:
    category = frontmatter.get('category')
    if not category:
        return False, "Eksik 'category' alani"
    return True, ""


def _check_mitre_ids(frontmatter: Dict) -> Tuple[bool, str]:
    mitre = frontmatter.get('mitre_attack', [])
    if not mitre:
        return True, ""
    if not isinstance(mitre, list):
        return False, f"'mitre_attack' liste olmali, su an: {type(mitre).__name__}"
    invalid = []
    for mid in mitre:
        mid_str = str(mid).strip()
        if not _VALID_MITRE_PATTERN.match(mid_str):
            invalid.append(mid_str)
    if invalid:
        return False, f"Gecersiz MITRE ATT&CK ID formati: {', '.join(invalid)}"
    return True, ""


def _check_nist_ids(frontmatter: Dict) -> Tuple[bool, str]:
    nist = frontmatter.get('nist_csf', [])
    if not nist:
        return True, ""
    if not isinstance(nist, list):
        return False, f"'nist_csf' liste olmali, su an: {type(nist).__name__}"
    invalid = []
    for nid in nist:
        nid_str = str(nid).strip()
        if not re.match(r'^[A-Z]{2,4}\.[A-Z]{2,4}-\d{2}$', nid_str):
            invalid.append(nid_str)
    if invalid:
        return False, f"NIST CSF ID formati supheli: {', '.join(invalid)} (beklenen: XX.YY-ZZ)"
    return True, ""


def _check_tags_are_strings(frontmatter: Dict) -> Tuple[bool, str]:
    tags = frontmatter.get('tags', [])
    if not tags:
        return True, ""
    if not isinstance(tags, list):
        return False, f"'tags' liste olmali, su an: {type(tags).__name__}"
    non_strings = []
    for t in tags:
        if not isinstance(t, str):
            non_strings.append(f"{t} ({type(t).__name__})")
    if non_strings:
        return False, f"String olmayan tag'ler: {', '.join(non_strings)}"
    return True, ""


def _check_references(skill_dir: Path) -> Tuple[bool, str]:
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return True, ""
    try:
        content = skill_md.read_text(encoding='utf-8')
    except Exception:
        return True, ""
    refs = re.findall(r'(?:references|scripts)/[^\s)\]]+', content)
    broken = []
    for ref in refs:
        ref_path = skill_dir / ref
        if not ref_path.exists():
            broken.append(ref)
    if broken:
        return False, f"Kirik referans linkleri: {', '.join(broken[:5])}"
    return True, ""


def _check_artifact_patterns(content: str) -> Tuple[bool, str]:
    found = []
    for pattern, label in _ARTIFACT_PATTERNS:
        if pattern.search(content):
            found.append(label)
    if found:
        return False, f"Ceviri artifact'leri: {', '.join(found)}"
    return True, ""


def _check_no_duplicate_name(
    name: str, skill_path: str, all_names: Dict[str, List[str]]
) -> Tuple[bool, str]:
    if name in all_names and len(all_names[name]) > 1:
        others = [p for p in all_names[name] if p != skill_path]
        if others:
            return False, f"Duplicate name '{name}' - diger: {others[0]}"
    return True, ""


# ---------------------------------------------------------------------------
# ValidationResult
# ---------------------------------------------------------------------------

class ValidationResult:
    __slots__ = ('skill_path', 'skill_name', 'errors', 'warnings', 'fixes_applied')

    def __init__(self, skill_path: str, skill_name: str = ""):
        self.skill_path = skill_path
        self.skill_name = skill_name
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.fixes_applied: List[str] = []

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0

    @property
    def is_clean(self) -> bool:
        return not self.has_errors and not self.has_warnings


# ---------------------------------------------------------------------------
# Frontmatter parser
# ---------------------------------------------------------------------------

def _parse_frontmatter_robust(content: str) -> Tuple[Dict[str, Any], str]:
    if not content.startswith('---'):
        return {}, content
    end_match = re.search(r'\n---\s*\n', content[3:])
    if not end_match:
        return {}, content
    yaml_content = content[3:end_match.start() + 3]
    body = content[end_match.end() + 3:]
    try:
        import yaml
        loader = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)
        parsed = yaml.load(yaml_content, Loader=loader)
        if isinstance(parsed, dict):
            return parsed, body
    except Exception:
        pass
    # Fallback: basit key: value parsing
    fm: Dict[str, Any] = {}
    try:
        for line in yaml_content.strip().split('\n'):
            line = line.strip()
            if ':' in line:
                key, _, val = line.partition(':')
                key = key.strip()
                val = val.strip()
                if val.startswith('[') and val.endswith(']'):
                    items = [v.strip().strip('"').strip("'") for v in val[1:-1].split(',')]
                    fm[key] = [i for i in items if i]
                else:
                    fm[key] = val.strip('"').strip("'")
    except Exception:
        pass
    return fm, body


# ---------------------------------------------------------------------------
# Ana validator
# ---------------------------------------------------------------------------

def validate_skill(skill_path: Path, all_names: Dict[str, List[str]]) -> ValidationResult:
    rel_path = str(skill_path)
    result = ValidationResult(rel_path)

    if not skill_path.exists():
        result.errors.append("Dosya bulunamadi")
        return result

    try:
        content = skill_path.read_text(encoding='utf-8')
    except Exception as e:
        result.errors.append(f"Dosya okunamadi: {e}")
        return result

    frontmatter, body = _parse_frontmatter_robust(content)

    ok, msg = _check_yaml_valid(frontmatter, content)
    if not ok:
        result.errors.append(msg)
        return result

    name = str(frontmatter.get('name', ''))
    result.skill_name = name

    ok, msg = _check_name(frontmatter)
    if not ok:
        result.errors.append(msg)

    ok, msg = _check_description(frontmatter)
    if not ok:
        result.errors.append(msg)

    ok, msg = _check_triggers(frontmatter)
    if not ok:
        result.errors.append(msg)

    ok, msg = _check_category(frontmatter)
    if not ok:
        result.warnings.append(msg)

    ok, msg = _check_mitre_ids(frontmatter)
    if not ok:
        result.errors.append(msg)

    ok, msg = _check_nist_ids(frontmatter)
    if not ok:
        result.warnings.append(msg)

    ok, msg = _check_tags_are_strings(frontmatter)
    if not ok:
        result.errors.append(msg)

    ok, msg = _check_no_duplicate_name(name, rel_path, all_names)
    if not ok:
        result.warnings.append(msg)

    if 'orchestrator' not in name.lower():
        ok, msg = _check_references(skill_path.parent)
        if not ok:
            result.warnings.append(msg)

    ok, msg = _check_artifact_patterns(content)
    if not ok:
        result.warnings.append(msg)

    return result


def _auto_fix_skill(skill_path: Path, result: ValidationResult) -> int:
    fix_count = 0
    try:
        content = skill_path.read_text(encoding='utf-8')
    except Exception:
        return 0

    original = content
    frontmatter, body = _parse_frontmatter_robust(content)

    # Fix 1: Eksik category -> parent dizin adi
    if not frontmatter.get('category') and 'category' in str(skill_path.parent):
        cat = skill_path.parent.name
        if content.startswith('---'):
            end_idx = content.find('---', 3)
            if end_idx > 0:
                new_fm = content[:end_idx].rstrip() + f'\ncategory: {cat}\n'
                content = new_fm + content[end_idx:]
                fix_count += 1
                result.fixes_applied.append(f"category: {cat} (otomatik)")

    # Fix 2: Tag'leri string'e cevir
    tags = frontmatter.get('tags', [])
    if tags and any(not isinstance(t, str) for t in tags):
        fixed_tags = [str(t) for t in tags]
        tag_lines = '\n'.join(f'  - {t}' for t in fixed_tags)
        content = re.sub(
            r'tags:\s*\n(\s*-\s+[^\n]+\n)*',
            f'tags:\n{tag_lines}\n',
            content
        )
        fix_count += 1
        result.fixes_applied.append("tags string'e cevrildi")

    if content != original:
        try:
            skill_path.write_text(content, encoding='utf-8')
        except Exception:
            pass

    return fix_count


def validate_all_skills(
    skills_dir: Optional[Path] = None,
    category: Optional[str] = None,
    auto_fix: bool = False,
) -> Tuple[List[ValidationResult], Dict[str, int]]:
    if skills_dir is None:
        skills_dir = get_skills_dir()

    results: List[ValidationResult] = []
    skill_files: List[Path] = []

    for root, dirs, files in os.walk(str(skills_dir)):
        dirs[:] = [d for d in dirs if d not in ('.git', '.github', '.hub', '.archive')]
        if 'SKILL.md' in files:
            skill_path = Path(root) / 'SKILL.md'
            if category:
                rel = skill_path.relative_to(skills_dir)
                if category not in str(rel):
                    continue
            skill_files.append(skill_path)

    # Duplicate name tespiti
    all_names: Dict[str, List[str]] = defaultdict(list)
    for sf in skill_files:
        try:
            content = sf.read_text(encoding='utf-8')
            fm, _ = _parse_frontmatter_robust(content)
            name = str(fm.get('name', ''))
            if name:
                all_names[name].append(str(sf))
        except Exception:
            pass

    for sf in skill_files:
        result = validate_skill(sf, all_names)
        if auto_fix and (result.has_errors or result.has_warnings):
            fixed = _auto_fix_skill(sf, result)
            if fixed > 0:
                result = validate_skill(sf, all_names)
                if not result.fixes_applied:
                    result.fixes_applied.append(f"{fixed} duzeltme uygulandi")
        results.append(result)

    stats = {
        'total': len(results),
        'clean': sum(1 for r in results if r.is_clean),
        'errors': sum(1 for r in results if r.has_errors),
        'warnings': sum(1 for r in results if r.has_warnings and not r.has_errors),
        'fixed': sum(1 for r in results if r.fixes_applied),
        'total_errors': sum(len(r.errors) for r in results),
        'total_warnings': sum(len(r.warnings) for r in results),
    }
    return results, stats


# ---------------------------------------------------------------------------
# Cikti formatlayicilari
# ---------------------------------------------------------------------------

def print_results(results: List[ValidationResult], stats: Dict[str, int]):
    total = stats['total']
    clean = stats['clean']
    errors = stats['errors']
    warnings = stats['warnings']
    fixed = stats['fixed']
    total_errs = stats['total_errors']
    total_warns = stats['total_warnings']

    print()
    print(_c(_BOLD, "+" + "-" * 50 + "+"))
    print(_c(_BOLD, "|" + "  FETIH Skill Validator - Sonuclar".ljust(48) + "  |"))
    print(_c(_BOLD, "+" + "-" * 50 + "+"))
    print()
    print(f"  Toplam skill:  {_c(_CYAN, str(total))}")
    print(f"  Temiz:         {_c(_GREEN, str(clean))} ({clean*100//max(total,1)}%)")
    if warnings:
        print(f"  Uyarili:       {_c(_YELLOW, str(warnings))} ({warnings*100//max(total,1)}%)")
    if errors:
        print(f"  Hatali:        {_c(_RED, str(errors))} ({errors*100//max(total,1)}%)")
    if fixed:
        print(f"  Duzeltilen:    {_c(_GREEN, str(fixed))}")
    print(f"  Toplam hata:   {_c(_RED if total_errs else _DIM, str(total_errs))}")
    print(f"  Toplam uyari:  {_c(_YELLOW if total_warns else _DIM, str(total_warns))}")
    print()

    error_results = [r for r in results if r.has_errors]
    if error_results:
        print(_c(_RED + _BOLD, "--- Hatalar ---"))
        print()
        for r in error_results:
            print(f"  {_c(_RED, 'X')} {_c(_BOLD, r.skill_path)}")
            if r.skill_name:
                print(f"    {_c(_DIM, f'Skill: {r.skill_name}')}")
            for e in r.errors:
                print(f"    {_c(_RED, '->')} {e}")
            print()

    warn_results = [r for r in results if r.has_warnings and not r.has_errors]
    if warn_results:
        print(_c(_YELLOW + _BOLD, "--- Uyarilar ---"))
        print()
        for r in warn_results:
            print(f"  {_c(_YELLOW, '/!\\')} {_c(_BOLD, r.skill_path)}")
            if r.skill_name:
                print(f"    {_c(_DIM, f'Skill: {r.skill_name}')}")
            for w in r.warnings:
                print(f"    {_c(_YELLOW, '->')} {w}")
            print()

    fixed_results = [r for r in results if r.fixes_applied]
    if fixed_results:
        print(_c(_GREEN + _BOLD, "--- Otomatik Duzeltmeler ---"))
        print()
        for r in fixed_results:
            print(f"  {_c(_GREEN, '/')} {r.skill_path}")
            for f in r.fixes_applied:
                print(f"    {_c(_GREEN, 'v')} {f}")
            print()

    print(_c(_BOLD, "-" * 52))
    if errors == 0 and warnings == 0:
        print(_c(_GREEN + _BOLD, f"  Tum {total} skill hatasiz!"))
    elif errors == 0:
        print(_c(_YELLOW, f"  {total} skill tarandi, {warnings} uyari var, kritik hata yok."))
    else:
        print(_c(_RED, f"  {errors} skill'de kritik hata var! Duzeltilmesi onerilir."))
    print()


def generate_markdown_report(results: List[ValidationResult], stats: Dict[str, int]) -> str:
    from datetime import datetime
    lines = [
        "# FETIH Skill Validation Report",
        f"\n**Tarih:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "\n## Ozet\n",
        "| Metrik | Deger |",
        "|--------|-------|",
        f"| Toplam skill | {stats['total']} |",
        f"| Temiz | {stats['clean']} ({stats['clean']*100//max(stats['total'],1)}%) |",
        f"| Uyarili | {stats['warnings']} |",
        f"| Hatali | {stats['errors']} |",
        f"| Toplam hata | {stats['total_errors']} |",
        f"| Toplam uyari | {stats['total_warnings']} |",
    ]
    if stats['fixed']:
        lines.append(f"| Otomatik duzeltilen | {stats['fixed']} |")

    error_results = [r for r in results if r.has_errors]
    if error_results:
        lines.append(f"\n## Hatalar ({len(error_results)})\n")
        for r in error_results:
            lines.append(f"### {r.skill_name or r.skill_path}")
            lines.append(f"- **Dosya:** `{r.skill_path}`")
            for e in r.errors:
                lines.append(f"- :x: {e}")
            lines.append("")

    warn_results = [r for r in results if r.has_warnings and not r.has_errors]
    if warn_results:
        lines.append(f"\n## Uyarilar ({len(warn_results)})\n")
        for r in warn_results:
            lines.append(f"### {r.skill_name or r.skill_path}")
            lines.append(f"- **Dosya:** `{r.skill_path}`")
            for w in r.warnings:
                lines.append(f"- :warning: {w}")
            lines.append("")

    if not error_results and not warn_results:
        lines.append(f"\n:tada: **Tum {stats['total']} skill hatasiz!**\n")

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# CLI / Slash entry points
# ---------------------------------------------------------------------------

def run_validator(
    category: Optional[str] = None,
    auto_fix: bool = False,
    report: bool = False,
    json_output: bool = False,
    skills_dir: Optional[Path] = None,
) -> int:
    if skills_dir is None:
        skills_dir = get_skills_dir()
    if not skills_dir.exists():
        print(_c(_RED, f"Hata: Skills dizini bulunamadi: {skills_dir}"))
        return 2

    print(_c(_CYAN, f"Skills dizini: {skills_dir}"))
    if category:
        print(_c(_CYAN, f"Kategori filtresi: {category}"))
    print(_c(_DIM, "Taranıyor..."))

    results, stats = validate_all_skills(skills_dir, category, auto_fix)

    if json_output:
        data = {
            'stats': stats,
            'results': [
                {
                    'path': r.skill_path, 'name': r.skill_name,
                    'errors': r.errors, 'warnings': r.warnings,
                    'fixes_applied': r.fixes_applied, 'clean': r.is_clean,
                }
                for r in results
            ]
        }
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print_results(results, stats)
        if report:
            report_path = Path('/tmp/fetih-skill-validation-report.md')
            report_path.write_text(generate_markdown_report(results, stats), encoding='utf-8')
            print(_c(_GREEN, f"  Markdown raporu: {report_path}"))

    if stats['errors'] > 0:
        return 2
    elif stats['warnings'] > 0:
        return 1
    return 0


def cmd_validate_skills(args):
    return run_validator(
        category=getattr(args, 'category', None),
        auto_fix=getattr(args, 'fix', False),
        report=getattr(args, 'report', False),
        json_output=getattr(args, 'json', False),
    )


def handle_validate_skills_slash(cmd: str) -> int:
    parts = cmd.strip().split()
    args_list = parts[1:] if len(parts) > 1 else []

    category = None
    auto_fix = False
    report = False
    json_output = False

    i = 0
    while i < len(args_list):
        arg = args_list[i]
        if arg == '--category' and i + 1 < len(args_list):
            category = args_list[i + 1]
            i += 2
        elif arg == '--fix':
            auto_fix = True
            i += 1
        elif arg == '--report':
            report = True
            i += 1
        elif arg == '--json':
            json_output = True
            i += 1
        else:
            i += 1

    return run_validator(category, auto_fix, report, json_output)
