"""Lightweight skill metadata utilities shared by prompt_builder and skills_tool.

This module intentionally avoids importing the tool registry, CLI config, or any
heavy dependency chain.  It is safe to import at module level without triggering
tool registration or provider resolution.
"""

import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from fetih_constants import get_config_path, get_skills_dir

logger = logging.getLogger(__name__)

# ── Platform mapping ──────────────────────────────────────────────────────

PLATFORM_MAP = {
    "macos": "darwin",
    "linux": "linux",
    "windows": "win32",
}

EXCLUDED_SKILL_DIRS = frozenset((".git", ".github", ".hub", ".archive"))

# ── Lazy YAML loader ─────────────────────────────────────────────────────

_yaml_load_fn = None


def yaml_load(content: str):
    """Parse YAML with lazy import and CSafeLoader preference."""
    global _yaml_load_fn
    if _yaml_load_fn is None:
        import yaml

        loader = getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader

        def _load(value: str):
            return yaml.load(value, Loader=loader)

        _yaml_load_fn = _load
    return _yaml_load_fn(content)


# ── Frontmatter parsing ──────────────────────────────────────────────────


def parse_frontmatter(content: str) -> Tuple[Dict[str, Any], str]:
    """Parse YAML frontmatter from a markdown string.

    Uses yaml with CSafeLoader for full YAML support (nested metadata, lists)
    with a fallback to simple key:value splitting for robustness.

    Returns:
        (frontmatter_dict, remaining_body)
    """
    frontmatter: Dict[str, Any] = {}
    body = content

    if not content.startswith("---"):
        return frontmatter, body

    end_match = re.search(r"\n---\s*\n", content[3:])
    if not end_match:
        return frontmatter, body

    yaml_content = content[3 : end_match.start() + 3]
    body = content[end_match.end() + 3 :]

    try:
        parsed = yaml_load(yaml_content)
        if isinstance(parsed, dict):
            frontmatter = parsed
    except Exception:
        # Fallback: simple key:value parsing for malformed YAML
        for line in yaml_content.strip().split("\n"):
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            frontmatter[key.strip()] = value.strip()

    return frontmatter, body


# ── Platform matching ─────────────────────────────────────────────────────


def skill_matches_platform(frontmatter: Dict[str, Any]) -> bool:
    """Return True when the skill is compatible with the current OS.

    Skills declare platform requirements via a top-level ``platforms`` list
    in their YAML frontmatter::

        platforms: [macos]          # macOS only
        platforms: [macos, linux]   # macOS and Linux

    If the field is absent or empty the skill is compatible with **all**
    platforms (backward-compatible default).
    """
    platforms = frontmatter.get("platforms")
    if not platforms:
        return True
    if not isinstance(platforms, list):
        platforms = [platforms]
    current = sys.platform
    for platform in platforms:
        normalized = str(platform).lower().strip()
        mapped = PLATFORM_MAP.get(normalized, normalized)
        if current.startswith(mapped):
            return True
    return False


# ── Disabled skills ───────────────────────────────────────────────────────


def get_disabled_skill_names(platform: str | None = None) -> Set[str]:
    """Read disabled skill names from config.yaml.

    Args:
        platform: Explicit platform name (e.g. ``"telegram"``).  When
            *None*, resolves from ``FETIH_PLATFORM`` or
            ``FETIH_SESSION_PLATFORM`` env vars.  Falls back to the
            global disabled list when no platform is determined.

    Reads the config file directly (no CLI config imports) to stay
    lightweight.
    """
    config_path = get_config_path()
    if not config_path.exists():
        return set()
    try:
        parsed = yaml_load(config_path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug("Could not read skill config %s: %s", config_path, e)
        return set()
    if not isinstance(parsed, dict):
        return set()

    skills_cfg = parsed.get("skills")
    if not isinstance(skills_cfg, dict):
        return set()

    from gateway.session_context import get_session_env
    resolved_platform = (
        platform
        or os.getenv("FETIH_PLATFORM")
        or get_session_env("FETIH_SESSION_PLATFORM")
    )
    if resolved_platform:
        platform_disabled = (skills_cfg.get("platform_disabled") or {}).get(
            resolved_platform
        )
        if platform_disabled is not None:
            return _normalize_string_set(platform_disabled)
    return _normalize_string_set(skills_cfg.get("disabled"))


def _normalize_string_set(values) -> Set[str]:
    if values is None:
        return set()
    if isinstance(values, str):
        values = [values]
    return {str(v).strip() for v in values if str(v).strip()}


# ── External skills directories ──────────────────────────────────────────

# (config_path_str, mtime_ns) -> resolved external dirs list.  Keyed by
# mtime_ns so a config.yaml edit mid-run is picked up automatically;
# otherwise every call would re-read + re-YAML-parse the 15KB config,
# which becomes the dominant cost of ``fetih`` startup when ~120 skills
# each trigger a category lookup during banner construction (10+ seconds
# of pure waste).
_EXTERNAL_DIRS_CACHE: Dict[Tuple[str, int], List[Path]] = {}


def _external_dirs_cache_clear() -> None:
    """Test hook — drop the in-process cache."""
    _EXTERNAL_DIRS_CACHE.clear()


def get_external_skills_dirs() -> List[Path]:
    """Read ``skills.external_dirs`` from config.yaml and return validated paths.

    Each entry is expanded (``~`` and ``${VAR}``) and resolved to an absolute
    path.  Only directories that actually exist are returned.  Duplicates and
    paths that resolve to the local ``~/.fetih/skills/`` are silently skipped.

    Cached in-process, keyed on ``config.yaml`` mtime — the function is
    called once per skill during banner / tool-registry scans, and YAML
    parsing a non-trivial config dominates ``fetih`` cold-start time
    when the cache is absent.
    """
    config_path = get_config_path()
    if not config_path.exists():
        return []

    # Cache key: (absolute path, mtime_ns).  stat() is ~2us vs ~85ms for
    # the full YAML parse, so the fast path is nearly free.
    try:
        stat = config_path.stat()
        cache_key: Tuple[str, int] = (str(config_path), stat.st_mtime_ns)
    except OSError:
        cache_key = None  # type: ignore[assignment]

    if cache_key is not None:
        cached = _EXTERNAL_DIRS_CACHE.get(cache_key)
        if cached is not None:
            # Return a copy so callers can't mutate the cached list.
            return list(cached)

    try:
        parsed = yaml_load(config_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(parsed, dict):
        return []

    skills_cfg = parsed.get("skills")
    if not isinstance(skills_cfg, dict):
        return []

    raw_dirs = skills_cfg.get("external_dirs")
    if not raw_dirs:
        result: List[Path] = []
        if cache_key is not None:
            _EXTERNAL_DIRS_CACHE[cache_key] = list(result)
        return result
    if isinstance(raw_dirs, str):
        raw_dirs = [raw_dirs]
    if not isinstance(raw_dirs, list):
        return []

    from fetih_constants import get_fetih_home

    fetih_home = get_fetih_home()
    local_skills = get_skills_dir().resolve()
    seen: Set[Path] = set()
    result = []

    for entry in raw_dirs:
        entry = str(entry).strip()
        if not entry:
            continue
        # Expand ~ and environment variables
        expanded = os.path.expanduser(os.path.expandvars(entry))
        p = Path(expanded)
        # Resolve relative paths against FETIH_HOME, not cwd
        if not p.is_absolute():
            p = (fetih_home / p).resolve()
        else:
            p = p.resolve()
        if p == local_skills:
            continue
        if p in seen:
            continue
        if p.is_dir():
            seen.add(p)
            result.append(p)
        else:
            logger.debug("External skills dir does not exist, skipping: %s", p)

    if cache_key is not None:
        _EXTERNAL_DIRS_CACHE[cache_key] = list(result)
    return result


def get_all_skills_dirs() -> List[Path]:
    """Return all skill directories: local ``~/.fetih/skills/`` first, then external.

    The local dir is always first (and always included even if it doesn't exist
    yet — callers handle that).  External dirs follow in config order.
    """
    dirs = [get_skills_dir()]
    dirs.extend(get_external_skills_dirs())
    return dirs


# ── Condition extraction ──────────────────────────────────────────────────


def extract_skill_conditions(frontmatter: Dict[str, Any]) -> Dict[str, List]:
    """Extract conditional activation fields from parsed frontmatter."""
    metadata = frontmatter.get("metadata")
    # Handle cases where metadata is not a dict (e.g., a string from malformed YAML)
    if not isinstance(metadata, dict):
        metadata = {}
    fetih = metadata.get("fetih") or {}
    if not isinstance(fetih, dict):
        fetih = {}
    return {
        "fallback_for_toolsets": fetih.get("fallback_for_toolsets", []),
        "requires_toolsets": fetih.get("requires_toolsets", []),
        "fallback_for_tools": fetih.get("fallback_for_tools", []),
        "requires_tools": fetih.get("requires_tools", []),
    }


# ── Skill config extraction ───────────────────────────────────────────────


def extract_skill_config_vars(frontmatter: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract config variable declarations from parsed frontmatter.

    Skills declare config.yaml settings they need via::

        metadata:
          fetih:
            config:
              - key: wiki.path
                description: Path to the LLM Wiki knowledge base directory
                default: "~/wiki"
                prompt: Wiki directory path

    Returns a list of dicts with keys: ``key``, ``description``, ``default``,
    ``prompt``.  Invalid or incomplete entries are silently skipped.
    """
    metadata = frontmatter.get("metadata")
    if not isinstance(metadata, dict):
        return []
    fetih = metadata.get("fetih")
    if not isinstance(fetih, dict):
        return []
    raw = fetih.get("config")
    if not raw:
        return []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []

    result: List[Dict[str, Any]] = []
    seen: set = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key", "")).strip()
        if not key or key in seen:
            continue
        # Must have at least key and description
        desc = str(item.get("description", "")).strip()
        if not desc:
            continue
        entry: Dict[str, Any] = {
            "key": key,
            "description": desc,
        }
        default = item.get("default")
        if default is not None:
            entry["default"] = default
        prompt_text = item.get("prompt")
        if isinstance(prompt_text, str) and prompt_text.strip():
            entry["prompt"] = prompt_text.strip()
        else:
            entry["prompt"] = desc
        seen.add(key)
        result.append(entry)
    return result


def discover_all_skill_config_vars() -> List[Dict[str, Any]]:
    """Scan all enabled skills and collect their config variable declarations.

    Walks every skills directory, parses each SKILL.md frontmatter, and returns
    a deduplicated list of config var dicts.  Each dict also includes a
    ``skill`` key with the skill name for attribution.

    Disabled and platform-incompatible skills are excluded.
    """
    all_vars: List[Dict[str, Any]] = []
    seen_keys: set = set()

    disabled = get_disabled_skill_names()
    for skills_dir in get_all_skills_dirs():
        if not skills_dir.is_dir():
            continue
        for skill_file in iter_skill_index_files(skills_dir, "SKILL.md"):
            try:
                raw = skill_file.read_text(encoding="utf-8")
                frontmatter, _ = parse_frontmatter(raw)
            except Exception:
                continue

            skill_name = frontmatter.get("name") or skill_file.parent.name
            if str(skill_name) in disabled:
                continue
            if not skill_matches_platform(frontmatter):
                continue

            config_vars = extract_skill_config_vars(frontmatter)
            for var in config_vars:
                if var["key"] not in seen_keys:
                    var["skill"] = str(skill_name)
                    all_vars.append(var)
                    seen_keys.add(var["key"])

    return all_vars


# Storage prefix: all skill config vars are stored under skills.config.*
# in config.yaml.  Skill authors declare logical keys (e.g. "wiki.path");
# the system adds this prefix for storage and strips it for display.
SKILL_CONFIG_PREFIX = "skills.config"


def _resolve_dotpath(config: Dict[str, Any], dotted_key: str):
    """Walk a nested dict following a dotted key.  Returns None if any part is missing."""
    parts = dotted_key.split(".")
    current = config
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def resolve_skill_config_values(
    config_vars: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Resolve current values for skill config vars from config.yaml.

    Skill config is stored under ``skills.config.<key>`` in config.yaml.
    Returns a dict mapping **logical** keys (as declared by skills) to their
    current values (or the declared default if the key isn't set).
    Path values are expanded via ``os.path.expanduser``.
    """
    config_path = get_config_path()
    config: Dict[str, Any] = {}
    if config_path.exists():
        try:
            parsed = yaml_load(config_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                config = parsed
        except Exception:
            pass

    resolved: Dict[str, Any] = {}
    for var in config_vars:
        logical_key = var["key"]
        storage_key = f"{SKILL_CONFIG_PREFIX}.{logical_key}"
        value = _resolve_dotpath(config, storage_key)

        if value is None or (isinstance(value, str) and not value.strip()):
            value = var.get("default", "")

        # Expand ~ in path-like values
        if isinstance(value, str) and ("~" in value or "${" in value):
            value = os.path.expanduser(os.path.expandvars(value))

        resolved[logical_key] = value

    return resolved


# ── Description extraction ────────────────────────────────────────────────


def extract_skill_description(frontmatter: Dict[str, Any]) -> str:
    """Extract a truncated description from parsed frontmatter."""
    raw_desc = frontmatter.get("description", "")
    if not raw_desc:
        return ""
    desc = str(raw_desc).strip().strip("'\"")
    if len(desc) > 60:
        return desc[:57] + "..."
    return desc


# ── File iteration ────────────────────────────────────────────────────────


def iter_skill_index_files(skills_dir: Path, filename: str):
    """Walk skills_dir yielding sorted paths matching *filename*.

    Excludes ``.git``, ``.github``, ``.hub``, ``.archive`` directories.
    """
    matches = []
    for root, dirs, files in os.walk(skills_dir, followlinks=True):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_SKILL_DIRS]
        if filename in files:
            matches.append(Path(root) / filename)
    for path in sorted(matches, key=lambda p: str(p.relative_to(skills_dir))):
        yield path


# ── Namespace helpers for plugin-provided skills ───────────────────────────

_NAMESPACE_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def parse_qualified_name(name: str) -> Tuple[Optional[str], str]:
    """Split ``'namespace:skill-name'`` into ``(namespace, bare_name)``.

    Returns ``(None, name)`` when there is no ``':'``.
    """
    if ":" not in name:
        return None, name
    return tuple(name.split(":", 1))  # type: ignore[return-value]


def is_valid_namespace(candidate: Optional[str]) -> bool:
    """Check whether *candidate* is a valid namespace (``[a-zA-Z0-9_-]+``)."""
    if not candidate:
        return False
    return bool(_NAMESPACE_RE.match(candidate))


# ---------------------------------------------------------------------------
# Mapping / Index dosyalari — hizli skill arama
# ---------------------------------------------------------------------------

# Cache: mapping dosyasi path -> parse edilmis dict
_MAPPING_CACHE: Dict[str, Any] = {}
_MAPPING_CACHE_MAX = 6

# Anahtar kelime -> kategori eşlemesi (Türkçe + İngilizce)
_KEYWORD_CATEGORY_MAP = {
    # Tehdit avı
    'tehdit avı': 'threat-hunting', 'tehdit avi': 'threat-hunting',
    'threat hunting': 'threat-hunting', 'threat hunt': 'threat-hunting',
    'anomali': 'threat-hunting', 'anomaly': 'threat-hunting',
    'yara': 'threat-hunting', 'sigma': 'threat-hunting',
    'siem': 'soc-operations', 'edr': 'endpoint-security',
    'xdr': 'endpoint-security',
    # Bulut
    'aws': 'cloud-security', 'azure': 'cloud-security',
    'gcp': 'cloud-security', 'bulut': 'cloud-security',
    'cloud': 'cloud-security', 's3': 'cloud-security',
    'iam': 'identity-access-management',
    # Zararlı yazılım
    'zararlı yazılım': 'malware-analysis', 'zararli yazilim': 'malware-analysis',
    'malware': 'malware-analysis', 'ransomware': 'ransomware-defense',
    'fidye': 'ransomware-defense', 'virus': 'malware-analysis',
    'trojan': 'malware-analysis', 'rootkit': 'malware-analysis',
    # Adli bilişim
    'adli bilişim': 'digital-forensics', 'adli bilisim': 'digital-forensics',
    'forensics': 'digital-forensics', 'forensic': 'digital-forensics',
    'disk imajı': 'digital-forensics', 'disk image': 'digital-forensics',
    'volatility': 'malware-analysis', 'memory dump': 'malware-analysis',
    'bellek': 'malware-analysis',
    # Ağ
    'ağ': 'network-security', 'ag': 'network-security',
    'network': 'network-security', 'nmap': 'network-security',
    'wireshark': 'network-security', 'paket': 'network-security',
    'packet': 'network-security', 'firewall': 'network-security',
    'ids': 'network-security', 'ips': 'network-security',
    # Web
    'web': 'web-application-security', 'sql injection': 'web-application-security',
    'sqli': 'web-application-security', 'xss': 'web-application-security',
    'csrf': 'web-application-security', 'ssrf': 'web-application-security',
    'owasp': 'web-application-security', 'api': 'api-security',
    'graphql': 'api-security', 'rest': 'api-security',
    # Sızma testi
    'sızma': 'penetration-testing', 'sizma': 'penetration-testing',
    'pentest': 'penetration-testing', 'pentesting': 'penetration-testing',
    'exploit': 'penetration-testing', 'exploitation': 'penetration-testing',
    'red team': 'penetration-testing', 'redteam': 'penetration-testing',
    # Olay müdahale
    'olay müdahale': 'incident-response', 'olay mudahale': 'incident-response',
    'incident response': 'incident-response', 'ir': 'incident-response',
    'kontaminasyon': 'incident-response', 'eradikasyon': 'incident-response',
    # SOC
    'soc': 'soc-operations', 'alert': 'soc-operations',
    'triage': 'soc-operations', 'vaka': 'incident-response',
    # Konteyner
    'docker': 'container-security', 'kubernetes': 'container-security',
    'k8s': 'container-security', 'container': 'container-security',
    'konteyner': 'container-security',
    # Kimlik
    'kimlik': 'identity-access-management', 'erişim': 'identity-access-management',
    'erisim': 'identity-access-management', 'mfa': 'identity-access-management',
    'sso': 'identity-access-management', 'active directory': 'identity-access-management',
    'azure ad': 'identity-access-management', 'entra': 'identity-access-management',
    'zero trust': 'zero-trust-architecture', 'sıfır güven': 'zero-trust-architecture',
    'sifir guven': 'zero-trust-architecture',
    # Zafiyet
    'zafiyet': 'vulnerability-management', 'vulnerability': 'vulnerability-management',
    'cvss': 'vulnerability-management', 'patch': 'vulnerability-management',
    'cve': 'vulnerability-management',
    # Kripto
    'kripto': 'cryptography', 'şifreleme': 'cryptography',
    'sifreleme': 'cryptography', 'crypto': 'cryptography',
    'tls': 'cryptography', 'ssl': 'cryptography', 'pki': 'cryptography',
    # Mobil
    'mobil': 'mobile-security', 'mobile': 'mobile-security',
    'android': 'mobile-security', 'ios': 'mobile-security', 'apk': 'mobile-security',
    # OT/ICS
    'scada': 'ot-ics-security', 'plc': 'ot-ics-security',
    'ics': 'ot-ics-security', 'ot': 'ot-ics-security',
    'endüstriyel': 'ot-ics-security', 'endustriyel': 'ot-ics-security',
    # Oltalma
    'oltalama': 'phishing-defense', 'phishing': 'phishing-defense',
    'email': 'phishing-defense', 'spf': 'phishing-defense',
    'dkim': 'phishing-defense', 'dmarc': 'phishing-defense',
    # Uyum
    'uyum': 'compliance-governance', 'compliance': 'compliance-governance',
    'iso 27001': 'compliance-governance', 'nist': 'compliance-governance',
    'gdpr': 'privacy-compliance', 'kvkk': 'privacy-compliance',
    'pci dss': 'compliance-governance', 'soc 2': 'compliance-governance',
    # DevSecOps
    'devsecops': 'devsecops', 'ci/cd': 'devsecops',
    'cicd': 'devsecops', 'sast': 'devsecops', 'dast': 'devsecops',
    'supply chain': 'supply-chain-security', 'tedarik zinciri': 'supply-chain-security',
    # Blockchain
    'blockchain': 'blockchain-security', 'smart contract': 'blockchain-security',
    'defi': 'blockchain-security',
    # Kablosuz
    'wifi': 'wireless-security', 'wireless': 'wireless-security',
    'kablosuz': 'wireless-security', 'bluetooth': 'wireless-security',
    # Yapay zeka
    'ai security': 'ai-security', 'ml security': 'ai-security',
    'yapay zeka': 'ai-security', 'adversarial': 'ai-security',
    # Sosyal mühendislik
    'sosyal mühendislik': 'social-engineering', 'sosyal muhendislik': 'social-engineering',
    'social engineering': 'social-engineering',
    # Tehdit istihbaratı
    'tehdit istihbarat': 'threat-intelligence', 'tehdit istihbarati': 'threat-intelligence',
    'threat intelligence': 'threat-intelligence', 'ioc': 'threat-intelligence',
    'misp': 'threat-intelligence', 'stix': 'threat-intelligence',
    'apt': 'threat-intelligence',
    # Uç nokta
    'uç nokta': 'endpoint-security', 'uc nokta': 'endpoint-security',
    'endpoint': 'endpoint-security',
    # Aldatma
    'honeypot': 'deception-technology', 'deception': 'deception-technology',
    'tuzak': 'deception-technology',
    # Firmware
    'firmware': 'firmware-security', 'bios': 'firmware-security',
    'uefi': 'firmware-security',
    # Veri koruma
    'dlp': 'data-protection', 'veri koruma': 'data-protection',
    'data protection': 'data-protection',
    # CTF
    'ctf': 'ctf', 'capture the flag': 'ctf',
}


def _load_mapping_file(mapping_name: str) -> Optional[Dict[str, Any]]:
    """Mapping dosyasini yukle ve cache'le.

    mapping_name: 'quick-ref', 'mitre-attack-index', 'nist-csf-index',
                  'tool-index', 'category-full-index'
    """
    global _MAPPING_CACHE

    if mapping_name in _MAPPING_CACHE:
        return _MAPPING_CACHE[mapping_name]

    # LRU temizligi
    while len(_MAPPING_CACHE) >= _MAPPING_CACHE_MAX:
        oldest = next(iter(_MAPPING_CACHE))
        del _MAPPING_CACHE[oldest]

    skills_dir = get_skills_dir()
    # cybersecurity/ altinda olabilir, direkt skills/ altinda da olabilir
    candidates = [
        skills_dir / 'cybersecurity' / f'{mapping_name}.md',
        skills_dir / f'{mapping_name}.md',
    ]

    for path in candidates:
        if not path.exists():
            continue
        try:
            content = path.read_text(encoding='utf-8')
            _MAPPING_CACHE[mapping_name] = {
                'path': str(path),
                'content': content,
                'lines': content.split('\n'),
            }
            return _MAPPING_CACHE[mapping_name]
        except Exception:
            continue

    return None


def query_skills_by_keyword(user_query: str, max_results: int = 25) -> List[str]:
    """Kullanici mesajindaki anahtar kelimelere gore ilgili skill isimlerini bul.

    Strateji:
      1. _KEYWORD_CATEGORY_MAP'te eslesen kategorileri bul
      2. quick-ref.md'de anahtar kelime iceren satirlari tara
      3. tool-index.md'de arac isimlerini ara
      4. Sonucu birlesik sekilde dondur (tekrarsiz, sirali)
    """
    query_lower = user_query.lower()
    matched_categories: Set[str] = set()
    extra_skills: Set[str] = set()

    # Adim 1: Anahtar kelime -> kategori esleme (sadece kategori adlari)
    for keyword, category in _KEYWORD_CATEGORY_MAP.items():
        # Kisa keyword'ler (<= 2 karakter) icin word-boundary eslesme
        if len(keyword) <= 2:
            if re.search(r'\b' + re.escape(keyword) + r'\b', query_lower):
                matched_categories.add(category)
        elif keyword in query_lower:
            matched_categories.add(category)

    # Adim 2: quick-ref.md'de ara (MITRE ID varsa)
    mitre_match = re.findall(r'T\d{4}(?:\.\d{3})?', user_query.upper())
    if mitre_match:
        quick_ref = _load_mapping_file('quick-ref')
        if quick_ref:
            for mid in mitre_match:
                for line in quick_ref['lines']:
                    if mid in line:
                        skills = re.findall(r'`([a-z][a-z0-9-]+)`', line)
                        extra_skills.update(skills)

    # Adim 3: tool-index.md'de arac ismi ara (supplementary)
    common_tools = [
        'nmap', 'wireshark', 'metasploit', 'burp', 'ghidra', 'ida',
        'volatility', 'splunk', 'nessus', 'hydra', 'john', 'hashcat',
        'gobuster', 'ffuf', 'sqlmap', 'nikto', 'zap', 'aircrack',
        'ettercap', 'tcpdump', 'tshark', 'autopsy', 'binwalk',
        'foremost', 'steghide', 'exiftool', 'radare2', 'gdb',
        'docker', 'kubernetes', 'terraform', 'ansible',
    ]
    for tool in common_tools:
        if tool in query_lower:
            tool_index = _load_mapping_file('tool-index')
            if tool_index:
                in_tool_section = False
                for line in tool_index['lines']:
                    if line.startswith(f'## {tool}') or line.startswith(f'## **{tool}**'):
                        in_tool_section = True
                        continue
                    if in_tool_section:
                        if line.startswith('## '):
                            break
                        skills = re.findall(r'`([a-z][a-z0-9-]+)`', line)
                        extra_skills.update(skills)

    # Adim 4: Kategorilerden skill isimlerini yukle (PRIMARY)
    result_skills: List[str] = []
    seen: Set[str] = set()

    # Once eslesen kategorilerdeki skill'leri yukle
    if matched_categories:
        category_index = _load_mapping_file('category-full-index')
        if category_index:
            for cat in sorted(matched_categories)[:4]:
                in_section = False
                for line in category_index['lines']:
                    if line.startswith(f'## {cat}') or line.startswith(f'## {cat.replace("-", " ")}'):
                        in_section = True
                        continue
                    if in_section:
                        if line.startswith('## '):
                            break
                        skills = re.findall(r'`([A-Za-z][A-Za-z0-9_ -]+)`', line)
                        for s in skills:
                            s_clean = s.strip().lower().replace(' ', '-').replace('_', '-')
                            if s_clean not in seen and len(s_clean) > 3:
                                seen.add(s_clean)
                                result_skills.append(s_clean)
                                if len(result_skills) >= max_results:
                                    break
                    if len(result_skills) >= max_results:
                        break
                if len(result_skills) >= max_results:
                    break

    # Sonra extra skill'leri ekle (tool-index'ten gelenler)
    for s in sorted(extra_skills):
        s_clean = s.lower().replace('_', '-')
        if s_clean not in seen and len(s_clean) > 3:
            seen.add(s_clean)
            result_skills.append(s_clean)
            if len(result_skills) >= max_results:
                break

    # Hic sonuc yoksa kategorileri direkt ekle (geriye donuk uyumluluk)
    if not result_skills:
        for cat in matched_categories:
            if cat not in seen:
                seen.add(cat)
                result_skills.append(cat)

    return result_skills[:max_results]


def query_skills_by_mitre(technique_ids: List[str]) -> List[str]:
    """MITRE ATT&CK teknik ID'lerine gore skill isimlerini bul."""
    skills: Set[str] = set()

    quick_ref = _load_mapping_file('quick-ref')
    if not quick_ref:
        return []

    for tid in technique_ids:
        for line in quick_ref['lines']:
            if tid in line:
                found = re.findall(r'`([a-z][a-z0-9-]+)`', line)
                skills.update(found)

    return sorted(skills)


def query_skills_by_nist_csf(nist_ids: List[str]) -> List[str]:
    """NIST CSF kategorilerine gore skill isimlerini bul."""
    skills: Set[str] = set()

    nist_index = _load_mapping_file('nist-csf-index')
    if not nist_index:
        return []

    for nid in nist_ids:
        for line in nist_index['lines']:
            if nid in line:
                found = re.findall(r'`([a-z][a-z0-9-]+)`', line)
                skills.update(found)

    return sorted(skills)


def query_skills_by_tool(tool_name: str) -> List[str]:
    """Arac ismine gore ilgili skill'leri bul."""
    skills: Set[str] = set()

    tool_index = _load_mapping_file('tool-index')
    if not tool_index:
        return []

    in_tool_section = False
    for line in tool_index['lines']:
        if line.startswith(f'## {tool_name}') or line.startswith(f'## **{tool_name}**'):
            in_tool_section = True
            continue
        if in_tool_section:
            if line.startswith('## ') and not line.startswith(f'## {tool_name}'):
                break
            found = re.findall(r'`([a-z][a-z0-9-]+)`', line)
            skills.update(found)

    return sorted(skills)


def clear_mapping_cache() -> None:
    """Mapping cache'ini temizle (ornegin skill'ler yeniden yuklendiginde)."""
    global _MAPPING_CACHE
    _MAPPING_CACHE.clear()
