"""CTF/pentest araç yöneticisi — Linux-only.

'fetih download-tools' komutunun arka planı. Araç listesi, kurulum
yöntemleri ve interaktif menü burada tanımlanır.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import os
import platform
import tempfile
import urllib.request
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Renk sabitleri
# ---------------------------------------------------------------------------
_RED    = "\033[0;31m"
_GREEN  = "\033[0;32m"
_YELLOW = "\033[0;33m"
_BLUE   = "\033[0;34m"
_CYAN   = "\033[0;36m"
_BOLD   = "\033[1m"
_NC     = "\033[0m"

def _c(color: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"{color}{text}{_NC}"
    return text


# ---------------------------------------------------------------------------
# Araç tanımı
# ---------------------------------------------------------------------------
class Tool(NamedTuple):
    name: str        # görünen ad
    check: str       # shutil.which ile kontrol edilecek binary
    method: str      # apt | pip | go | cargo | gem | git | deb | script
    pkg: str         # paket adı veya URL/path (method'a göre değişir)
    root: bool       # sudo gerektirir mi?
    desc: str        # kısa açıklama


# ---------------------------------------------------------------------------
# Araç listesi — 9 kategori
# ---------------------------------------------------------------------------
TOOLS: dict[str, list[Tool]] = {
    "network": [
        Tool("nmap",       "nmap",       "apt",   "nmap",                         True,  "Port tarayıcı"),
        Tool("masscan",    "masscan",    "apt",   "masscan",                      True,  "Hızlı port tarayıcı"),
        Tool("arp-scan",   "arp-scan",   "apt",   "arp-scan",                     True,  "LAN host keşfi"),
        Tool("dnsenum",    "dnsenum",    "apt",   "dnsenum",                      True,  "DNS enumeration"),
        Tool("fierce",     "fierce",     "pip",   "fierce",                       False, "DNS zone tarama"),
        Tool("rustscan",   "rustscan",   "cargo", "rustscan",                     False, "Ultrafast port tarayıcı"),
        Tool("tshark",     "tshark",     "apt",   "tshark",                       True,  "Komut satırı paket analizi"),
        Tool("wireshark",  "wireshark",  "apt",   "wireshark",                    True,  "GUI paket analizi"),
        Tool("scapy",      "scapy",      "pip",   "scapy",                        False, "Paket manipülasyon kütüphanesi"),
        Tool("pyshark",    "pyshark",    "pip",   "pyshark",                      False, "Python PCAP analiz"),
        Tool("subfinder",  "subfinder",  "go",    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                                                                                  False, "Subdomain keşfi"),
        Tool("amass",      "amass",      "apt",   "amass",                        False, "OSINT + subdomain"),
        Tool("waybackurls","waybackurls","go",    "github.com/tomnomnom/waybackurls@latest",
                                                                                  False, "Wayback Machine URL"),
        Tool("gau",        "gau",        "go",    "github.com/lc/gau/v2/cmd/gau@latest",
                                                                                  False, "URL toplayıcı"),
        Tool("assetfinder","assetfinder","go",    "github.com/tomnomnom/assetfinder@latest",
                                                                                  False, "Asset/subdomain bulucu"),
    ],
    "web": [
        Tool("sqlmap",     "sqlmap",     "pip",   "sqlmap",                       False, "SQL injection"),
        Tool("nikto",      "nikto",      "apt",   "nikto",                        False, "Web zafiyet tarayıcı"),
        Tool("nuclei",     "nuclei",     "go",    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                                                                                  False, "Template tabanlı tarayıcı"),
        Tool("dalfox",     "dalfox",     "go",    "github.com/hahwul/dalfox/v2@latest",
                                                                                  False, "XSS tarayıcı"),
        Tool("ffuf",       "ffuf",       "go",    "github.com/ffuf/ffuf/v2@latest",
                                                                                  False, "Web fuzzer"),
        Tool("gobuster",   "gobuster",   "apt",   "gobuster",                     False, "Dizin/dosya bruteforce"),
        Tool("feroxbuster","feroxbuster","apt",   "feroxbuster",                  False, "Recursive fuzzer"),
        Tool("arjun",      "arjun",      "pip",   "arjun",                        False, "HTTP parametre keşfi"),
        Tool("wafw00f",    "wafw00f",    "pip",   "wafw00f",                      False, "WAF tespit"),
        Tool("wpscan",     "wpscan",     "gem",   "wpscan",                       False, "WordPress tarayıcı"),
        Tool("katana",     "katana",     "go",    "github.com/projectdiscovery/katana/cmd/katana@latest",
                                                                                  False, "Web crawler"),
        Tool("hakrawler",  "hakrawler",  "go",    "github.com/hakluke/hakrawler@latest",
                                                                                  False, "Hızlı web crawler"),
        Tool("smuggler",   "smuggler",   "pip",   "smuggler",                     False, "HTTP request smuggling"),
        Tool("httpx",      "httpx",      "pip",   "httpx[http2]",                 False, "HTTP/2 race condition testi"),
        Tool("aiohttp",    "aiohttp",    "pip",   "aiohttp",                      False, "Async HTTP (race condition)"),
        Tool("racepwn",    "racepwn",    "pip",   "racepwn",                      False, "Race condition saldırı aracı"),
    ],
    "pentest": [
        Tool("hydra",      "hydra",      "apt",   "hydra",                        True,  "Brute-force aracı"),
        Tool("john",       "john",       "apt",   "john",                         False, "Şifre kırıcı"),
        Tool("hashcat",    "hashcat",    "apt",   "hashcat",                      False, "GPU şifre kırıcı"),
        Tool("netexec",    "netexec",    "pip",   "netexec",                      False, "SMB/SSH/WinRM sızma"),
        Tool("haiti-hash", "haiti",      "pip",   "haiti-hash",                   False, "Hash formatı tanıma"),
        Tool("metasploit", "msfconsole", "script","https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb",
                                                                                  True,  "Exploit framework (büyük)"),
    ],
    "binary": [
        Tool("gdb",        "gdb",        "apt",   "gdb",                          False, "GNU debugger"),
        Tool("pwntools",   "pwn",        "pip",   "pwntools",                     False, "Exploit geliştirme kütüphanesi"),
        Tool("radare2",    "r2",         "apt",   "radare2",                      False, "Binary analiz"),
        Tool("ropper",     "ropper",     "pip",   "ropper",                       False, "ROP gadget bulucu"),
        Tool("checksec",   "checksec",   "pip",   "checksec",                     False, "Binary güvenlik kontrol"),
        Tool("one_gadget", "one_gadget", "gem",   "one_gadget",                   False, "One-gadget libc bulucu"),
        Tool("angr",       "angr",       "pip",   "angr",                         False, "Symbolic execution"),
        Tool("z3-solver",  "z3",         "pip",   "z3-solver",                    False, "Z3 constraint solver"),
        Tool("seccomp-tools","seccomp-tools","gem","seccomp-tools",               False, "SECCOMP filter analizi"),
        Tool("pwndbg",     "pwndbg",     "git",   "https://github.com/pwndbg/pwndbg|/opt/pwndbg|./setup.sh",
                                                                                  False, "GDB için pwn eklenti"),
        Tool("ghidra",     "ghidra",     "deb",   "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip",
                                                                                  False, "Reverse engineering (~500MB)"),
    ],
    "crypto": [
        Tool("pycryptodome","python3",   "pip",   "pycryptodome",                 False, "Kripto kütüphanesi"),
        Tool("gmpy2",      "python3",    "pip",   "gmpy2",                        False, "GMP Python binding (RSA)"),
        Tool("sympy",      "python3",    "pip",   "sympy",                        False, "Sembolik matematik"),
        Tool("fpylll",     "python3",    "pip",   "fpylll",                       False, "LLL lattice reduction"),
        Tool("sagemath",   "sage",       "apt",   "sagemath",                     False, "Matematiksel hesaplama (~1GB)"),
        Tool("padding-oracle","python3", "pip",   "padding-oracle",               False, "Padding oracle saldırı"),
    ],
    "forensics": [
        Tool("binwalk",       "binwalk",    "pip",   "binwalk",                   False, "Firmware analiz + carving"),
        Tool("foremost",      "foremost",   "apt",   "foremost",                  False, "File carving"),
        Tool("testdisk",      "testdisk",   "apt",   "testdisk",                  False, "Disk kurtarma + PhotoRec"),
        Tool("sleuthkit",     "fls",        "apt",   "sleuthkit",                 False, "Disk forensics (TSK)"),
        Tool("autopsy",       "autopsy",    "apt",   "autopsy",                   False, "GUI disk forensics"),
        Tool("exiftool",      "exiftool",   "apt",   "libimage-exiftool-perl",    False, "EXIF / metadata"),
        Tool("ewf-tools",     "ewfmount",   "apt",   "ewf-tools",                 True,  "EnCase .E01 imaj desteği"),
        Tool("ntfs-3g",       "ntfscat",    "apt",   "ntfs-3g",                   True,  "NTFS analiz araçları"),
        Tool("volatility3",   "vol",        "pip",   "volatility3",               False, "Bellek forensics"),
        Tool("pypykatz",      "pypykatz",   "pip",   "pypykatz",                  False, "LSASS / NTLM dump"),
        Tool("analyzeMFT",    "analyzeMFT", "pip",   "analyzeMFT",                False, "NTFS MFT analizi"),
        Tool("pytsk3",        "python3",    "pip",   "pytsk3",                    False, "Python TSK binding"),
        Tool("bless",         "bless",      "apt",   "bless",                     False, "Hex editor (GUI)"),
        Tool("wxhexeditor",   "wxHexEditor","apt",   "wxhexeditor",               False, "Hex editor (GUI, büyük)"),
        Tool("wrk",           "wrk",        "apt",   "wrk",                       False, "HTTP load tester"),
    ],
    "stego": [
        Tool("steghide",      "steghide",    "apt",  "steghide",                  False, "Stegano hide/extract"),
        Tool("zsteg",         "zsteg",       "gem",  "zsteg",                     False, "PNG/BMP stegano"),
        Tool("stegoveritas",  "stegoveritas","pip",  "stegoveritas",              False, "Multi-format stegano"),
        Tool("stegseek",      "stegseek",    "deb",  "https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb",
                                                                                  False, "Steghide brute-force"),
        Tool("stegolsb",      "stegolsb",    "pip",  "stegolsb",                  False, "LSB stegano"),
        Tool("ffmpeg",        "ffmpeg",      "apt",  "ffmpeg",                    False, "Audio/video dönüşüm"),
        Tool("sox",           "sox",         "apt",  "sox",                       False, "Ses işleme"),
        Tool("audacity",      "audacity",    "apt",  "audacity",                  False, "Ses editörü (GUI)"),
        Tool("sonic-visualiser","sonic-visualiser","apt","sonic-visualiser",      False, "Spektogram analizi (GUI)"),
    ],
    "mobile": [
        Tool("androguard",    "androguard",  "pip",  "androguard",                False, "Android APK analizi"),
        Tool("frida-tools",   "frida",       "pip",  "frida-tools",               False, "Dynamic instrumentation"),
        Tool("objection",     "objection",   "pip",  "objection",                 False, "Frida wrapper (SSL/root bypass)"),
        Tool("ntfs-tools",    "python3",     "pip",  "ntfs-tools",                False, "NTFS Python araçları"),
    ],
    "osint": [
        Tool("maigret",       "maigret",     "pip",  "maigret",                   False, "Kullanıcı adı OSINT"),
        Tool("sherlock",      "sherlock",    "pip",  "sherlock-project",           False, "Sosyal medya hesap arama"),
    ],
}

# Temel araç seti — "basic" seçeneğinde kurulur
BASIC_TOOLS = {"nmap", "sqlmap", "pwntools", "gdb", "binwalk",
               "foremost", "hydra", "john", "ffuf", "exiftool"}


# ---------------------------------------------------------------------------
# Yardımcı: kurulum yöntemleri
# ---------------------------------------------------------------------------
def _run(cmd: list[str], check: bool = True) -> bool:
    try:
        subprocess.run(cmd, check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _has_sudo() -> bool:
    return _run(["sudo", "-n", "true"], check=False)


def _check_tool(tool: Tool) -> bool:
    return shutil.which(tool.check) is not None


def _install_apt(tool: Tool) -> bool:
    return _run(["sudo", "apt-get", "install", "-y", "-q", tool.pkg])


def _install_pip(tool: Tool) -> bool:
    return _run([sys.executable, "-m", "pip", "install", "--quiet", tool.pkg])


def _install_go(tool: Tool) -> bool:
    if not shutil.which("go"):
        return False
    return _run(["go", "install", tool.pkg])


def _install_cargo(tool: Tool) -> bool:
    if not shutil.which("cargo"):
        return False
    return _run(["cargo", "install", tool.pkg])


def _install_gem(tool: Tool) -> bool:
    if not shutil.which("gem"):
        return False
    return _run(["gem", "install", tool.pkg])


def _install_git(tool: Tool) -> bool:
    """pkg formatı: <url>|<dest>|<build_cmd>"""
    parts = tool.pkg.split("|")
    if len(parts) != 3:
        return False
    url, dest, build = parts
    if not os.path.isdir(dest):
        if not _run(["git", "clone", "--depth=1", url, dest]):
            return False
    orig = os.getcwd()
    try:
        os.chdir(dest)
        return _run(["/bin/bash", build])
    except Exception:
        return False
    finally:
        os.chdir(orig)


def _install_deb(tool: Tool) -> bool:
    """pkg: .deb URL veya zip URL (ghidra için)"""
    url = tool.pkg
    if url.endswith(".deb"):
        with tempfile.NamedTemporaryFile(suffix=".deb", delete=False) as f:
            tmp = f.name
        try:
            print(f"    İndiriliyor {url.split('/')[-1]}...", end="", flush=True)
            urllib.request.urlretrieve(url, tmp)
            print(" indirildi")
            return _run(["sudo", "dpkg", "-i", tmp])
        except Exception:
            return False
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    elif url.endswith(".zip"):
        # Ghidra gibi zip araçlar için — /opt'a aç, symlink oluştur
        dest_dir = "/opt/ghidra"
        if os.path.isdir(dest_dir):
            return True
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            tmp = f.name
        try:
            print(f"    İndiriliyor {url.split('/')[-1]} (~500MB)...", end="", flush=True)
            urllib.request.urlretrieve(url, tmp)
            print(" indirildi")
            _run(["sudo", "unzip", "-q", tmp, "-d", "/opt"])
            # İndirilen klasörü /opt/ghidra olarak symlink et
            extracted = next(
                (e for e in os.listdir("/opt") if e.startswith("ghidra_")),
                None,
            )
            if extracted:
                _run(["sudo", "ln", "-sf", f"/opt/{extracted}/ghidraRun",
                      "/usr/local/bin/ghidra"])
            return shutil.which("ghidra") is not None
        except Exception:
            return False
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return False


def _install_script(tool: Tool) -> bool:
    """Metasploit gibi curl | bash installer'lar için."""
    if tool.name == "metasploit":
        print("    Metasploit kurulumu başlatılıyor (uzun sürebilir)...")
        with tempfile.NamedTemporaryFile(suffix=".sh", delete=False, mode="w") as f:
            tmp = f.name
        try:
            urllib.request.urlretrieve(
                "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/"
                "config/templates/metasploit-framework-wrappers/msfupdate.erb",
                tmp,
            )
            return _run(["sudo", "bash", tmp])
        except Exception:
            return False
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return False


_INSTALL_DISPATCH = {
    "apt":    _install_apt,
    "pip":    _install_pip,
    "go":     _install_go,
    "cargo":  _install_cargo,
    "gem":    _install_gem,
    "git":    _install_git,
    "deb":    _install_deb,
    "script": _install_script,
}


# ---------------------------------------------------------------------------
# Kurulum ana fonksiyonu
# ---------------------------------------------------------------------------
def install_tool(tool: Tool) -> bool:
    fn = _INSTALL_DISPATCH.get(tool.method)
    if fn is None:
        return False
    return fn(tool)


# ---------------------------------------------------------------------------
# Toplu kurulum
# ---------------------------------------------------------------------------
def install_tools(tools: list[Tool], yes: bool = False) -> None:
    """Araçları tek tek kur, varsa atla."""
    if platform.system() != "Linux":
        print(_c(_RED, "Hata: download-tools yalnızca Linux'ta çalışır."))
        return

    has_sudo = _has_sudo()
    to_install = [t for t in tools if not _check_tool(t)]
    already = len(tools) - len(to_install)

    if not to_install:
        print(_c(_GREEN, f"✓ Tüm araçlar zaten kurulu ({len(tools)}/{len(tools)})"))
        return

    if already:
        print(_c(_CYAN, f"  {already} araç zaten kurulu, {len(to_install)} araç kurulacak"))

    if not yes:
        names = ", ".join(t.name for t in to_install[:8])
        if len(to_install) > 8:
            names += f"... (+{len(to_install) - 8} daha)"
        print(f"\n  Kurulacak: {_c(_BOLD, names)}")
        ans = input("  Devam? [e/H] ").strip().lower()
        if ans not in ("e", "evet", "y", "yes"):
            print("İptal.")
            return

    ok = 0
    fail = 0
    for t in to_install:
        needs_root = t.root and not has_sudo
        if needs_root:
            print(f"  {_c(_YELLOW, '⚠')} {t.name:<16} sudo erişimi yok, atlanıyor")
            fail += 1
            continue

        print(f"  {_c(_BLUE, '↓')} {t.name:<16} kuruluyor ({t.method})...", end="", flush=True)
        if install_tool(t):
            print(f"\r  {_c(_GREEN, '✓')} {t.name:<16} kuruldu")
            ok += 1
        else:
            print(f"\r  {_c(_RED, '✗')} {t.name:<16} başarısız ({t.method}: {t.pkg})")
            fail += 1

    print()
    print(_c(_GREEN, f"  ✓ {ok} kuruldu") + (f"  {_c(_YELLOW, f'⚠ {fail} başarısız')}" if fail else ""))


# ---------------------------------------------------------------------------
# Status görünümü
# ---------------------------------------------------------------------------
def print_status() -> None:
    """Hangi araçların kurulu olduğunu kategori bazında göster."""
    total = installed = 0
    for cat, tools in TOOLS.items():
        cat_ok = [t for t in tools if _check_tool(t)]
        cat_miss = [t for t in tools if not _check_tool(t)]
        total += len(tools)
        installed += len(cat_ok)
        print(f"\n  {_c(_BOLD, cat.upper())} ({len(cat_ok)}/{len(tools)})")
        for t in cat_ok:
            print(f"    {_c(_GREEN, '✓')} {t.name:<16} {t.desc}")
        for t in cat_miss:
            print(f"    {_c(_RED, '✗')} {t.name:<16} {t.desc}")

    print(f"\n  Toplam: {_c(_GREEN, str(installed))} / {total} araç kurulu\n")
    if installed < total:
        print(f"  Eksikleri kurmak için: {_c(_CYAN, 'fetih download-tools')}\n")


# ---------------------------------------------------------------------------
# İnteraktif menü
# ---------------------------------------------------------------------------
def interactive_menu() -> None:
    """Kategori seçim menüsü."""
    all_tools = [t for tlist in TOOLS.values() for t in tlist]
    basic_list = [t for tlist in TOOLS.values() for t in tlist if t.name in BASIC_TOOLS]

    categories = list(TOOLS.keys())
    total = len(all_tools)
    installed = sum(1 for t in all_tools if _check_tool(t))

    print()
    print(_c(_BOLD, "  ╔══════════════════════════════════════════╗"))
    print(_c(_BOLD, "  ║      CTF / Pentest Araç İndiricisi       ║"))
    print(_c(_BOLD, "  ╚══════════════════════════════════════════╝"))
    print(f"\n  Mevcut: {_c(_GREEN, str(installed))}/{total} araç kurulu\n")
    print(f"  {_c(_BOLD, '1)')} Hepsini yükle    ({total} araç — nmap, sqlmap, pwntools, ghidra...)")
    print(f"  {_c(_BOLD, '2)')} Temel araçlar    ({len(basic_list)} araç — nmap, sqlmap, pwntools, gdb, binwalk...)")
    print(f"  {_c(_BOLD, '3)')} Kategori seç")
    for i, cat in enumerate(categories, 4):
        tools_in_cat = TOOLS[cat]
        ok = sum(1 for t in tools_in_cat if _check_tool(t))
        print(f"       {i}) {cat:<12} ({ok}/{len(tools_in_cat)} kurulu)")
    print(f"  {_c(_BOLD, 'q)')} Çıkış\n")

    choice = input("  Seçim: ").strip().lower()

    if choice == "1":
        install_tools(all_tools)
    elif choice == "2":
        install_tools(basic_list)
    elif choice == "3":
        cat_choice = input(f"  Kategori ({'/'.join(categories)}): ").strip().lower()
        if cat_choice in TOOLS:
            install_tools(TOOLS[cat_choice])
        else:
            print("Geçersiz kategori.")
    elif choice.isdigit():
        idx = int(choice) - 4
        if 0 <= idx < len(categories):
            install_tools(TOOLS[categories[idx]])
        else:
            print("Geçersiz seçim.")
    elif choice in ("q", "çık", "exit"):
        return
    else:
        print("Geçersiz seçim.")


# ---------------------------------------------------------------------------
# Kategori adından araç listesi döndür
# ---------------------------------------------------------------------------
def tools_for_category(category: str | None) -> list[Tool] | None:
    """
    None       → interaktif menü
    'all'      → tüm araçlar
    'basic'    → temel araçlar
    'status'   → None (özel durum — çağıran handle eder)
    <kategori> → o kategorinin araçları
    """
    if category is None:
        return None  # interaktif menü açılacak
    if category == "all":
        return [t for tlist in TOOLS.values() for t in tlist]
    if category == "basic":
        return [t for tlist in TOOLS.values() for t in tlist if t.name in BASIC_TOOLS]
    if category == "status":
        return None  # özel durum
    return TOOLS.get(category)
