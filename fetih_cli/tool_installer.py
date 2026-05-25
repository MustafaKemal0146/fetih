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

def _clear_line(text: str) -> str:
    """Satırı sıfırla + 70 karaktere kadar boşlukla temizle (kuruluyor... kalıntısı için)."""
    return f"\r{text:<70}"


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
        Tool("fierce",     "fierce",     "pip",   "dnspython fierce",             False, "DNS zone tarama"),
        Tool("rustscan",   "rustscan",   "deb",   "https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb",
                                                                                  False, "Ultrafast port tarayıcı"),
        Tool("tshark",     "tshark",     "apt",   "tshark",                       True,  "Komut satırı paket analizi"),
        Tool("wireshark",  "wireshark",  "apt",   "wireshark",                    True,  "GUI paket analizi"),
        Tool("scapy",      "module:scapy","pip",   "scapy",                       False, "Paket manipülasyon kütüphanesi"),
        Tool("pyshark",    "module:pyshark","pip", "pyshark",                     False, "Python PCAP analiz"),
        Tool("subfinder",  "subfinder",  "go",    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                                                                                  False, "Subdomain keşfi"),
        Tool("amass",      "amass",      "go",    "github.com/owasp-amass/amass/v4/cmd/amass@latest",
                                                                                  False, "OSINT + subdomain"),
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
        Tool("feroxbuster","feroxbuster","cargo", "feroxbuster",                  False, "Recursive fuzzer"),
        Tool("arjun",      "arjun",      "pip",   "arjun",                        False, "HTTP parametre keşfi"),
        Tool("wafw00f",    "wafw00f",    "pip",   "wafw00f",                      False, "WAF tespit"),
        Tool("wpscan",     "wpscan",     "gem",   "wpscan",                       False, "WordPress tarayıcı"),
        Tool("katana",     "katana",     "go",    "github.com/projectdiscovery/katana/cmd/katana@latest",
                                                                                  False, "Web crawler"),
        Tool("hakrawler",  "hakrawler",  "go",    "github.com/hakluke/hakrawler@latest",
                                                                                  False, "Hızlı web crawler"),
        Tool("smuggler",   "smuggler.py","git",   "https://github.com/defparam/smuggler|/opt/smuggler|true",
                                                                                  False, "HTTP request smuggling"),
        Tool("httpx",      "httpx",      "pip",   "httpx[http2]",                 False, "HTTP/2 race condition testi"),
        Tool("aiohttp",    "module:aiohttp","pip", "aiohttp",                     False, "Async HTTP (race condition - kütüphane)"),
        Tool("racepwn",    "/opt/racepwn","git",  "https://github.com/insidersec/racepwn|/opt/racepwn|true",
                                                                                  False, "Race condition saldırı aracı"),
    ],
    "pentest": [
        Tool("hydra",      "hydra",      "apt",   "hydra",                        True,  "Brute-force aracı"),
        Tool("john",       "john",       "apt",   "john",                         False, "Şifre kırıcı"),
        Tool("hashcat",    "hashcat",    "apt",   "hashcat",                      False, "GPU şifre kırıcı"),
        Tool("netexec",    "netexec",    "pipx",  "netexec",                      False, "SMB/SSH/WinRM sızma"),
        Tool("haiti-hash", "haiti",      "cargo", "haiti-hash",                   False, "Hash formatı tanıma (Rust)"),
        Tool("metasploit", "msfconsole", "script","metasploit",                   True,  "Exploit framework (büyük)"),
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
        Tool("pwndbg",     "/opt/pwndbg/gdbinit.py", "git",
             "https://github.com/pwndbg/pwndbg|/opt/pwndbg|true",
                                                                                  False, "GDB için pwn eklenti (GDB'ye 'source /opt/pwndbg/gdbinit.py' ekle)"),
        Tool("ghidra",     "ghidra",     "deb",   "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip",
                                                                                  False, "Reverse engineering (~500MB)"),
    ],
    "crypto": [
        Tool("pycryptodome","module:Crypto","pip","pycryptodome",                 False, "Kripto kütüphanesi"),
        Tool("gmpy2",      "module:gmpy2","pip",  "gmpy2",                        False, "GMP Python binding (RSA)"),
        Tool("sympy",      "module:sympy","pip",  "sympy",                        False, "Sembolik matematik"),
        Tool("fpylll",     "module:fpylll","pip", "fpylll",                       False, "LLL lattice reduction"),
        Tool("padding-oracle","module:padding_oracle","pip","padding-oracle",     False, "Padding oracle saldırı"),
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
        Tool("pytsk3",        "module:pytsk3","pip", "pytsk3",                    False, "Python TSK binding"),
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
        Tool("stegolsb",      "stegolsb",    "pip",  "stego-lsb",                 False, "LSB stegano"),
        Tool("ffmpeg",        "ffmpeg",      "apt",  "ffmpeg",                    False, "Audio/video dönüşüm"),
        Tool("sox",           "sox",         "apt",  "sox",                       False, "Ses işleme"),
        Tool("audacity",      "audacity",    "apt",  "audacity",                  False, "Ses editörü (GUI)"),
        Tool("sonic-visualiser","sonic-visualiser","apt","sonic-visualiser",      False, "Spektogram analizi (GUI)"),
    ],
    "mobile": [
        Tool("androguard",    "androguard",  "pip",  "androguard",                False, "Android APK analizi"),
        Tool("frida-tools",   "frida",       "pip",  "frida-tools",               False, "Dynamic instrumentation"),
        Tool("objection",     "objection",   "pip",  "objection",                 False, "Frida wrapper (SSL/root bypass)"),
        Tool("ntfs-tools",    "module:ntfs", "pip",  "ntfs-tools",                False, "NTFS Python araçları"),
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
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------
def _run(cmd: list[str], check: bool = True, env: dict | None = None) -> bool:
    try:
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        subprocess.run(cmd, check=check,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       env=run_env)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _has_sudo() -> bool:
    return _run(["sudo", "-n", "true"], check=False)


def _check_tool(tool: Tool) -> bool:
    """Check semantiği:
    - 'module:<name>'      → Python modülü olarak içe aktar dene
    - '/path'              → dosya yolu kontrol
    - '<binary>'           → PATH + bilinen bin dizinleri
    """
    # Python modülü
    if tool.check.startswith("module:"):
        mod = tool.check.split(":", 1)[1]
        try:
            _run([sys.executable, "-c", f"import {mod}"], check=True)
            return True
        except Exception:
            pass
        # uv venv için ayrı kontrol
        if shutil.which("uv"):
            r = subprocess.run(
                ["uv", "run", "python", "-c", f"import {mod}"],
                capture_output=True
            )
            if r.returncode == 0:
                return True
        return False

    # Dosya yolu
    if tool.check.startswith("/"):
        return os.path.exists(tool.check)

    # Binary kontrolü
    if shutil.which(tool.check):
        return True
    import glob
    venv_bin = os.path.dirname(sys.executable)
    candidates = [
        venv_bin,
        os.path.expanduser("~/.local/bin"),
        os.path.expanduser("~/.cargo/bin"),
        os.path.expanduser("~/go/bin"),
    ]
    for d in candidates:
        if os.path.exists(os.path.join(d, tool.check)):
            return True
    for p in glob.glob(os.path.expanduser("~/.gem/ruby/*/bin")):
        if os.path.exists(os.path.join(p, tool.check)):
            return True
    return False


# ---------------------------------------------------------------------------
# Bağımlılık yöneticisi önkurulum
# ---------------------------------------------------------------------------
_APT_UPDATED = False

def _ensure_apt_update() -> None:
    global _APT_UPDATED
    if not _APT_UPDATED:
        _run(["sudo", "apt-get", "update", "-qq"])
        _APT_UPDATED = True


def _ensure_ruby() -> bool:
    """Ruby/gem + native extension için build araçları."""
    if not shutil.which("gem"):
        _ensure_apt_update()
        if not _run(["sudo", "apt-get", "install", "-y", "-q", "ruby-full"]):
            return False
    # Native gem extension build için (wpscan, seccomp-tools)
    global _RUBY_BUILD_DEPS
    if not _RUBY_BUILD_DEPS:
        _ensure_apt_update()
        _run(["sudo", "apt-get", "install", "-y", "-q",
              "ruby-dev", "build-essential",
              "libcurl4-openssl-dev", "libxml2-dev", "libxslt1-dev",
              "zlib1g-dev", "libsqlite3-dev"], check=False)
        _RUBY_BUILD_DEPS = True
    return shutil.which("gem") is not None

_RUBY_BUILD_DEPS = False


def _ensure_rust() -> bool:
    """cargo yoksa rustup ile kur."""
    if shutil.which("cargo"):
        return True
    with tempfile.NamedTemporaryFile(suffix=".sh", delete=False) as f:
        tmp = f.name
    try:
        urllib.request.urlretrieve("https://sh.rustup.rs", tmp)
        if _run(["sh", tmp, "-y", "--no-modify-path"]):
            cargo_bin = os.path.expanduser("~/.cargo/bin")
            os.environ["PATH"] = cargo_bin + ":" + os.environ.get("PATH", "")
            return shutil.which("cargo") is not None
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return False


def _ensure_pipx() -> bool:
    """pipx yoksa 3 yolla kurmayı dene."""
    if shutil.which("pipx"):
        return True
    # 1. apt
    _ensure_apt_update()
    if _run(["sudo", "apt-get", "install", "-y", "-q", "pipx"]):
        if shutil.which("pipx"):
            return True
    # 2. pip3 --user
    if shutil.which("pip3"):
        if _run(["pip3", "install", "--user", "--quiet",
                 "--break-system-packages", "pipx"]):
            os.environ["PATH"] = os.path.expanduser("~/.local/bin") + ":" + os.environ.get("PATH", "")
            return shutil.which("pipx") is not None
    # 3. uv tool
    if shutil.which("uv"):
        if _run(["uv", "tool", "install", "pipx"]):
            return shutil.which("pipx") is not None
    return False


def _ensure_universe_repo() -> bool:
    """Ubuntu universe repo yoksa ekle (sagemath için)."""
    result = subprocess.run(
        ["apt-cache", "show", "sagemath"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        return True
    return _run(["sudo", "add-apt-repository", "-y", "universe"]) and \
           _run(["sudo", "apt-get", "update", "-qq"])


# ---------------------------------------------------------------------------
# Kurulum yöntemleri
# ---------------------------------------------------------------------------
def _install_apt(tool: Tool) -> bool:
    _ensure_apt_update()
    # 1. apt-get install
    if _run(["sudo", "apt-get", "install", "-y", "-q",
             "-o", "Dpkg::Options::=--force-confdef",
             "-o", "Dpkg::Options::=--force-confold",
             tool.pkg]):
        return True
    # 2. snap fallback (sadece bazı paketler için anlamlı)
    if shutil.which("snap") and tool.name in {"sagemath", "amass", "ffuf"}:
        if _run(["sudo", "snap", "install", tool.name]):
            return True
    return False


def _install_pip(tool: Tool) -> bool:
    """5 katmanlı pip fallback zinciri."""
    pkgs = tool.pkg.split()  # "dnspython fierce" → ["dnspython", "fierce"]

    # 1. uv pip — FETIH'in uv venv'i için ana yol
    if shutil.which("uv"):
        if _run(["uv", "pip", "install"] + pkgs):
            return True

    # 2. ensurepip + venv pip — pip yoksa kur, sonra dene
    _run([sys.executable, "-m", "ensurepip", "--upgrade"], check=False)
    if _run([sys.executable, "-m", "pip", "install", "--quiet"] + pkgs):
        return True

    # 3. --break-system-packages (Ubuntu 22.04+)
    if _run([sys.executable, "-m", "pip", "install", "--quiet",
             "--break-system-packages"] + pkgs):
        return True

    # 4. Sistem pip3 --user
    if shutil.which("pip3"):
        if _run(["pip3", "install", "--quiet", "--user",
                 "--break-system-packages"] + pkgs):
            return True
        if _run(["pip3", "install", "--quiet", "--user"] + pkgs):
            return True

    # 5. pipx fallback — CLI araçlar için son şans
    if _ensure_pipx() and _run(["pipx", "install", "--quiet", pkgs[-1]]):
        return True

    return False


def _install_pipx(tool: Tool) -> bool:
    """4 katmanlı pipx fallback."""
    # 1. pipx install
    if _ensure_pipx():
        if _run(["pipx", "install", "--quiet", tool.pkg]):
            return True
    # 2. uv tool install (pipx alternatifi)
    if shutil.which("uv"):
        if _run(["uv", "tool", "install", tool.pkg]):
            return True
    # 3. pip install fallback
    return _install_pip(tool)


def _install_go(tool: Tool) -> bool:
    if not shutil.which("go"):
        return False
    return _run(["go", "install", tool.pkg])


def _install_cargo(tool: Tool) -> bool:
    if not shutil.which("cargo"):
        if not _ensure_rust():
            return False
    cargo_bin = os.path.expanduser("~/.cargo/bin")
    env = {"PATH": cargo_bin + ":" + os.environ.get("PATH", "")}
    cargo = shutil.which("cargo") or os.path.join(cargo_bin, "cargo")
    return _run([cargo, "install", tool.pkg], env=env)


def _install_gem(tool: Tool) -> bool:
    """3 katmanlı gem fallback."""
    if not _ensure_ruby():
        return False
    # 1. --user-install (sudo'suz, ~/.gem'e kurar)
    if _run(["gem", "install", "--user-install", "--no-document", tool.pkg]):
        # PATH'e ekle
        import glob
        for gem_bin in glob.glob(os.path.expanduser("~/.gem/ruby/*/bin")):
            os.environ["PATH"] = gem_bin + ":" + os.environ.get("PATH", "")
        return True
    # 2. sudo gem install (sistem geneli)
    if _has_sudo() and _run(["sudo", "gem", "install", "--no-document", tool.pkg]):
        return True
    # 3. Düz gem install
    return _run(["gem", "install", "--no-document", tool.pkg])


def _install_git(tool: Tool) -> bool:
    """pkg formatı: <url>|<dest>|<build_cmd>
    build_cmd 'true' → sadece clone + symlink
    """
    parts = tool.pkg.split("|")
    if len(parts) != 3:
        return False
    url, dest, build = parts

    needs_sudo = dest.startswith(("/opt", "/usr"))
    git_cmd = (["sudo"] if needs_sudo else []) + ["git"]

    # Mevcut durumu temizle
    if os.path.isdir(dest):
        if os.path.isdir(os.path.join(dest, ".git")):
            # Geçerli git repo — güncelle
            _run(git_cmd + ["-C", dest, "fetch", "--all"], check=False)
            _run(git_cmd + ["-C", dest, "reset", "--hard", "origin/HEAD"], check=False)
        else:
            # Bozuk durum — temizle
            _run((["sudo"] if needs_sudo else []) + ["rm", "-rf", dest], check=False)

    if not os.path.isdir(dest):
        if not _run(git_cmd + ["clone", "--depth=1", url, dest]):
            return False

    if build == "true":
        # Sadece clone + ana script symlink
        basename = os.path.basename(dest)
        candidates = [
            f"{basename}.py", "main.py", "run.py", basename,
            f"{basename}/{basename}.py",
        ]
        for cand in candidates:
            script = os.path.join(dest, cand)
            if os.path.isfile(script):
                _run((["sudo"] if needs_sudo else []) + ["chmod", "+x", script], check=False)
                link = f"/usr/local/bin/{os.path.basename(cand)}"
                _run(["sudo", "ln", "-sf", script, link], check=False)
                return True
        return True  # Clone başarılı, script bulunmasa da

    # Build script çalıştır
    orig = os.getcwd()
    try:
        os.chdir(dest)
        return _run(["/bin/bash", build])
    except Exception:
        return False
    finally:
        os.chdir(orig)


def _install_deb(tool: Tool) -> bool:
    """pkg: .deb URL veya .zip URL (ghidra için)."""
    url = tool.pkg
    if url.endswith(".deb"):
        with tempfile.NamedTemporaryFile(suffix=".deb", delete=False) as f:
            tmp = f.name
        try:
            print(f"    İndiriliyor {url.split('/')[-1]}...", end="", flush=True)
            urllib.request.urlretrieve(url, tmp)
            print(" indirildi")
            # dpkg -i yerine apt install — bağımlılıkları otomatik çözer
            if _run(["sudo", "apt", "install", "-y", "-q", tmp]):
                return True
            # Fallback: dpkg + bağımlılık düzeltme
            _run(["sudo", "dpkg", "-i", tmp], check=False)
            return _run(["sudo", "apt-get", "install", "-f", "-y", "-q"])
        except Exception:
            return False
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    elif url.endswith(".zip"):
        dest_dir = "/opt/ghidra"
        if os.path.isdir(dest_dir):
            # Zaten kurulu, sadece symlink kontrol
            extracted = next(
                (e for e in os.listdir("/opt") if e.startswith("ghidra_")), None
            )
            if extracted and not shutil.which("ghidra"):
                _run(["sudo", "ln", "-sf", f"/opt/{extracted}/ghidraRun",
                      "/usr/local/bin/ghidra"])
            return True
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            tmp = f.name
        try:
            print(f"    İndiriliyor {url.split('/')[-1]} (~500MB)...", end="", flush=True)
            urllib.request.urlretrieve(url, tmp)
            print(" indirildi")
            if not _run(["sudo", "unzip", "-q", tmp, "-d", "/opt"]):
                return False
            extracted = next(
                (e for e in os.listdir("/opt") if e.startswith("ghidra_")), None
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
    """Metasploit gibi özel installer'lar."""
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
    "pipx":   _install_pipx,
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
    try:
        for t in to_install:
            needs_root = t.root and not has_sudo
            if needs_root:
                print(f"  {_c(_YELLOW, '⚠')} {t.name:<16} sudo erişimi yok, atlanıyor")
                fail += 1
                continue

            prefix = f"  {_c(_BLUE, '↓')} {t.name:<16} kuruluyor ({t.method})..."
            print(prefix, end="", flush=True)
            if install_tool(t):
                success = f"  {_c(_GREEN, '✓')} {t.name:<16} kuruldu"
                print(_clear_line(success))
                ok += 1
            else:
                pkg_short = t.pkg.split("|")[0][:40]
                fail_msg = f"  {_c(_RED, '✗')} {t.name:<16} başarısız ({t.method}: {pkg_short})"
                print(_clear_line(fail_msg))
                fail += 1
    except KeyboardInterrupt:
        print(f"\n\n  {_c(_YELLOW, '⚠')} Kullanıcı iptal etti.")

    print()
    summary = _c(_GREEN, f"  ✓ {ok} kuruldu")
    if fail:
        summary += f"  {_c(_YELLOW, f'⚠ {fail} başarısız')}"
    print(summary)


# ---------------------------------------------------------------------------
# Status görünümü
# ---------------------------------------------------------------------------
def print_status() -> None:
    """Hangi araçların kurulu olduğunu kategori bazında göster."""
    total = installed = 0
    for cat, tools in TOOLS.items():
        cat_ok  = [t for t in tools if _check_tool(t)]
        cat_miss = [t for t in tools if not _check_tool(t)]
        total    += len(tools)
        installed += len(cat_ok)
        print(f"\n  {_c(_BOLD, cat.upper())} ({len(cat_ok)}/{len(tools)})")
        for t in cat_ok:
            print(f"    {_c(_GREEN, '✓')} {t.name:<18} {t.desc}")
        for t in cat_miss:
            print(f"    {_c(_RED, '✗')} {t.name:<18} {t.desc}")

    print(f"\n  Toplam: {_c(_GREEN, str(installed))} / {total} araç kurulu\n")
    if installed < total:
        print(f"  Eksikleri kurmak için: {_c(_CYAN, 'fetih download-tools')}\n")


# ---------------------------------------------------------------------------
# İnteraktif menü
# ---------------------------------------------------------------------------
def interactive_menu() -> None:
    """Kategori seçim menüsü."""
    all_tools  = [t for tlist in TOOLS.values() for t in tlist]
    basic_list = [t for tlist in TOOLS.values() for t in tlist if t.name in BASIC_TOOLS]
    categories = list(TOOLS.keys())
    total      = len(all_tools)
    installed  = sum(1 for t in all_tools if _check_tool(t))

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
        print(f"       {i}) {cat:<14} ({ok}/{len(tools_in_cat)} kurulu)")
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
        return None
    if category == "all":
        return [t for tlist in TOOLS.values() for t in tlist]
    if category == "basic":
        return [t for tlist in TOOLS.values() for t in tlist if t.name in BASIC_TOOLS]
    if category == "status":
        return None
    return TOOLS.get(category)
