"""Windows kabuk (shell) arka uç seçimi — Git Bash veya WSL.

FETİH'in araç sistemi POSIX kabuğuna göre tasarlanmıştır: oturum anlık
görüntüsü ``export -p`` ile alınır, çalışma dizini ``pwd -P`` ile okunur,
komutlar ``bash -c`` ile çalıştırılır ve komut metinleri ``shlex.quote``
ile kaçışlanır.  Bu yüzden Windows'ta **anlamlı olan iki** seçenek vardır:

``git-bash`` (varsayılan)
    Git for Windows'un MSYS2 tabanlı ``bash.exe``'si.  Windows dosya
    sistemine doğrudan erişir (``C:\\Users\\...`` ↔ ``/c/Users/...``),
    Windows ikililerini (``python.exe``, ``nmap.exe``) çalıştırabilir.

``wsl``
    ``wsl.exe`` üzerinden gerçek bir Linux dağıtımı.  Windows sürücüleri
    ``/mnt/c/...`` altında görünür.  Linux araç zinciri (apt, gcc,
    binwalk, radare2 …) doğrudan kullanılabilir; Windows ``.exe``'leri de
    WSL interop sayesinde çalışır.

**PowerShell bilerek sunulmaz.**  Yukarıdaki dört varsayımın hiçbiri
PowerShell'de geçerli değildir (``export -p`` yok, ``pwd -P`` yok,
``shlex.quote`` PowerShell kaçışlaması değildir, oturum anlık görüntüsü
``source`` edilemez).  Bir "PowerShell" seçeneği eklemek çalışmayan sahte
bir seçenek olurdu; bunun yerine kullanıcılar Git Bash / WSL içinden
``powershell.exe -c "…"`` çağırabilir.

Bu modül ayrıca WSL tarafında FETİH'e ayrılmış bir ``fetih`` kullanıcısını
(yoksa) oluşturabilir; böylece ajanın yazdığı dosyalar kullanıcının kendi
ev dizinine karışmaz.
"""

from __future__ import annotations

import functools
import logging
import os
import platform
import re
import shutil
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

_IS_WINDOWS = platform.system() == "Windows"

#: ``terminal.windows_shell`` için geçerli değerler.
SHELL_GIT_BASH = "git-bash"
SHELL_WSL = "wsl"
VALID_SHELLS = (SHELL_GIT_BASH, SHELL_WSL)

#: WSL içinde FETİH için açılan ayrılmış kullanıcı adı.
DEFAULT_WSL_USER = "fetih"

# wsl.exe UTF-16LE yazar; çıktıyı bu kodlamayla çözüyoruz.
_WSL_ENCODING = "utf-16-le"

# Kısa süreli yardımcı komutlar için üst sınır (saniye).
_PROBE_TIMEOUT = 20
_SETUP_TIMEOUT = 90


# ── Yol çevirileri ───────────────────────────────────────────────────────


def windows_to_wsl_path(path: str) -> str:
    """``C:\\Users\\ara`` → ``/mnt/c/Users/ara``.

    Zaten POSIX biçimindeki yollar (``/mnt/c/...``, ``/home/...``)
    değiştirilmeden döner, yani işlem idempotenttir.
    """
    if not path:
        return path
    if path.startswith("/"):
        return path
    m = re.match(r"^([a-zA-Z]):[\\/](.*)$", path)
    if not m:
        # Sürücü kökü ("C:") ya da göreli yol — çevrilemez, olduğu gibi bırak.
        m_root = re.match(r"^([a-zA-Z]):$", path)
        if m_root:
            return f"/mnt/{m_root.group(1).lower()}"
        return path.replace("\\", "/")
    drive = m.group(1).lower()
    tail = m.group(2).replace("\\", "/")
    return f"/mnt/{drive}/{tail}" if tail else f"/mnt/{drive}"


def wsl_to_windows_path(path: str) -> str:
    """``/mnt/c/Users/ara`` → ``C:\\Users\\ara``. Eşleşme yoksa girdi döner."""
    if not path:
        return path
    m = re.match(r"^/mnt/([a-zA-Z])(/.*)?$", path)
    if not m:
        return path
    drive = m.group(1).upper()
    tail = (m.group(2) or "").replace("/", "\\")
    return f"{drive}:{tail or chr(92)}"


# ── Git Bash bulma ───────────────────────────────────────────────────────


def is_wsl_shim(path: str | None) -> bool:
    """``path`` Windows'un WSL başlatıcı ``bash.exe`` shim'i mi?

    Windows 10/11'de WSL kurulduğunda ``C:\\Windows\\System32\\bash.exe``
    (ve ``%LOCALAPPDATA%\\Microsoft\\WindowsApps\\bash.exe`` mağaza
    kısayolu) PATH'e girer.  Bu **Git Bash değildir**: WSL'i açar ve
    WSL'de ``/c/Users/...`` diye bir yol olmadığı için (WSL ``/mnt/c/...``
    kullanır) FETİH'in ürettiği her komut
    ``No such file or directory`` ile başarısız olur.

    Karşılaştırma büyük/küçük harf duyarsızdır ve kısa (8.3) yol farkları
    ile sembolik bağları eritmek için ``os.path.realpath`` uygulanır;
    ``C:\\WINDOWS\\system32\\bash.EXE`` ile ``C:\\Windows\\System32\\bash.exe``
    aynı sayılır.
    """
    if not path:
        return False
    try:
        resolved = os.path.realpath(path)
    except OSError:
        resolved = path
    normalized = os.path.normcase(os.path.normpath(resolved)).replace("/", "\\")
    base = os.path.basename(normalized)
    if base not in ("bash.exe", "wsl.exe"):
        return False
    directory = os.path.dirname(normalized)
    # System32 / SysWOW64 / WindowsApps altındaki bash.exe daima WSL shim'idir;
    # Git for Windows kendini asla oraya kurmaz.
    return (
        directory.endswith("\\system32")
        or directory.endswith("\\syswow64")
        or directory.endswith("\\windowsapps")
    )


def _git_bash_candidates() -> list[str]:
    """Git Bash aday yolları — **öncelik sırasıyla**.

    Sıralama bilinçlidir: PATH araması (``shutil.which``) EN SONA bırakılır,
    çünkü WSL kurulu makinelerde PATH'teki ilk ``bash`` neredeyse her zaman
    ``C:\\Windows\\System32\\bash.exe`` (WSL shim'i) olur ve onu seçmek
    terminal aracını tamamen bozar.
    """
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")

    candidates: list[str] = []

    # 1) FETİH'in kendi taşınabilir Git kurulumu (install.ps1 buraya koyar).
    if local_appdata:
        fetih_git = os.path.join(local_appdata, "fetih", "git")
        candidates.append(os.path.join(fetih_git, "bin", "bash.exe"))
        candidates.append(os.path.join(fetih_git, "usr", "bin", "bash.exe"))

    # 2) Bilinen sistem Git for Windows kurulumları.
    for root in (program_files, program_files_x86):
        if root:
            candidates.append(os.path.join(root, "Git", "bin", "bash.exe"))
            candidates.append(os.path.join(root, "Git", "usr", "bin", "bash.exe"))
    if local_appdata:
        candidates.append(os.path.join(local_appdata, "Programs", "Git", "bin", "bash.exe"))
        candidates.append(
            os.path.join(local_appdata, "Programs", "Git", "usr", "bin", "bash.exe")
        )

    return [c for c in candidates if c]


def find_git_bash() -> str | None:
    """Gerçek Git Bash ``bash.exe``'sini bul; WSL shim'ini asla döndürme."""
    custom = os.environ.get("FETIH_GIT_BASH_PATH")
    if custom and os.path.isfile(custom) and not is_wsl_shim(custom):
        return custom

    for candidate in _git_bash_candidates():
        if os.path.isfile(candidate):
            return candidate

    # EN SON çare: PATH araması — ama WSL shim'i çıkarsa reddet.
    found = shutil.which("bash")
    if found and os.path.isfile(found) and not is_wsl_shim(found):
        return found

    # PATH'te git.exe varsa kardeş bash.exe'yi dene (özel kurulum konumları).
    git_exe = shutil.which("git")
    if git_exe:
        git_root = os.path.dirname(os.path.dirname(git_exe))
        for tail in (("bin", "bash.exe"), ("usr", "bin", "bash.exe")):
            candidate = os.path.join(git_root, *tail)
            if os.path.isfile(candidate) and not is_wsl_shim(candidate):
                return candidate

    return None


# ── WSL tespiti ──────────────────────────────────────────────────────────


def find_wsl_exe() -> str | None:
    """``wsl.exe``'nin tam yolu (kurulu değilse ``None``)."""
    if not _IS_WINDOWS:
        return None
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    for candidate in (
        os.path.join(system_root, "System32", "wsl.exe"),
        os.path.join(system_root, "Sysnative", "wsl.exe"),
    ):
        if os.path.isfile(candidate):
            return candidate
    return shutil.which("wsl")


def _decode_wsl_output(raw: bytes) -> str:
    """wsl.exe çıktısını çöz — UTF-16LE, olmazsa UTF-8'e düş."""
    if not raw:
        return ""
    try:
        text = raw.decode(_WSL_ENCODING)
        # UTF-16 yanlış tahminse metin NUL doludur; o zaman UTF-8'e düş.
        if "\x00" not in text:
            return text
    except (UnicodeDecodeError, LookupError):
        pass
    return raw.decode("utf-8", errors="replace").replace("\x00", "")


def _run_wsl(args: list[str], timeout: int = _PROBE_TIMEOUT) -> tuple[int, str]:
    """``wsl.exe`` çağır; ``(returncode, birleştirilmiş çıktı)`` döndür."""
    exe = find_wsl_exe()
    if not exe:
        return 127, "wsl.exe bulunamadı"
    try:
        proc = subprocess.run(
            [exe, *args],
            capture_output=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return 124, f"wsl.exe zaman aşımına uğradı ({timeout}s)"
    except OSError as exc:
        return 126, f"wsl.exe çalıştırılamadı: {exc}"
    out = _decode_wsl_output(proc.stdout) + _decode_wsl_output(proc.stderr)
    return proc.returncode, out.strip()


def list_wsl_distros() -> list[str]:
    """Kurulu WSL dağıtımlarının adları (yoksa boş liste).

    Sistem dağıtımları (``docker-desktop*``) atlanır — bunlar kabuk
    olarak kullanılamaz.
    """
    code, out = _run_wsl(["--list", "--quiet"])
    if code != 0:
        return []
    names: list[str] = []
    for line in out.splitlines():
        name = line.strip().strip("\ufeff")
        if not name:
            continue
        if name.startswith("docker-desktop"):
            continue
        names.append(name)
    return names


def default_wsl_distro() -> str | None:
    """Varsayılan WSL dağıtımı (``wsl -l -q`` çıktısındaki ilk kayıt)."""
    distros = list_wsl_distros()
    return distros[0] if distros else None


@functools.lru_cache(maxsize=1)
def wsl_status() -> dict[str, Any]:
    """WSL kurulum durumunu özetle (süreç ömrü boyunca önbelleklenir).

    ``{"available": bool, "distros": [...], "default": str|None,
    "detail": str}``
    """
    if not _IS_WINDOWS:
        return {"available": False, "distros": [], "default": None,
                "detail": "WSL yalnızca Windows'ta kullanılabilir."}
    exe = find_wsl_exe()
    if not exe:
        return {"available": False, "distros": [], "default": None,
                "detail": "wsl.exe bulunamadı — WSL kurulu değil."}
    distros = list_wsl_distros()
    if not distros:
        return {"available": False, "distros": [], "default": None,
                "detail": "wsl.exe var ama kurulu bir dağıtım yok "
                          "(`wsl --install -d Ubuntu` ile kurabilirsin)."}
    return {
        "available": True,
        "distros": distros,
        "default": distros[0],
        "detail": f"{len(distros)} dağıtım kurulu: " + ", ".join(distros),
    }


# ── WSL kullanıcı hazırlığı ──────────────────────────────────────────────


def _wsl_root_exec(distro: str | None, script: str, timeout: int = _SETUP_TIMEOUT):
    args: list[str] = []
    if distro:
        args += ["-d", distro]
    args += ["-u", "root", "--", "sh", "-c", script]
    return _run_wsl(args, timeout=timeout)


def wsl_user_exists(distro: str | None, user: str) -> bool:
    code, _ = _run_wsl(
        ([*(["-d", distro] if distro else [])] + ["-u", "root", "--", "id", "-u", user]),
    )
    return code == 0


def ensure_wsl_user(distro: str | None = None, user: str = DEFAULT_WSL_USER) -> dict[str, Any]:
    """WSL dağıtımında ``user`` adlı kullanıcıyı (yoksa) oluştur.

    ``useradd`` bulunmayan minimal dağıtımlarda (Alpine) ``adduser``
    denenir.  Her durumda ``{"ok": bool, "created": bool, "detail": str}``
    döner — çağıran taraf hatayı kullanıcıya gösterebilir, ama bu işlev
    asla istisna fırlatmaz (terminal aracı bu yüzden bozulmasın).
    """
    if not _IS_WINDOWS:
        return {"ok": False, "created": False, "detail": "WSL yalnızca Windows'ta."}

    status = wsl_status()
    if not status["available"]:
        return {"ok": False, "created": False, "detail": status["detail"]}

    target = distro or status["default"]
    safe_user = re.sub(r"[^a-z0-9_-]", "", (user or "").lower())
    if not safe_user:
        return {"ok": False, "created": False, "detail": "Geçersiz kullanıcı adı."}

    if wsl_user_exists(target, safe_user):
        return {
            "ok": True,
            "created": False,
            "detail": f"'{safe_user}' kullanıcısı {target} içinde zaten var.",
        }

    # useradd (Debian/Ubuntu/Fedora) → adduser (Alpine/BusyBox) sırası.
    script = (
        f"set -e; "
        f"if command -v useradd >/dev/null 2>&1; then "
        f"  useradd -m -s /bin/bash {safe_user}; "
        f"elif command -v adduser >/dev/null 2>&1; then "
        f"  adduser -D -s /bin/sh {safe_user}; "
        f"else echo 'useradd/adduser yok' >&2; exit 1; fi; "
        # Şifresiz sudo VERİLMEZ: bu bir güvenlik aracı, ajanın root'a
        # sessizce yükselmesi istenmez.  Yalnızca ev dizini hazırlanır.
        f"mkdir -p /home/{safe_user}; chown {safe_user} /home/{safe_user} || true"
    )
    code, out = _wsl_root_exec(target, script)
    if code != 0:
        return {
            "ok": False,
            "created": False,
            "detail": f"'{safe_user}' oluşturulamadı ({target}): {out or f'çıkış kodu {code}'}",
        }
    return {
        "ok": True,
        "created": True,
        "detail": f"'{safe_user}' kullanıcısı {target} içinde oluşturuldu.",
    }


# ── Yapılandırma okuma ───────────────────────────────────────────────────


def read_shell_preference() -> dict[str, Any]:
    """``terminal.*`` altındaki Windows kabuk tercihini oku.

    Dönen sözlük: ``{"shell": "git-bash"|"wsl", "distro": str,
    "user": str}``.  Yapılandırma okunamazsa Git Bash varsayılanına düşer —
    terminal aracı config hatası yüzünden asla çalışmaz duruma gelmemeli.
    """
    shell = SHELL_GIT_BASH
    distro = ""
    user = ""
    try:
        from fetih_cli.config import load_config

        terminal_cfg = (load_config() or {}).get("terminal") or {}
        raw = str(terminal_cfg.get("windows_shell") or "").strip().lower()
        if raw in VALID_SHELLS:
            shell = raw
        distro = str(terminal_cfg.get("wsl_distro") or "").strip()
        user = str(terminal_cfg.get("wsl_user") or "").strip()
    except Exception:  # pragma: no cover - config bozuksa varsayılana düş
        pass

    # Ortam değişkeni yapılandırmayı geçersiz kılar (test / hata ayıklama).
    env_override = (os.environ.get("FETIH_WINDOWS_SHELL") or "").strip().lower()
    if env_override in VALID_SHELLS:
        shell = env_override

    return {"shell": shell, "distro": distro, "user": user}


def effective_shell() -> str:
    """Gerçekten kullanılacak kabuk — WSL seçili ama yoksa Git Bash'e düşer."""
    pref = read_shell_preference()
    if pref["shell"] != SHELL_WSL:
        return SHELL_GIT_BASH
    if not wsl_status()["available"]:
        logger.warning(
            "terminal.windows_shell='wsl' seçili ama kullanılabilir bir WSL "
            "dağıtımı yok; Git Bash'e dönülüyor."
        )
        return SHELL_GIT_BASH
    return SHELL_WSL


def build_wsl_argv(
    cmd_string: str,
    *,
    login: bool,
    cwd: str,
    distro: str = "",
    user: str = "",
) -> list[str]:
    """WSL için ``wsl.exe … bash -c <komut>`` argüman dizisini kur.

    ``--cd`` mutlak bir Windows yolu kabul eder ve WSL tarafında
    ``/mnt/<sürücü>/…`` karşılığına çevirir; böylece FETİH'in Windows
    tarafında tuttuğu çalışma dizini WSL oturumunda da geçerli olur.
    """
    exe = find_wsl_exe()
    if not exe:
        raise RuntimeError("wsl.exe bulunamadı.")

    args = [exe]
    if distro:
        args += ["-d", distro]
    if user:
        args += ["-u", user]
    if cwd:
        args += ["--cd", cwd]
    args += ["--exec", "/bin/bash"]
    args += ["-l", "-c", cmd_string] if login else ["-c", cmd_string]
    return args
