#!/usr/bin/env python3
"""Yerelleştirme (i18n) doğrulama aracı.

1. en-US ve tr-TR .resw anahtar kümeleri birebir aynı mı.
2. XAML dosyalarındaki her x:Uid'in .resw'da karşılığı var mı.
3. .xaml ve .cs dosyalarında sabit Türkçe karakterli metin literalleri var mı.
"""

import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

ROOT_DIR = Path(__file__).resolve().parent.parent
WIN_DIR = ROOT_DIR / "apps" / "windows" / "Fetih.Desktop"

TR_RESW = WIN_DIR / "Strings" / "tr-TR" / "Resources.resw"
EN_RESW = WIN_DIR / "Strings" / "en-US" / "Resources.resw"

TURKISH_CHARS = set("çğıöşüÇĞİÖŞÜ")

# Beyaz liste: Yerelleştirme dosyaları, ayar envanterleri, log/crash çağrıları ve geliştirici araçları
WHITELIST_FILES = {
    "Localization.cs",
    "Resources.resw",
    "AppInfo.cs",                # Versiyon ve derleme bilgisi
    "BrandIcon.cs",              # Win32 icon API
    "SimpleSettingsCatalog.cs",  # Çift dilli ayar kataloğu tanımları
    "SettingDescriptions.cs",    # Çift dilli ayar açıklamaları kataloğu
    "Branding.xaml",             # Vektörel grafik ve marka banner şablonu
}

WHITELIST_PATTERNS = [
    re.compile(r'App\.LogCrash\('),
    re.compile(r'logger\.(debug|info|warning|error)'),
    re.compile(r'Debug\.WriteLine'),
    re.compile(r'Trace\.WriteLine'),
    re.compile(r'throw new \w*Exception\('),
]


def parse_resw_keys(path: Path) -> dict:
    if not path.exists():
        print(f"HATA: {path} dosyası bulunamadı!", file=sys.stderr)
        return {}
    tree = ET.parse(path)
    root = tree.getroot()
    keys = {}
    for data in root.findall("data"):
        name = data.get("name")
        val = data.findtext("value") or ""
        keys[name] = val
    return keys


def check_resw_parity():
    print("== 1. .resw Anahtar Birebir Eşleşme Denetimi ==")
    tr_keys = parse_resw_keys(TR_RESW)
    en_keys = parse_resw_keys(EN_RESW)

    missing_in_en = set(tr_keys.keys()) - set(en_keys.keys())
    missing_in_tr = set(en_keys.keys()) - set(tr_keys.keys())

    errors = 0
    if missing_in_en:
        print(f"HATA: en-US içinde eksik {len(missing_in_en)} anahtar:")
        for k in sorted(missing_in_en):
            print(f"  - {k}")
        errors += len(missing_in_en)
    else:
        print("✓ en-US içinde eksik anahtar yok.")

    if missing_in_tr:
        print(f"HATA: tr-TR içinde eksik {len(missing_in_tr)} anahtar:")
        for k in sorted(missing_in_tr):
            print(f"  - {k}")
        errors += len(missing_in_tr)
    else:
        print("✓ tr-TR içinde eksik anahtar yok.")

    print(f"Toplam anahtar sayısı: {len(tr_keys)} (tr-TR) / {len(en_keys)} (en-US)\n")
    return errors, tr_keys


def check_xaml_uids(resw_keys: dict):
    print("== 2. XAML x:Uid Denetimi ==")
    errors = 0
    uid_pattern = re.compile(r'x:Uid="([^"]+)"')

    for xaml_path in WIN_DIR.rglob("*.xaml"):
        if not xaml_path.is_file() or "bin" in xaml_path.parts or "obj" in xaml_path.parts:
            continue
        try:
            text = xaml_path.read_text(encoding="utf-8")
        except Exception:
            continue
        # Strip comments
        text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)
        for m in uid_pattern.finditer(text):
            uid = m.group(1)
            # Match uid or uid.* in resw
            matching = [k for k in resw_keys if k == uid or k.startswith(uid + ".")]
            if not matching:
                print(f"HATA: {xaml_path.name} içindeki x:Uid=\"{uid}\" için .resw'da karşılık bulunamadı!")
                errors += 1

    if errors == 0:
        print("✓ Tüm XAML x:Uid öğeleri .resw içinde tanımlı.\n")
    else:
        print(f"Toplam {errors} x:Uid hatası.\n")
    return errors


def check_hardcoded_strings():
    print("== 3. Sabit Metin ve Türkçe Karakter Denetimi ==")
    errors = 0

    # 1. Check XAML hardcoded attributes
    xaml_attr_pattern = re.compile(r'(?:Text|Content|PlaceholderText|Title)="([^"{}>]+)"')
    allowed_xaml_values = {"FETİH", "Mica", "", "...", "$", "•", "✓", "✗"}

    for xaml_path in WIN_DIR.rglob("*.xaml"):
        if not xaml_path.is_file() or xaml_path.name in WHITELIST_FILES or "bin" in xaml_path.parts or "obj" in xaml_path.parts:
            continue
        try:
            content = xaml_path.read_text(encoding="utf-8")
        except Exception:
            continue
        clean_content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)

        for line_no, line in enumerate(clean_content.splitlines(), start=1):
            for m in xaml_attr_pattern.finditer(line):
                val = m.group(1).strip()
                if (
                    val in allowed_xaml_values
                    or val.startswith("{")
                    or val.startswith("&#x")
                    or val.isdigit()
                    or len(val) <= 1
                ):
                    continue
                # If it contains Turkish characters or looks like a hardcoded message
                if any(c in TURKISH_CHARS for c in val):
                    print(f"HATA [{xaml_path.name}:{line_no}] XAML sabit Türkçe metin: \"{val}\"")
                    errors += 1

    # 2. Check C# string literals
    cs_str_pattern = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')

    for cs_path in WIN_DIR.rglob("*.cs"):
        if not cs_path.is_file() or cs_path.name in WHITELIST_FILES or "bin" in cs_path.parts or "obj" in cs_path.parts:
            continue
        try:
            content = cs_path.read_text(encoding="utf-8")
        except Exception:
            continue
        clean_lines = []
        in_block_comment = False
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if in_block_comment:
                if "*/" in line:
                    in_block_comment = False
                    line = line.split("*/", 1)[1]
                else:
                    clean_lines.append("")
                    continue
            if "/*" in line and "*/" not in line:
                in_block_comment = True
                line = line.split("/*", 1)[0]
            # Strip single-line comments
            if "//" in line:
                line = line.split("//", 1)[0]
            clean_lines.append(line)

        for line_no, line in enumerate(clean_lines, start=1):
            if any(wp.search(line) for wp in WHITELIST_PATTERNS):
                continue
            for m in cs_str_pattern.finditer(line):
                lit = m.group(1)
                # Check for unescaped Turkish letters
                if any(c in TURKISH_CHARS for c in lit):
                    # Check if line is just Loc.T or Loc.Format key lookup
                    if 'Loc.T(' in line or 'Loc.Format(' in line:
                        continue
                    print(f"HATA [{cs_path.name}:{line_no}] C# sabit Türkçe metin: \"{lit}\"")
                    errors += 1

    if errors == 0:
        print("✓ Kaynak kodda sabit Türkçe metin bulunamadı (sıfır ihlal).\n")
    else:
        print(f"Toplam {errors} sabit metin ihlali.\n")
    return errors


def main():
    print("FETİH Masaüstü - Yerelleştirme Denetim Aracı")
    print("=" * 50)
    parity_err, resw_keys = check_resw_parity()
    uid_err = check_xaml_uids(resw_keys)
    hardcoded_err = check_hardcoded_strings()

    total = parity_err + uid_err + hardcoded_err
    print("=" * 50)
    if total == 0:
        print("SONUÇ: BÜTÜN DENETİMLER BAŞARIYLA GEÇTİ (0 İHLAL)")
        sys.exit(0)
    else:
        print(f"SONUÇ: {total} İHLAL TESPİT EDİLDİ.")
        sys.exit(1)


if __name__ == "__main__":
    main()
