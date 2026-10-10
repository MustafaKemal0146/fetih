"""Tests for edit tool robustness (#63: CRLF, BOM, fuzzy limits, guidance)."""

import os
from pathlib import Path
import pytest

from tools.file_operations import ShellFileOperations
from tools.environments.local import LocalEnvironment
from tools.fuzzy_match import fuzzy_find_and_replace


def test_crlf_file_preserved_with_lf_pattern(tmp_path: Path):
    """CRLF'li dosya + LF'li old_string → düzenleme başarılı, dosyanın tüm satırları CRLF kalır."""
    file_path = tmp_path / "crlf_test.txt"
    # Write initial content with CRLF line endings
    content_bytes = b"first line\r\nsecond line to edit\r\nthird line\r\n"
    file_path.write_bytes(content_bytes)

    env = LocalEnvironment(cwd=str(tmp_path))
    ops = ShellFileOperations(env, cwd=str(tmp_path))

    # Old string has LF line ending
    old_string = "second line to edit\n"
    new_string = "second line replacement\n"

    result = ops.patch_replace(str(file_path), old_string, new_string)
    assert result.success is True, f"Patch failed: {result.error}"

    # Verify all line endings on disk are CRLF
    updated_bytes = file_path.read_bytes()
    assert b"second line replacement\r\n" in updated_bytes
    assert b"first line\r\n" in updated_bytes
    assert b"third line\r\n" in updated_bytes
    # Ensure no lone \n without \r
    assert updated_bytes.count(b"\r\n") == 3
    assert updated_bytes.count(b"\n") == 3


def test_bom_file_preserved_after_patch(tmp_path: Path):
    """BOM'lu dosya düzenlenince ilk 3 bayt EF BB BF olarak kalır."""
    file_path = tmp_path / "bom_test.txt"
    # Write UTF-8 BOM + content
    initial_bytes = b"\xef\xbb\xbfname = 'alice'\nage = 30\n"
    file_path.write_bytes(initial_bytes)

    env = LocalEnvironment(cwd=str(tmp_path))
    ops = ShellFileOperations(env, cwd=str(tmp_path))

    result = ops.patch_replace(str(file_path), "name = 'alice'", "name = 'bob'")
    assert result.success is True, f"Patch failed: {result.error}"

    updated_bytes = file_path.read_bytes()
    assert updated_bytes[:3] == b"\xef\xbb\xbf", "BOM header was lost"
    assert b"name = 'bob'" in updated_bytes


def test_multiple_occurrences_fails_without_replace_all(tmp_path: Path):
    """Aynı satır dosyada 2 kez geçiyor, replace_all=false → hata ve yönlendirici mesaj; dosya değişmez."""
    file_path = tmp_path / "dup_test.txt"
    initial_bytes = b"line 1\nshared target\nline 2\nshared target\nline 3\n"
    file_path.write_bytes(initial_bytes)

    env = LocalEnvironment(cwd=str(tmp_path))
    ops = ShellFileOperations(env, cwd=str(tmp_path))

    result = ops.patch_replace(str(file_path), "shared target", "replaced", replace_all=False)
    assert result.success is False
    assert "Found 2 matches" in result.error
    assert "replace_all=True" in result.error

    # File must be untouched
    assert file_path.read_bytes() == initial_bytes


def test_tab_and_space_indentation_block_matches():
    """Girinti farkı (tab↔4 boşluk) olan blok başarıyla eşleşir."""
    content = "def test():\n\tx = 1\n\ty = 2\n\treturn x + y\n"
    old_string = "def test():\n    x = 1\n    y = 2\n    return x + y"
    new_string = "def test():\n    return 3"

    new_content, count, strategy, err = fuzzy_find_and_replace(content, old_string, new_string)
    assert count == 1
    assert err is None
    assert "return 3" in new_content


def test_oversized_fuzzy_match_rejected_with_hint():
    """Bulanık eşleşme sonucu len(match) > 3 * len(old_string) veya satır sayısı farkı > %50 ise reddet."""
    content = "prefix\nfoo(                                 x, y, z                                 ):\nsuffix\n"
    old_string = "foo( x, y, z ):"
    new_content, count, strategy, err = fuzzy_find_and_replace(
        content,
        old_string,
        "foo( a, b, c ):",
    )
    assert count == 0
    assert err is not None
    assert "Fuzzy match rejected" in err
    assert "differs significantly" in err
    assert "Closest matching lines:" in err
    assert new_content == content
