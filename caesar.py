"""Caesar Cipher (klasik): C = (P + K) mod 26, P = (C - K) mod 26.

Diimplementasikan manual karena ini algoritma edukasi klasik.
Hanya huruf ASCII A-Z / a-z yang digeser; karakter lain dibiarkan.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Step:
    no: int
    char: str
    is_letter: bool
    start: int | None
    shift: int | None
    end: int | None
    out: str
    calc: str


@dataclass(frozen=True)
class Result:
    mode: str  # "enc" | "dec"
    shift: int
    input: str
    output: str
    steps: list[Step] = field(default_factory=list)


def validate_shift(raw) -> int:
    s = str(raw if raw is not None else "").strip()
    if not s:
        raise ValueError("Key Caesar tidak boleh kosong.")
    try:
        k = int(s)
    except ValueError:
        raise ValueError("Key Caesar harus berupa bilangan bulat (contoh: 3).") from None
    if not 1 <= k <= 25:
        raise ValueError("Key Caesar harus berada pada rentang 1–25.")
    return k


def _base(ch: str) -> int | None:
    if "A" <= ch <= "Z":
        return 65
    if "a" <= ch <= "z":
        return 97
    return None


def process(text: str, shift, decrypt: bool = False) -> Result:
    k = validate_shift(shift)
    steps: list[Step] = []
    out: list[str] = []
    for i, ch in enumerate(text, 1):
        base = _base(ch)
        if base is None:
            steps.append(Step(i, ch, False, None, None, None, ch, "Bukan huruf → tidak diubah"))
            out.append(ch)
            continue
        p = ord(ch) - base
        if decrypt:
            v = (p - k) % 26
            calc = f"({p} − {k}) mod 26 = {v}"
        else:
            v = (p + k) % 26
            calc = f"({p} + {k}) mod 26 = {v}"
        r = chr(v + base)
        steps.append(Step(i, ch, True, p, k, v, r, calc))
        out.append(r)
    return Result("dec" if decrypt else "enc", k, text, "".join(out), steps)


def encrypt(text: str, shift) -> str:
    return process(text, shift, False).output


def decrypt(text: str, shift) -> str:
    return process(text, shift, True).output
