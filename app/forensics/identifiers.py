from __future__ import annotations

import re

_FULLWIDTH = {chr(0xFF01 + offset): chr(0x21 + offset) for offset in range(94)}
_FULLWIDTH[chr(0x3000)] = " "
_TRANSLATION = str.maketrans(_FULLWIDTH)
_PUNCTUATION = re.compile(r"[\s\-_—–‐‑‒―/\\.,，。、;；:：'\"`·〔〕\[\]()（）【】{}<>《》#＃*＊]+")


def normalize_identifier(value: str | None) -> str:
    """归一化委托编号、案号别名和封识号。

    同一编号在补送文书上常有不同写法（全半角、标点、大小写、空格），
    比对前统一折算为大写、半角并去除常见标点，避免误建新案件。
    """
    if not value:
        return ""
    halfwidth = value.strip().translate(_TRANSLATION)
    return _PUNCTUATION.sub("", halfwidth).upper()
