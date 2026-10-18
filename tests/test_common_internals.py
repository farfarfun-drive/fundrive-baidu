"""针对 `fundrives.baidu.common` 下几个内部工具的回归测试。

这些用例对应统一 lint 规则集（2026-10）时实测发现的两个问题：

1. `SimpleCryptography.encrypt()` / `.decrypt()` 把数据拷成不可变的 `bytes` 再交给原地
   改写的 `crypt()`，任何调用都直接 `TypeError` —— 这条加密路径（`io.py` 的
   SimpleCipher 模式）从来没能跑通，也没有任何测试碰过它。
2. `RAPID_UPLOAD_TABLE_COLS` 把建表 DDL 里的 `UNIQUE(...)` 约束行当成了一个列名，
   解析出 14 个名字而 `SELECT *` 只有 13 列。结果一直是对的，纯粹因为 `zip()` 会按较短
   的一边截断 —— 一旦给 zip 加 `strict=True` 就会炸。
"""

import sqlite3
import tempfile
from pathlib import Path

from fundrives.baidu.common.localstorage import (
    CREATE_RAPID_UPLOAD_TABLE,
    RAPID_UPLOAD_TABLE,
    RAPID_UPLOAD_TABLE_COLS,
    RapidUploadInfo,
)
from fundrives.baidu.common.simple_cipher import SimpleCryptography
from fundrives.baidu.utils import human_size


class TestSimpleCryptography:
    def test_roundtrip_all_byte_values(self):
        """全 256 个字节值都要能原样回转。"""
        crypto = SimpleCryptography("k")
        original = bytes(range(256))

        encrypted = crypto.encrypt(original)
        assert isinstance(encrypted, bytes)
        assert encrypted != original, "加密后不应与原文相同"
        assert bytes(crypto.decrypt(encrypted)) == original

    def test_does_not_mutate_input(self):
        """入参是调用方的数据，不能被原地改写。"""
        crypto = SimpleCryptography("k")
        data = bytearray(b"hello world")
        before = bytes(data)

        crypto.encrypt(data)

        assert bytes(data) == before

    def test_same_key_same_mapping(self):
        """同一个 key 必须给出同一套映射，否则跨进程解不开。"""
        a = SimpleCryptography("key-1").encrypt(b"payload")
        b = SimpleCryptography("key-1").encrypt(b"payload")
        assert a == b
        assert SimpleCryptography("key-2").encrypt(b"payload") != a


class TestRapidUploadTableCols:
    def test_cols_match_select_star(self):
        """解析出的列名必须与 `SELECT *` 的真实列逐项一致。"""
        con = sqlite3.connect(":memory:")
        con.execute(CREATE_RAPID_UPLOAD_TABLE)
        actual = [
            d[0] for d in con.execute(f"SELECT * FROM {RAPID_UPLOAD_TABLE}").description
        ]

        assert actual == RAPID_UPLOAD_TABLE_COLS

    def test_no_table_constraint_leaks_in(self):
        """表级约束（UNIQUE / PRIMARY KEY ...）不能被当成列名。"""
        for name in RAPID_UPLOAD_TABLE_COLS:
            assert not name.upper().startswith(
                ("UNIQUE", "PRIMARY", "FOREIGN", "CHECK", "CONSTRAINT")
            ), f"{name} 是约束而不是列"

    def test_read_path_returns_every_column(self):
        """写进去再读回来，13 个字段都要在，值要对。"""
        db = Path(tempfile.mkdtemp()) / "rapid.db"
        store = RapidUploadInfo(str(db))
        store.insert(
            slice_md5="a" * 32,
            content_md5="b" * 32,
            content_crc32=0,
            content_length=123,
            filename="x.bin",
        )

        rows = store.list()

        assert len(rows) == 1
        assert list(rows[0].keys()) == RAPID_UPLOAD_TABLE_COLS
        assert rows[0]["content_length"] == 123
        assert rows[0]["filename"] == "x.bin"


class TestHumanSize:
    def test_units_are_not_dropped(self):
        """human_size 靠循环变量泄漏出单位（见那处 noqa: B007），单位不能丢。"""
        assert human_size(0) == "0 B"
        assert human_size(512) == "512 B"
        assert human_size(1024) == "1 KB"
        assert human_size(1536) == "1.5 KB"
        assert human_size(1024**4) == "1 TB"

    def test_above_max_unit_falls_back(self):
        """超过 1024TB 时循环不会 break，兜底分支要把多除的那次乘回去。"""
        assert human_size(1024**5) == "1024 TB"
