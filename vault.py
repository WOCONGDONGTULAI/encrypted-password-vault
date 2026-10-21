#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vault.py — 零依赖加密密码容器

设计目标：
  · 密码数据以密文形式存放在公开的 GitHub 仓库里
  · 唯一的秘密是「口令」，口令不落盘、不上传、只在你脑子里
  · 任何地方（本机 / Docker / CI）只要有 Python 3，就能拉取密文 + 用口令解出明文

加密构造（纯标准库，无需 pip install）：
  PBKDF2-HMAC-SHA256(passphrase, salt, 200000) -> 64 字节
      enc_key = 前 32 字节  (HMAC-SHA256 CTR 模式密钥流)
      mac_key = 后 32 字节  (Encrypt-then-MAC 认证标签)
  nonce = 16 字节随机
  密文 = 明文 XOR keystream
  标签 = HMAC-SHA256(mac_key, nonce || 密文)
  文件 = "PVLT1" || salt || nonce || tag || ciphertext   (base64 编码后存文本)

用法：
  python3 vault.py list                     列出所有条目名
  python3 vault.py get github               取某条目的密码
  python3 vault.py get github --user        同时输出用户名
  python3 vault.py dump                     输出全部明文 JSON
  python3 vault.py encrypt vault.json       把本地明文 JSON 加密成密文
  python3 vault.py decrypt                  把密文解成本地明文 JSON
  python3 vault.py edit                     解密 -> 编辑器改 -> 重新加密
  python3 vault.py push                     把本地密文推到 GitHub
  python3 vault.py selftest                 自检（CI 用）

口令来源优先级： --pass 参数  >  VAULT_PASS 环境变量  >  交互式输入
远端地址优先级： --url 参数   >  VAULT_URL 环境变量   >  仓库默认地址
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import subprocess
import sys
import tempfile
import urllib.request

# ---------------------------------------------------------------- 常量

MAGIC = b"PVLT1"
SALT_LEN = 16
NONCE_LEN = 16
TAG_LEN = 32
ITERATIONS = 200_000

REPO_RAW = "https://raw.githubusercontent.com/WOCONGDONGTULAI/encrypted-password-vault/main"
DEFAULT_URL = REPO_RAW + "/vault.enc"
DEFAULT_FILE = os.environ.get("VAULT_FILE") or "vault.enc"

ENV_PASS = "VAULT_PASS"
ENV_URL = "VAULT_URL"
ENV_TOKEN = "GITHUB_TOKEN"


# ---------------------------------------------------------------- 密码学核心

def derive_keys(passphrase: bytes, salt: bytes):
    """口令 -> (enc_key, mac_key)"""
    raw = hashlib.pbkdf2_hmac("sha256", passphrase, salt, ITERATIONS, 64)
    return raw[:32], raw[32:64]


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """HMAC-SHA256 计数器模式密钥流"""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(enc_key, nonce + struct.pack(">I", counter), hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def encrypt_bytes(plaintext: bytes, passphrase: bytes) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    enc_key, mac_key = derive_keys(passphrase, salt)

    ks = _keystream(enc_key, nonce, len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, ks))
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return MAGIC + salt + nonce + tag + ciphertext


def decrypt_bytes(blob: bytes, passphrase: bytes) -> bytes:
    header_len = len(MAGIC) + SALT_LEN + NONCE_LEN + TAG_LEN
    if len(blob) < header_len:
        raise ValueError("密文过短或已损坏")
    if not hmac.compare_digest(blob[:len(MAGIC)], MAGIC):
        raise ValueError("密文格式不正确（缺少 PVLT1 头）")

    pos = len(MAGIC)
    salt = blob[pos:pos + SALT_LEN];            pos += SALT_LEN
    nonce = blob[pos:pos + NONCE_LEN];          pos += NONCE_LEN
    tag = blob[pos:pos + TAG_LEN];              pos += TAG_LEN
    ciphertext = blob[pos:]

    enc_key, mac_key = derive_keys(passphrase, salt)

    expected = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("口令错误，或密文被篡改（认证标签不匹配）")

    ks = _keystream(enc_key, nonce, len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, ks))


# ---------------------------------------------------------------- 读写辅助

def load_blob(source: str) -> bytes:
    """从 URL 或本地文件读取密文，自动识别 base64 / 二进制 / GitHub API JSON"""
    if source.startswith("http://") or source.startswith("https://"):
        req = urllib.request.Request(source, headers={
            "User-Agent": "vault.py",
            "Accept": "application/vnd.github+json",
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        # GitHub Contents API 返回 JSON，密文在 base64 的 content 字段里
        if data[:1] == b"{":
            info = json.loads(data.decode("utf-8"))
            if "content" in info:
                data = base64.b64decode(info["content"])
            elif "message" in info:
                raise ValueError("GitHub API: %s" % info["message"])
    else:
        with open(source, "rb") as f:
            data = f.read()

    data = data.strip()
    # 二进制格式
    if data.startswith(MAGIC):
        return data
    # base64 文本格式
    try:
        decoded = base64.b64decode(data, validate=False)
        if decoded.startswith(MAGIC):
            return decoded
    except Exception:
        pass
    raise ValueError("无法识别的密文格式：%s" % source)


def save_encrypted(blob: bytes, path: str):
    """以 base64 文本形式写密文（便于 git / 复制粘贴）"""
    b64 = base64.b64encode(blob).decode("ascii")
    wrapped = "\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))
    with open(path, "w", encoding="utf-8") as f:
        f.write(wrapped + "\n")


def read_source(args) -> str:
    """确定密文来源"""
    if getattr(args, "local", False):
        return getattr(args, "file", DEFAULT_FILE)
    for candidate in (
        getattr(args, "url", None),
        os.environ.get(ENV_URL),
    ):
        if candidate:
            return candidate
    return DEFAULT_URL


def write_source(args) -> str:
    """
    写入类命令的读取源：本地文件优先。

    防止连续写入时后一次覆盖前一次 —— 若上次写完没推送，
    这次必须基于本地那份继续改，而不是重新拉远端旧版。
    """
    local = getattr(args, "file", DEFAULT_FILE)
    if os.path.exists(local):
        return local
    return read_source(args)


def read_passphrase(args) -> bytes:
    """确定口令"""
    candidate = getattr(args, "pass_arg", None) or os.environ.get(ENV_PASS)
    if candidate:
        return candidate.encode("utf-8")
    pwd = getpass.getpass("口令: ")
    if not pwd:
        sys.exit("错误：口令不能为空")
    return pwd.encode("utf-8")


def ask_new_passphrase():
    p1 = getpass.getpass("设置口令: ")
    p2 = getpass.getpass("再确认一次: ")
    if p1 != p2:
        sys.exit("错误：两次输入的口令不一致")
    if not p1:
        sys.exit("错误：口令不能为空")
    if len(p1) < 8:
        print("警告：口令短于 8 位，安全性较弱", file=sys.stderr)
    return p1.encode("utf-8")


def decrypt_to_obj(source: str, passphrase: bytes) -> dict:
    blob = load_blob(source)
    plaintext = decrypt_bytes(blob, passphrase)
    return json.loads(plaintext.decode("utf-8"))


def api_fallback_urls(source: str):
    """
    由 GitHub raw 地址推出对应的 Contents API 地址。

    raw.githubusercontent.com 有 CDN 缓存，刚推送的新密文可能几分钟后才生效，
    期间会返回「有效但过期」的旧密文 —— 它能被正常解开，只是内容落后，
    所以不能靠「解不开」来发现。Contents API 不经过这层缓存，是权威源。
    """
    m = re.match(r"https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$",
                 source)
    if not m:
        return []
    owner, repo, branch, path = m.groups()
    return ["https://api.github.com/repos/%s/%s/contents/%s?ref=%s"
            % (owner, repo, path, branch)]


def fetch_decrypted(source: str, passphrase: bytes) -> dict:
    """
    解密取数据。GitHub 仓库优先走 Contents API（权威、无 CDN 缓存），
    API 不可用时（如匿名限流 60 次/小时）才退回 raw 地址。
    """
    ordered = api_fallback_urls(source) + [source]
    last_error = None
    for idx, url in enumerate(ordered):
        try:
            return decrypt_to_obj(url, passphrase)
        except ValueError as e:
            last_error = e
            # 口令本身错了的话，换地址也没用
            if "标签不匹配" in str(e) and idx == 0 and len(ordered) > 1:
                decrypt_to_obj(source, passphrase)  # 用 raw 复核一次，排除 CDN 干扰
    raise last_error


# ---------------------------------------------------------------- 子命令

def emit_json(obj):
    """给 AI / 脚本用的机读输出，保证一行一个 JSON"""
    print(json.dumps(obj, ensure_ascii=False))


def cmd_list(args):
    data = fetch_decrypted(read_source(args), read_passphrase(args))
    if getattr(args, "json", False):
        emit_json(sorted(data.keys()))
        return
    if not data:
        print("(容器为空)")
        return
    width = max(len(k) for k in data)
    for key in sorted(data):
        entry = data[key]
        note = entry.get("note", "") if isinstance(entry, dict) else ""
        user = entry.get("username", "") if isinstance(entry, dict) else ""
        line = key.ljust(width) + "  "
        if user:
            line += user.ljust(24)
        if note:
            line += "  # " + note
        print(line.rstrip())


def cmd_get(args):
    data = fetch_decrypted(read_source(args), read_passphrase(args))
    missing = [k for k in args.keys if k not in data]

    if getattr(args, "json", False):
        hit = {k: data[k] for k in args.keys if k in data}
        if len(args.keys) == 1 and hit:
            emit_json(hit[args.keys[0]])
        else:
            emit_json(hit)
        if missing:
            print("未找到条目：%s" % ", ".join(missing), file=sys.stderr)
            sys.exit(1)
        return

    for key in args.keys:
        if key not in data:
            print("未找到条目：%s" % key, file=sys.stderr)
            continue
        entry = data[key]
        if isinstance(entry, dict):
            if getattr(args, "user", False) and entry.get("username"):
                print("用户名: %s" % entry.get("username"))
            print("密码:   %s" % entry.get("password", ""))
            for extra in ("email", "url", "otp", "note"):
                if entry.get(extra):
                    print("%s: %s" % (extra.ljust(6), entry[extra]))
        else:
            print(entry)
    if missing:
        sys.exit(1)


def _write_back(data: dict, passphrase: bytes, args) -> bool:
    """重新加密落盘，并在有 token 且要求推送时同步到 GitHub"""
    plaintext = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    blob = encrypt_bytes(plaintext, passphrase)
    save_encrypted(blob, getattr(args, "file", DEFAULT_FILE))

    if getattr(args, "push", False) and os.environ.get(ENV_TOKEN):
        cmd_push(args)
        return True
    print("已写入本地 %s" % getattr(args, "file", DEFAULT_FILE), file=sys.stderr)
    if getattr(args, "push", False):
        print("（未设置 GITHUB_TOKEN，跳过推送）", file=sys.stderr)
    return False


def cmd_set(args):
    """新增或更新一条（幂等），AI / 脚本主要用这个写"""
    if not any([args.username, args.password, args.email, args.url,
                args.otp, args.note, args.field]) and not args.replace:
        sys.exit("错误：至少给一个要写入的字段")

    passphrase = read_passphrase(args)
    source = write_source(args)
    try:
        data = fetch_decrypted(source, passphrase)
    except ValueError:
        if getattr(args, "create", False):
            data = {}
        else:
            raise

    entry = data.get(args.key)
    if not isinstance(entry, dict):
        entry = {}
    if args.replace:
        entry = {}

    for attr, key in (("username", "username"), ("password", "password"),
                      ("email", "email"), ("url", "url"),
                      ("otp", "otp"), ("note", "note")):
        val = getattr(args, attr, None)
        if val is not None:
            entry[key] = val

    for raw in getattr(args, "field", None) or []:
        if "=" not in raw:
            sys.exit("错误：--field 需要写成 key=value 形式：%s" % raw)
        k, v = raw.split("=", 1)
        entry[k.strip()] = v

    created = args.key not in data
    data[args.key] = entry

    pushed = _write_back(data, passphrase, args)
    emit_json({
        "ok": True,
        "key": args.key,
        "action": "created" if created else "updated",
        "pushed": pushed,
        "entry": entry,
    })


def cmd_rm(args):
    """删除一条"""
    passphrase = read_passphrase(args)
    data = fetch_decrypted(write_source(args), passphrase)
    if args.key not in data:
        sys.exit("错误：没有这个条目 %s" % args.key)
    del data[args.key]
    pushed = _write_back(data, passphrase, args)
    emit_json({"ok": True, "key": args.key, "action": "deleted", "pushed": pushed})


def cmd_dump(args):
    data = fetch_decrypted(read_source(args), read_passphrase(args))
    print(json.dumps(data, ensure_ascii=False, indent=2))


def cmd_encrypt(args):
    """把本地明文 JSON 加密成密文"""
    src = args.input
    if src == "-":
        plaintext = sys.stdin.buffer.read()
    else:
        with open(src, "rb") as f:
            plaintext = f.read()
    # 校验是合法 JSON
    json.loads(plaintext.decode("utf-8"))

    if args.pass_cmd:
        passphrase = args.pass_cmd.encode("utf-8")
    else:
        passphrase = os.environ.get(ENV_PASS, "").encode("utf-8") or ask_new_passphrase()

    blob = encrypt_bytes(plaintext, passphrase)
    save_encrypted(blob, args.output)
    print("已加密写入：%s（%d 字节明文 -> %d 字节密文）" % (args.output, len(plaintext), len(blob)))


def cmd_decrypt_out(args):
    """把密文解成本地明文 JSON"""
    data = fetch_decrypted(read_source(args), read_passphrase(args))
    text = json.dumps(data, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("已写入明文：%s（用完请立即删除）" % args.out)
    else:
        print(text)


def cmd_edit(args):
    """解密 -> 编辑器修改 -> 重新加密"""
    source = read_source(args)
    passphrase = read_passphrase(args)
    data = fetch_decrypted(source, passphrase)

    editor = os.environ.get("EDITOR") or os.environ.get("VISUAL") or "vi"
    with tempfile.NamedTemporaryFile("w+", suffix=".json", encoding="utf-8", delete=False) as tf:
        json.dump(data, tf, ensure_ascii=False, indent=2)
        tf.write("\n")
        tmp_path = tf.name

    try:
        subprocess.call([editor, tmp_path])
        with open(tmp_path, "r", encoding="utf-8") as f:
            new_data = json.load(f)
    finally:
        os.unlink(tmp_path)

    plaintext = json.dumps(new_data, ensure_ascii=False, indent=2).encode("utf-8")
    blob = encrypt_bytes(plaintext, passphrase)
    save_encrypted(blob, getattr(args, "file", DEFAULT_FILE))
    print("已重新加密：%s" % getattr(args, "file", DEFAULT_FILE))


def cmd_push(args):
    """把本地密文推到 GitHub（需要 GITHUB_TOKEN）"""
    token = os.environ.get(ENV_TOKEN)
    if not token:
        sys.exit("错误：请设置环境变量 GITHUB_TOKEN")

    repo = getattr(args, "repo", None) or "WOCONGDONGTULAI/encrypted-password-vault"
    path = getattr(args, "path", None) or "vault.enc"
    with open(getattr(args, "file", DEFAULT_FILE), "r", encoding="utf-8") as f:
        content = f.read()

    import urllib.error

    api = "https://api.github.com/repos/%s/contents/%s" % (repo, path)
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "vault.py",
    }

    # 更新已有文件必须带上它当前的 sha，否则 GitHub 返回 422 "sha wasn't supplied"
    body = {
        "message": "vault: update encrypted data",
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
    }
    try:
        probe = urllib.request.Request(api, headers=headers)
        existing = json.load(urllib.request.urlopen(probe, timeout=30))
        body["sha"] = existing["sha"]
    except urllib.error.HTTPError:
        pass  # 文件还不存在，新建即可
    except Exception:
        pass

    req = urllib.request.Request(
        api,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="PUT",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            print("已推送到 https://github.com/%s/blob/main/%s" % (repo, path))
    except urllib.error.HTTPError as e:
        sys.exit("推送失败：HTTP %s %s" % (e.code, e.read().decode("utf-8", "ignore")[:300]))


def cmd_selftest(args):
    """算法自检：加密 -> 解密 -> 错误口令必须失败"""
    ok = True

    sample = json.dumps({"demo": {"username": "u", "password": "p"}}, ensure_ascii=False).encode()
    pwd = b"correct horse battery staple"

    blob = encrypt_bytes(sample, pwd)
    if decrypt_bytes(blob, pwd) != sample:
        print("FAIL 正常加解密往返"); ok = False
    else:
        print("PASS 正常加解密往返")

    try:
        decrypt_bytes(blob, b"wrong-passphrase")
        print("FAIL 错误口令应当报错"); ok = False
    except ValueError:
        print("PASS 错误口令被拒绝")

    tampered = bytearray(blob); tampered[-1] ^= 0x01
    try:
        decrypt_bytes(bytes(tampered), pwd)
        print("FAIL 篡改应当报错"); ok = False
    except ValueError:
        print("PASS 密文篡改被检测")

    # base64 往返（对应磁盘上的文本形态）
    b64 = base64.b64encode(blob)
    if decrypt_bytes(base64.b64decode(b64), pwd) != sample:
        print("FAIL base64 往返"); ok = False
    else:
        print("PASS base64 往返")

    print("----")
    print("自检通过" if ok else "自检失败")
    sys.exit(0 if ok else 1)


# ---------------------------------------------------------------- CLI

def build_parser():
    p = argparse.ArgumentParser(
        prog="vault.py",
        description="零依赖加密密码容器：密文存 GitHub，口令在你手里",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="cmd")

    def add_common(sp, source_url=True):
        sp.add_argument("--pass", dest="pass_arg", help="口令（也可用环境变量 VAULT_PASS）")
        # set / rm 里 --url 是条目字段（网址），故写入类命令改用 --remote-url
        sp.add_argument("--remote-url" if not source_url else "--url",
                        dest="url",
                        help="密文远端地址（也可用 VAULT_URL）")
        sp.add_argument("--file", default=DEFAULT_FILE, help="本地密文文件，默认 vault.enc")
        sp.add_argument("--local", action="store_true", help="读取本地密文而非远端")

    def add_write(sp):
        sp.add_argument("--push", action="store_true",
                       help="写完后推到 GitHub（需 GITHUB_TOKEN）")

    sp = sub.add_parser("list", help="列出所有条目")
    sp.add_argument("--json", action="store_true", help="输出 JSON 数组（给程序读）")
    add_common(sp); sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("get", help="查看某个条目的密码")
    sp.add_argument("keys", nargs="+")
    sp.add_argument("--user", action="store_true", help="同时输出用户名")
    sp.add_argument("--json", action="store_true", help="输出 JSON（给程序读）")
    add_common(sp); sp.set_defaults(func=cmd_get)

    sp = sub.add_parser("dump", help="导出全部明文 JSON")
    add_common(sp); sp.set_defaults(func=cmd_dump)

    sp = sub.add_parser("set", help="新增或更新一条（幂等，写操作主要用这个）")
    sp.add_argument("key")
    sp.add_argument("--username")
    sp.add_argument("--password")
    sp.add_argument("--email")
    sp.add_argument("--url")
    sp.add_argument("--otp")
    sp.add_argument("--note")
    sp.add_argument("--field", action="append", metavar="K=V",
                    help="任意额外字段，可重复")
    sp.add_argument("--replace", action="store_true", help="整条覆盖而非合并")
    sp.add_argument("--create", action="store_true", help="容器不存在时创建新的")
    add_common(sp, source_url=False); add_write(sp); sp.set_defaults(func=cmd_set)

    sp = sub.add_parser("rm", help="删除一条")
    sp.add_argument("key")
    add_common(sp, source_url=False); add_write(sp); sp.set_defaults(func=cmd_rm)

    sp = sub.add_parser("encrypt", help="把本地明文 JSON 加密成密文")
    sp.add_argument("input", help="明文 JSON 文件，- 表示 stdin")
    sp.add_argument("-o", "--output", default=DEFAULT_FILE)
    sp.add_argument("--pass-cmd", dest="pass_cmd", help="直接给出口令（脚本用，注意 shell history）")
    sp.set_defaults(func=cmd_encrypt)

    sp = sub.add_parser("decrypt", help="解密成明文 JSON")
    sp.add_argument("-o", "--out", help="写入文件；不指定则打印到终端")
    add_common(sp); sp.set_defaults(func=cmd_decrypt_out)

    sp = sub.add_parser("edit", help="解密 -> 编辑器修改 -> 重新加密")
    add_common(sp); sp.set_defaults(func=cmd_edit)

    sp = sub.add_parser("push", help="把本地密文推到 GitHub")
    sp.add_argument("--repo", default="WOCONGDONGTULAI/encrypted-password-vault")
    sp.add_argument("--path", default="vault.enc")
    add_common(sp); sp.set_defaults(func=cmd_push)

    sub.add_parser("selftest", help="算法自检").set_defaults(func=cmd_selftest)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        sys.exit(1)
    try:
        args.func(args)
    except ValueError as e:
        sys.exit("错误：%s" % e)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
