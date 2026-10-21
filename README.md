# encrypted-password-vault

一个**裝在 GitHub 上的加密密码容器**。明文口令整个互联网都看不到，只有你手里的那串「口令」能解开。

> 适用前提：放的是**不太重要的密码**。真金库请用 Bitwarden / 1Password。

---

## 它怎么工作

```
   你的口令  ──┐
                ├──>  vault.py  ──>  真实密码（只出现在终端里）
GitHub 密文  ──┘
```

- **GitHub 上只有密文**（`vault.enc`），仓库是公开的，任何人都能下载，但没有口令就是一堆随机字节
- **口令从不上传**、不落盘、不存在任何配置文件里
- 仓库是**公开的**，所以拉取密文**不需要任何凭据** —— 换台机器、起个 Docker 容器，给出口令就能用
- 加密构造：`PBKDF2-HMAC-SHA256`（20 万轮）派生密钥 → `HMAC-SHA256` 计数器模式做流加密 → `Encrypt-then-MAC` 做完整性认证
- **纯 Python 标准库**，零依赖，`pip install` 都不用

## 一分钟上手

```bash
# 1. 列出所有条目
VAULT_PASS='你的口令' python3 vault.py list

# 2. 取某个密码
VAULT_PASS='你的口令' python3 vault.py get github --user

# 若不想把口令写进 shell history，省略环境变量，会交互式询问：
python3 vault.py get github
```

把 `vault.py` 存到任意机器即可，它就一个文件。

## Docker（程序运行到哪儿都行）

```bash
docker build -t vault .

# 列出条目
docker run --rm -e VAULT_PASS='你的口令' vault list

# 取某条密码
docker run --rm -e VAULT_PASS='你的口令' vault get github --user

# 换自己的密文文件或远端地址
docker run --rm -v "$PWD/vault.enc:/app/vault.enc" \
  -e VAULT_PASS='你的口令' vault list --local

docker run --rm -e VAULT_URL='https://.../vault.enc' \
  -e VAULT_PASS='你的口令' vault list
```

## 录入你自己的密码

```bash
# 方式 A：从示例模板改起
cp vault.example.json my.json
$EDITOR my.json          # 改成你真实的账号密码

# 加密（会交互式让你设置口令）
python3 vault.py encrypt my.json -o vault.enc
rm my.json               # ← 明文删掉，别留在磁盘上

# 上传到 GitHub（需要 GITHUB_TOKEN，scope: repo）
GITHUB_TOKEN='ghp_xxx' python3 vault.py push
```

```bash
# 方式 B：在已有容器上直接改
python3 vault.py edit    # 解密 -> $EDITOR 打开 JSON -> 保存后自动重加密
GITHUB_TOKEN='ghp_xxx' python3 vault.py push
```

JSON 结构长这样，字段随意增删：

```json
{
  "github": {
    "username": "你的用户名",
    "password": "你的密码",
    "url": "https://github.com",
    "note": "备注",
    "otp": "可选，两步验证种子"
  }
}
```

## 全部命令

| 命令 | 作用 |
|---|---|
| `list` | 列出所有条目名、用户名、备注 |
| `get KEY...` | 取某条目密码，加 `--user` 连用户名一起输出 |
| `dump` | 导出全部明文 JSON |
| `encrypt IN.json -o vault.enc` | 明文 JSON → 密文 |
| `decrypt` | 密文 → 明文 JSON（结果只在终端） |
| `edit` | 解密 → 编辑器改 → 自动重加密 |
| `push` | 密文推到 GitHub（需 `GITHUB_TOKEN`） |
| `selftest` | 算法自检（加密往返 / 错误口令 / 篡改检测） |

**通用参数**：`--pass`、`--url`、`--file`、`--local`
**环境变量**：`VAULT_PASS`、`VAULT_URL`、`GITHUB_TOKEN`

## 刚推送完却说「口令错误」？

不是口令问题，是 `raw.githubusercontent.com` 的 **CDN 缓存**还在吐旧版密文，
刚 `push` 完的几分钟内尤其容易碰到。

工具会自己兜住：raw 地址解不开时自动改走 GitHub Contents API 重试一次，
成功后你会看到一行提示：

```
提示：raw CDN 返回的是旧版密文，已自动改走 GitHub API 取到最新版
```

看到这行说明已经取到最新版了，忽略即可。过一阵子 CDN 追上就安静了。
注意 Contents API 匿名调用限 60 次/小时，正常取密码用不完。

## 想改成私有仓库？

可以，但拉取就要带 GitHub token 了（`VAULT_URL` 里没法塞 header，需要改 `load_blob` 加鉴权头）。
对「密码不重要但要够用」这个场景，**公开仓库 + 强口令**反而更省事也更稳 —— 攻击者能拿到密文，但拿不到你的口令就解不开。

## 口令丢了怎么办

**没有后门，没有找回。** 密文是用你的口令派生密钥加密的，口令丢了数据就永久没了。
建议把口令本身记在你能记住的地方，或者单独离线存一份。
密文本身建议另外留一个备份副本 —— 密文丢了还能靠备份找回，口令丢了连同备份一起废。

## 安全边界（说清楚再决定要不要用）

- ✅ 密文公开也安全 —— 前提是**口令足够强**（建议 16 位以上随机，或 4 个以上随机词）
- ✅ 有完整性校验 —— 密文被改一个字节都会被检测出来
- ⚠️ **别在同一个 git commit 里同时提交明文和密文**
- ⚠️ 口令一旦进过 shell history 就可能被读走 —— 交互式输入更安全
- ⚠️ 这是自用轻量方案，**没有做审计、没有防侧信道**，别放银行和主邮箱密码
