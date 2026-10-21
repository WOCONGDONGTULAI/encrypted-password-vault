# AGENTS.md

给被调用来操作这个密码容器的 AI / Agent 看的说明书。
如果你是人类，直接看 [README.md](./README.md) 就够了。

---

## 0. 一句话搞清楚你在动什么

这是一个**加密密码容器**。GitHub 上存的是密文，
**唯一的秘密是口令**，口令不在任何文件里。

```
    口令  ──┐
             ├──>  vault.py  ──>  真实密码（只在 stdout）
远端密文 ──┘
```

你（AI）被允许：读取、新增、修改、删除条目。
你不许：把口令或明文密码写进任何文件、commit、日志、issue、PR。

---

## 1. 取工具

`vault.py` 是单个文件，零依赖，不需要 `pip install`。

```bash
python3 -c "
import json,urllib.request
c=json.load(urllib.request.urlopen('https://api.github.com/repos/WOCONGDONGTULAI/encrypted-password-vault/contents/vault.py'))
open('vault.py','wb').write(__import__('base64').b64decode(c['content']))
"
```

> 用 Contents API 拉，不要用 `raw.githubusercontent.com`。raw 有 CDN 缓存，
> 几分钟内可能给你旧版。工具自己已经优先走 API，但取工具这一下你也别踩坑。

## 2. 配置两个环境变量（建议在容器/会话级设置，别写进 shell rc）

```bash
export VAULT_PASS='口令'      # 必填，容器里的所有数据靠它
export GITHUB_TOKEN='ghp_xxx' # 只在需要「写入并推送」时才要，scope: repo
```

只读取密码的话**不需要 token**，仓库是公开的。

## 3. 命令

所有命令加 `--json` 就输出单行 JSON，**给程序读请一律加 `--json`**。

### 读

```bash
python3 vault.py list --json                 # ["github","email",...]
python3 vault.py get github --json           # 整条的 JSON
python3 vault.py get github email --json     # 多条
python3 vault.py dump                        # 全部明文 JSON
```

`get --json` 的返回形式：
- 查一个 key → 返回**该条对象**（如 `{"username":"a","password":"b"}`）
- 查多个 key → 返回 `{key: 对象, ...}`
- 没找到 → stdout `{}`，stderr 提示，**退出码非 0**（可以靠这个判断分支）

### 写

```bash
# 新增或更新（幂等；只给定字段会被合并进已有条目）
python3 vault.py set github --username alice --password s3cret --note 主账号 --push

# 任意额外字段
python3 vault.py set vpn --password p1 --field endpoint=vpn.example.com --field proto=wireguard --push

# 整条覆盖而不是合并
python3 vault.py set github --username bob --password newpw --replace --push

# 删除
python3 vault.py rm old-entry --push
```

`set` / `rm` 默认写本地文件再推送。**不给 `GITHUB_TOKEN` 就只写本地不推送**，
此时后续 `-read` 要加 `--local`，否则读到的是远端旧版。

`set` / `rm` 也返回 JSON：`{"ok":true,"key":"github","action":"created|updated|deleted","pushed":true,"entry":{...}}`

---

## 4. 必须遵守的规矩

1. **口令永远只出现在 `VAULT_PASS` 里**，不要拼进命令行、不要写文件、不要在输出里回显。
2. **不要把明文密码输出到会被长期留存的地方** —— 需要给用户看时才打印，别写进 commit message、别写进 issue。
3. **不要提交明文 JSON**。仓库根目录的 `.gitignore` 已经拦 `*.json`，别用 `git add -f` 绕过。
4. **任务结束后删掉本地 `vault.enc`**（`rm -f vault.enc`），不要在工作目录留密文副本。
5. **不要试图「优化」加解密算法或绕过校验**。认证标签不匹配就是口令错或被篡改，别重试、别猜口令。
6. 遇到 `标签不匹配` 报错，**直接告诉用户口令不对**，自己不要反复试不同口令。

## 5. 已知坑

- **刚 push 完立刻读可能拿到旧数据**：GitHub raw CDN 有缓存。
  工具已默认走 Contents API 规避；如果它还是给了旧数据，等一两分钟再试。
- **Contents API 匿名限 60 次/小时**。频繁读取建议加 token，或先 `list --json` 一次缓存结果。
- **口令丢了救不回来**，没有后门，没有找回。

## 6. 典型任务模板

**用户说「帮我查一下 github 的密码」**

```bash
export VAULT_PASS='口令'
python3 vault.py get github --json
# -> {"username":"...","password":"..."}
# 只输出用户要的那个字段，不要把整份 JSON 贴出去
```

**用户说「把这个账号存进去」**

```bash
export VAULT_PASS='口令'; export GITHUB_TOKEN='...'
python3 vault.py set <起个名字> --username <账号> --password <密码> --push
rm -f vault.enc
```
