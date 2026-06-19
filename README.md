[English](./README.en.md) | **简体中文**

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:b91c1c,100:f59e0b&height=200&section=header&text=PromptShield&fontSize=72&fontColor=ffffff&fontAlignY=38&desc=%E5%9C%A8%E4%BD%A0%E7%9A%84%20Coding%20Agent%20%E8%AF%BB%E5%8F%96%E4%BB%A3%E7%A0%81%E4%B9%8B%E5%89%8D%EF%BC%8C%E6%8B%A6%E6%88%AA%E9%9A%90%E8%97%8F%E7%9A%84%E6%8F%90%E7%A4%BA%E8%AF%8D%E6%B3%A8%E5%85%A5&descSize=16&descAlignY=58" alt="PromptShield" />
</p>

<p align="center">
  <strong>PromptShield 是在 Claude Code / Cursor 读取代码前，拦截隐藏注入指令的扫描器。</strong>
</p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <img src="https://img.shields.io/badge/python-3.12%2B-blue.svg" alt="Python 3.12+" />
  <img src="https://img.shields.io/badge/release-v0.1.0-f59e0b.svg" alt="Release v0.1.0" />
  <a href="./.github/workflows/ci.yml"><img src="https://img.shields.io/badge/CI-ruff%20%2B%20pytest-success.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs welcome" />
  <br/>
  <img src="https://img.shields.io/badge/agentic-coding%20security-7c3aed.svg" alt="Agentic coding security" />
  <img src="https://img.shields.io/badge/offline-no%20API%20key-0ea5e9.svg" alt="Offline, no API key" />
</p>

---

## 目录

- [为什么需要它](#为什么需要它)
- [60 秒上手](#60-秒上手)
- [演示](#演示)
- [它扫描什么](#它扫描什么)
- [集成到 CI](#集成到-ci)
- [基线工作流](#基线工作流)
- [对比同类方案](#对比同类方案)
- [配置项](#配置项)
- [付费 · PromptShield Cloud](#付费--promptshield-cloud)
- [路线图](#路线图)
- [许可证与贡献](#许可证与贡献)
- [Share this](#share-this)

---

## 为什么需要它

Claude Code、Cursor 这类 coding agent 会把第三方仓库、PR、代码注释、commit message **直接读进上下文**，然后照着读到的内容去执行——但在仓库和 agent 之间，没有任何一层把这些代码**当作提示词**来扫描。

这正是 [r/LocalLLaMA 那条 "dev sneaks data-nuking prompt injection into their code"](https://www.reddit.com/r/LocalLLaMA/comments/1trdnap/fed_up_with_vibe_coders_dev_sneaks_datanuking/) 帖子揭露的攻击面：有人把一句 `rm -rf /` 的销毁指令藏进注释里，等着别人的 agent 读到并执行。人工 review 的眼睛追不上 agent 的阅读吞吐——这是一种**结构性的吞吐量不对称**，不是"再仔细一点"能解决的。

**Why now：** agentic coding 的普及，把"agent 读到的代码"变成了"agent 会照做的代码"。Cursor 已有上百万开发者，[affaan-m/everything-claude-code](https://github.com/affaan-m/everything-claude-code) 这类 Claude Code 实战仓库让 agent 例行拉取外部 PR 与 vendored OSS。两年前主流还是人把片段复制进聊天框，agent 没有对外部仓库自主读取并执行的回路；MCP 与工具调用的扩张才让注入有了通往"动作"的路径。PromptShield 就是在 agent 读取之前，把这条注入面卡在 CI 里——离线、零 API key、几秒出结果。

PromptShield 引入的新原语是 **Finding over a code-as-prompt surface**：把 agent 将要*读取*的源文本视为攻击向量，而不是当作可执行代码或要做 CVE 扫描的依赖包。这与聊天越狱扫描（Garak）和依赖漏洞扫描（Socket / Snyk）是不同的威胁类别。

---

## <img src="https://api.iconify.design/tabler:topology-star-3.svg?color=%23b91c1c&width=24" height="22" align="absmiddle" alt="" /> 架构

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/atlas-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/atlas-light.svg">
    <img src="./assets/atlas-light.svg" width="880" alt="架构：仓库 / git diff / PR JSON 经 Collectors 拆成代码即提示词的 Surface，YAML 规则引擎把每段映射成五类注入 Finding，基线抑制已接受项，Report 打印发现表并给出 CI 退出码">
  </picture>
</p>

一次扫描接收三种 **Source**——整个仓库、一段 `git diff`，或一份 `gh api` 的 PR-files JSON——**Collectors** 把它们拆解成 agent 真正会*读到*的 **Surface**（注释、docstring、commit message、markdown、配置、字符串字面量）。**Rule Engine** 用 YAML 规则集把每段 Surface 映射成横跨五类注入的 **Finding**，高噪声规则用 `requires` 二次门控压低误报；**基线**抑制已接受的历史 Finding。最后 **Report** 打印发现表（或 JSON），只要出现任何 HIGH 就 `exit 1`——整条链路离线、零 API key，卡在 agent 读取之前的 CI 门里。

---

## 60 秒上手

```bash
pip install promptshield           # 或: uvx promptshield
promptshield scan .                # 扫描当前仓库，打印发现表
echo "退出码: $?"                  # 出现任何 HIGH 即为 1，可直接接入 CI
```

<details>
<summary>示例输出（扫描内置的恶意 PR 复现样本）</summary>

```text
$ promptshield scan ./tests/fixtures/malicious_pr

                          PromptShield findings
┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━┓
┃ Sev  ┃ Rule                          ┃ Category        ┃ Location    ┃ Surf ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━┩
│ HIGH │ PS001-instruction-override-d… │ instruction_ov… │ utils.py:11 │ com… │
│ HIGH │ PS010-destructive-shell       │ data_destructi… │ utils.py:12 │ com… │
│ HIGH │ PS011-destructive-instruction │ data_destructi… │ utils.py:17 │ doc… │
│ HIGH │ PS020-exfil-secrets           │ exfiltration    │ utils.py:17 │ doc… │
└──────┴───────────────────────────────┴─────────────────┴─────────────┴──────┘

Scanned 31 surfaces · 8 HIGH · 0 MED · 0 LOW
✗ HIGH findings present — exit 1 (CI gate failed).
```

每一条 HIGH 都会附带一句 `why`，说明它为什么是注入——精度优先于召回，让你信得过每一个告警。
</details>

`promptshield scan .` 不需要 `git` 或 `gh`，也不发任何网络请求。只有用 `--diff` / `--pr` 时才会把它们当子进程调用。

---

## <img src="https://api.iconify.design/tabler:photo.svg?color=%23b91c1c&width=24" height="22" align="absmiddle" alt="" /> 演示

脚本：扫描 `malicious_pr` → 发现表 → `--pr` 退出码 1 让 CI 变红 → 现场命中真实的 Reddit 数据销毁注入。

![demo](./assets/demo.gif)

> 📼 录制脚本见 [`docs/demo.tape`](./docs/demo.tape)，由 [`.github/workflows/demo.yml`](./.github/workflows/demo.yml) 在打 tag 时用 [vhs](https://github.com/charmbracelet/vhs) 自动渲染并提交 `assets/demo.gif`；本地可直接 `vhs docs/demo.tape`（需 `promptshield` 在 PATH 上）。

---

## 它扫描什么

PromptShield 把仓库或 diff 拆解成 **Surface** 记录（agent 会读到的每一段文本），再用 YAML 规则引擎把每段映射成零或多个 **Finding**。

**扫描的 Surface（代码即提示词的面）：** 代码注释 · docstring · commit message · markdown / README · 配置文件 · 字符串字面量。

**五类威胁（seed 规则集，v0.1）：**

| 类别 | 含义 | 代表规则 |
| --- | --- | --- |
| `instruction_override` | 直接对 agent 喊话、让它忽略此前指令 | `PS001` `PS002` `PS003` |
| `data_destructive` | 删库 / 销毁数据（Reddit 那类攻击） | `PS010` `PS011` `PS012` |
| `exfiltration` | 读取密钥并外发 | `PS020` `PS021` `PS022` |
| `tool_abuse` | 诱导 agent 跳过确认、滥用工具自主权 | `PS030` `PS031` |
| `obfuscation` | 零宽 / 双向 Unicode、编码载荷等规避人工 review 的手法 | `PS040` `PS041` |

严重度分三档：**HIGH**（令 CI 失败）· **MED** · **LOW**。为压低误报，部分高噪声动词规则用 `requires` 二次门控——只有同时出现 agent 喊话或"全部 / 递归 / 生产库"这类措辞时才会触发，避免一句"删掉临时缓存"的普通注释就被误报。

---

## 集成到 CI

把仓库自带的 [`.github/workflows/promptshield.yml`](./.github/workflows/promptshield.yml) 复制进任意仓库的 `.github/workflows/`，每个 PR 就会被自动门控：

- **PR 上**：`promptshield scan --diff origin/<base>` 只扫改动过的 Surface（新增行 + 新 commit message）。
- **push 到 main**：`promptshield scan .` 扫整棵树。
- 出现任何 **HIGH** 即退出 1，让 check 变红。

也可以手动接入：

```bash
# 只扫本次相对 main 的改动
promptshield scan --diff origin/main

# 扫一份 gh api PR-files JSON（CI 里无需 checkout 全量历史）
gh api repos/OWNER/REPO/pulls/123/files > pr.json
promptshield scan --pr pr.json        # 有 HIGH 即 exit 1
```

---

## 基线工作流

在有历史包袱的老仓库上，先把当前所有 Finding 记成"已接受"，之后只对**新增**注入告警：

```bash
promptshield scan . --update-baseline        # 写入 .promptshield-baseline.yaml，并 exit 0
git add .promptshield-baseline.yaml
promptshield scan .                          # 旧 Finding 被抑制，只报新出现的
```

基线按指纹（`rule_id` + 文件 + excerpt 哈希）抑制，所以一旦真有新注入潜入，它仍会浮出水面。

---

## 对比同类方案

定位，不是吹嘘——在该认输的地方如实认输。

vs [affaan-m/ECC](https://github.com/affaan-m/ECC)（Claude Code / Cursor 实战配置仓库，代表"agent 例行吞入外部代码"的工作流）：

| 能力轴 | PromptShield | Garak / PromptBench | Socket / Snyk |
| --- | :---: | :---: | :---: |
| 扫描**源码注释 / commit / markdown** 中的注入 | ✓ | ✗ | ✗ |
| 离线、零 API key、几秒出结果 | ✓ | partial | ✓ |
| 依赖包 CVE / 供应链漏洞 | ✗ | ✗ | ✓ |
| 聊天越狱 / 红队语料成熟度 | partial | ✓ | ✗ |
| 一行接入 PR 门控（GitHub Action） | ✓ | partial | ✓ |

Garak 在**聊天提示词**红队上更成熟，Socket / Snyk 在**依赖供应链**上无可替代——它们和 PromptShield 是互补关系。PromptShield 只专注一件它们都没碰的事：把你的 coding agent *会读进上下文并照做*的源文本，当作提示词来扫描。

---

## 配置项

`scan` 命令的主要选项：

| 选项 | 类型 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `PATH` | 路径 | `.` | 要扫描的目录或文件 |
| `--diff REF` | 字符串 | 无 | 只扫 `git diff REF` 的新增行 + 新 commit message |
| `--pr FILE.json` | 路径 | 无 | 扫一份 `gh api .../files` 的 PR-files JSON |
| `--baseline FILE` | 路径 | `.promptshield-baseline.yaml` | 用于抑制已接受 Finding 的基线文件 |
| `--update-baseline` | 开关 | `false` | 把当前所有 Finding 写入基线并 exit 0 |
| `--rules FILE` | 路径 | 内置规则集 | 使用自定义 `rules.yaml` |
| `--json` | 开关 | `false` | 输出机器可读 JSON 而非 Rich 表格 |
| `--no-color` | 开关 | `false` | 关闭彩色输出 |
| `--repo DIR` | 路径 | `.` | `--diff` 使用的仓库目录 |

> `--diff` 与 `--pr` 互斥。

---

## 付费 · PromptShield Cloud

**CLI 与 GitHub Action 永久开源免费**，它们是漏斗的入口；营收来自托管的 **PromptShield Cloud** 团队版——把 CLI 之上的团队协作能力变成订阅。

| | 开源 CLI / Action | PromptShield Cloud（团队版） |
| --- | --- | --- |
| 本地 / CI 扫描 | ✓ | ✓ |
| 五类 seed 规则集 | ✓ | ✓ |
| 单仓库基线 | ✓ | ✓ |
| **组织级 PR 门控**（多仓库统一策略） | ✗ | ✓ |
| **共享 / 中心化基线**（跨仓库） | ✗ | ✓ |
| **统一 Finding 看板** | ✗ | ✓ |
| **Slack / 飞书 告警**（命中 HIGH 即推送） | ✗ | ✓ |
| 托管的攻击签名 / 规则订阅源 | ✗ | ✓ |

**定价：** **$8 / 席位 / 月**（年付），或 **$99 / 月**封顶团队版（含 15 席）——比一个 Snyk 席位更省，同时是免费 CLI 之上清晰的"团队协作"升级。

**最短付费路径：** Cloud 看板用一个 token 接入团队现有的 Action 输出 → 展示全组织 Finding + 跨仓库共享基线 → 14 天试用 → Stripe Checkout 自助下单。最有说服力的演示：**你的 6 个仓库，一块看板，一份基线，HIGH 命中即 Slack 告警。**

> 目标客户：已经在 vendored OSS / 外部 PR 上跑 Claude Code / Cursor 的 5–30 人 AI 工具与安全团队。想成为设计合作伙伴？欢迎在 [Issues](https://github.com/SuperMarioYL/promptshield/issues) 留言。

---

## 路线图

- [x] **m1 — `scan <path>`**：遍历仓库，抽取注释 / docstring / markdown / 字符串字面量为 Surface，跑 YAML 规则引擎，打印 Rich 发现表 + 严重度计数。
- [x] **m2 — diff 与 CI**：`scan --diff <ref>`（git diff 新增行）+ `scan --pr <file.json>`（gh PR-files JSON），HIGH → exit 1，附带 `promptshield.yml` Action。
- [x] **m3 — 基线与演示**：`.promptshield-baseline.yaml` 抑制；复现真实 Reddit 数据销毁注入的 `tests/fixtures/malicious_pr/`；asciinema 演示；双语 README。
- [ ] 语义检测（可选、需开关）——在 regex / 启发式之上叠加，提升对绕过手法的召回。
- [ ] 托管攻击签名 / 规则订阅源（PromptShield Cloud）。
- [ ] 上架 GitHub Marketplace，进入 awesome-claude-code / awesome-ai-coding 等清单。

> 明确不在 v0.1 范围：Web UI / 看板、LLM 语义检测、逐语言 AST 解析、自动修复、IDE / 编辑器插件、SARIF / SBOM 输出、自训练分类器。

---

## 许可证与贡献

[MIT](./LICENSE)。欢迎 PR 与 Issue——发现误报或漏报？带上能复现的最小样本，到 [Issues](https://github.com/SuperMarioYL/promptshield/issues) 开一条，我们会据此收紧规则。

变更记录见 [CHANGELOG.md](./CHANGELOG.md)。

---

## Share this

```text
PromptShield — 在你的 Claude Code / Cursor agent 读取代码之前，扫描其中隐藏的提示词注入。
离线、零 API key、一行接入 CI。现场拦下 Reddit 那条 rm -rf 数据销毁注入。
https://github.com/SuperMarioYL/promptshield
```
