[English](./README.en.md) · [Website](https://promptshield.lei6393.com) · [GitHub](https://github.com/SuperMarioYL/promptshield)

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/hero-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/hero-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/hero-dark.svg">
  <img src="./assets/presentation/hero-light.svg" width="960" alt="Hero diagram">
</picture>

# PromptShield

**找出仓库文本中的可疑指令**

PromptShield 扫描编程 Agent 可能读取的文本，用源码位置标出提示注入模式，并在仍有 HIGH 发现项时让 CI 返回失败。

## 为什么需要它

注释、文档和提交信息中可能夹带针对 Agent 的指令。单独审阅这些文本表面，有助于在进入 Agent 上下文之前发现可疑要求。

- **定位指令来源** — 发现项保留文件、行号、文本类型、规则及原因。
- **检查解码后文本** — 默认解码阶段增加 Base64、十六进制和 Unicode 归一化变体。
- **融入仓库审查** — 可扫描路径、Diff 新增行及提交信息，或保存的 GitHub PR 文件 JSON。

## 架构

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/architecture-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/architecture-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/architecture-dark.svg">
  <img src="./assets/presentation/architecture-light.svg" width="960" alt="Architecture diagram">
</picture>

收集器识别支持的注释、文档和变更文本。解码器在保留来源的同时创建额外变体；YAML 规则分类匹配项，scanner.py 去重排序，baseline 按指纹过滤已接受项。表格、JSON 和 SARIF 共享同一个 ScanResult。

| 组件 | 职责 |
| --- | --- |
| `Collectors` | paths / diffs / PR JSON |
| `Decode + rules` | text variants and patterns |
| `Baseline` | accepted finding fingerprints |
| `ScanResult` | evidence, counts and exit code |

## 安装与快速上手

需要 Python 3.12+ 和 uv。本地样本扫描不需要模型或网络。

```bash
git clone https://github.com/SuperMarioYL/promptshield.git
cd promptshield
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e .
```

脚本用真实 CLI 扫描随仓 clean.py 和 utils.py，汇总 JSON 结果并核对预期的 0/1 退出码。可疑文件仅作为文本读取。

```bash
.venv/bin/python examples/presentation_demo.py
```

## 实际运行示例

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/process-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/process-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/process-dark.svg">
  <img src="./assets/presentation/process-light.svg" width="960" alt="Process diagram">
</picture>

The clean fixture exits 0; the injection fixture exits 1. Neither fixture is executed.

```text
{"fixture": "clean.py", "exit_code": 0, "counts": {"HIGH": 0, "MED": 0, "LOW": 0}, "rule_ids": []}
{"fixture": "utils.py", "exit_code": 1, "counts": {"HIGH": 4, "MED": 0, "LOW": 0}, "rule_ids": ["PS001-instruction-override-direct", "PS010-destructive-shell", "PS011-destructive-instruction", "PS020-exfil-secrets"]}
Scope: deterministic static fixture scan; no fixture code executed and no model called.
```

完整命令与输出保存在 [docs/demo-results.json](./docs/demo-results.json). 输入和复现代码均随仓提供。

![已有终端录制](./assets/demo.gif)

保留已有录制供参考；上方文字示例给出当前可复现的操作。

## 用法

第一条示例会按预期返回 1。--diff 需要所选仓库中有效的 Git 引用。--pr 接受保存的 PR 文件 JSON，不会自动获取。CI 接入可使用 --format sarif，脚本处理可使用 --format json。--diff 与 --pr 互斥。

```bash
.venv/bin/promptshield scan ./tests/fixtures/malicious_pr --format json
.venv/bin/promptshield scan --diff HEAD~1 --repo . --format sarif
.venv/bin/promptshield rules list
```

## 配置

可重复传入 --rules YAML 文件或目录叠加规则，后来的同 ID 规则覆盖前者。--baseline 指定接受项文件，默认 .promptshield-baseline.yaml。--update-baseline 会写入全部当前发现并返回 0，因此应在审阅之后使用。--no-decode 关闭解码，--no-color 关闭终端颜色。HIGH 返回 1，仅有 MED 或 LOW 不会。

## 集成与职责分工

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/integrations-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/integrations-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/integrations-dark.svg">
  <img src="./assets/presentation/integrations-light.svg" width="960" alt="Integrations diagram">
</picture>

PromptShield 报告文本模式，运行时仍需执行自身信任边界。审阅者需判断被标记指令是正常文档还是攻击。规则包与 baseline 使这些审阅决策保持明确。

| 路径 | 已实现职责 |
| --- | --- |
| Repository paths | comments and document surfaces |
| Git diff | added lines and commit messages |
| PR-files JSON | saved GitHub API input |
| Rule packs | stacked YAML rules |
| SARIF / JSON | CI and review tools |

## 限制与后续方向

- 模式匹配可能漏过新攻击，也可能标记合法示例。没有发现项并不能证明文本适合交给 Agent。
- 解码只覆盖已实现变换，不覆盖任意混淆方式或模型行为。
- 示例验证样本检测，不验证模型是否遵循或忽略注入指令。

已实现仓库、Diff、PR 扫描，解码变体、规则叠加、baseline 处理和 SARIF。后续可扩展语言收集器，并在代表性仓库上评估误报。运行时拦截和托管审阅服务不在当前 CLI 内。

## 许可与贡献

许可见 [LICENSE](./LICENSE). 反馈问题时请提供最小输入、执行命令和实际输出。
