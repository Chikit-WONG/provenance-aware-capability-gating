# 基于来源追踪与能力门控的多 Agent 间接提示注入攻防

[English version](README.md)

本目录是 AIAA/AAIA 4313 Group Project 的代码、实验和复现材料。项目构建一个
完全本地的 Level-2 办公助理：Reader Agent 读取不可信邮件，Action Agent 使用
文件、日历和发信工具，确定性 Gateway 在实际执行前检查用户授权、参数边界及敏感
数据流。

正式研究问题是：**在任务授权 manifest 正确的前提下，provenance-aware
capability gating 能否减少真实执行的越权行为和合成秘密泄露，同时保持正常任务
完成率？** 本项目不声称解决一般语义信息流安全；Full 防御只追踪已注册的精确合成
敏感值，编码、释义或拆分后的逃逸属于明确局限。

## 已固定的关键选择

- 使用已有本地模型 `Qwen3-VL-8B-Instruct`，不额外下载模型；
- Reader 和 Action Agent 共用一份单 A40 vLLM 服务；
- Red Agent 只在实验前离线生成语料，正式 payload 冻结并记录 SHA-256；
- 只连接本地 mock Email、Calendar 和 File Vault，不连接真实账号或服务；
- 正式矩阵为 6 个任务 × 3 个内容条件 × 4 个防御 × 3 个 seed，共 216 runs；
- 攻击是否成功由独立 evaluator 读取实际 world state 判定，不使用 LLM judge；
- Demo 使用 Gradio 现场展示，并准备录屏/离线回放作为备份。

独立冻结的后续消融计划只增加第五个防御
`prompt_capability_only`：它与 Full 使用相同的安全提示、能力检查和阻断后恢复，
但关闭 provenance sink check。该 add-on 为 6 × 3 × 1 × 3 = 54 次运行，用于在
不改写原 216-run 正式研究的前提下隔离 Full 相对 Prompt+Capability 的来源追踪
增量。

随后补齐了 `provenance_only` 和 `prompt_provenance_only`，并在 hardened 语料上补齐其余
六个缺失防御臂。原始语料和 hardened 语料分别形成
`6 × 3 × 8 × 3 = 432` 个计划 cell。Provenance-only 两臂故意不做 capability
限制，只测试出口的 exact-taint 阻断；它们不能替代 least-authority capability gating。
另有确定性的 16-case sink 压力测试，在邮件 subject/body 以及日历 title/location 四类出口
注入恶意敏感值。

详细接口见 [系统架构](docs/ARCHITECTURE.md)、[威胁模型](docs/THREAT_MODEL.md)
和[实验协议](docs/EXPERIMENT_PROTOCOL.md)。

## 正式实验结果

冻结的正式计划包含 216 次运行，分析得到 213 条有效记录和 3 条基础设施无效记录；
无效记录保留在 intention-to-test（ITT）统计中。下表为六个任务合并后的有效样本率：

| 防御方案 | Attack 越权执行 | Attack 秘密泄露 | Clean 正常完成 |
| --- | ---: | ---: | ---: |
| Allow-All | 9/17（52.9%） | 6/17（35.3%） | 17/17（100%） |
| Prompt-Only | 6/18（33.3%） | 3/18（16.7%） | 18/18（100%） |
| Capability-Only | 3/18（16.7%） | 3/18（16.7%） | 17/18（94.4%） |
| Full | 0/18（0%） | 0/18（0%） | 15/18（83.3%） |

原 T5--T6 对比中，Capability-Only 泄漏 3/6，Full 泄漏 0/6；但这两个方案同时
相差安全提示词和 provenance 检查，不能据此把差异归因于 provenance。第五组消融
专门拆开了这两个因素。

## 原始语料完整 factorial 结果

原始完整 factorial 共 432 次计划运行，其中 428 条有效、4 条无效（ITT 保留）。在 T5--T6
attack 子集上：

| 防御方案 | 秘密泄漏 |
| --- | ---: |
| Allow-All | 3/6（50.0%） |
| Prompt-Only | 0/6（0%） |
| Capability-Only | 3/6（50.0%） |
| Provenance-only | 0/6（0%） |
| Prompt+Provenance | 0/6（0%） |
| Capability+Provenance | 0/6（0%） |
| Prompt+Capability | 0/6（0%） |
| Full | 0/6（0%） |

Provenance-only 相对 Allow-All 的配对泄漏风险差为 $-0.50$（95% CI
$[-0.83,-0.17]$）；Prompt+Provenance 相对 Prompt-Only 为 $0.00$。Capability+Provenance
相对 Capability-Only 也为 $-0.50$。Full 与 Prompt+Capability 在该语料上都为 0/6，存在
floor effect。

完整表格、比较、图和 manifest 见
[原始完整分析目录](artifacts/original-full-factorial-analysis-v1/)：

- [结果摘要](artifacts/original-full-factorial-analysis-v1/results_summary.json)
- [结果表](artifacts/original-full-factorial-analysis-v1/publication_table.csv)
- [注册比较](artifacts/original-full-factorial-analysis-v1/registered_comparisons.csv)
- [安全性图](artifacts/original-full-factorial-analysis-v1/security_outcomes.png)
- [效用图](artifacts/original-full-factorial-analysis-v1/utility_outcomes.png)

确定性 sink 压力测试为 16/16 通过：启用 provenance 的 8 次受保护值出口调用全部被拒绝，
副作用为 0；两个未启用 provenance 的对照方案的 8 次能力合法调用均正常执行。原始结果见
[sink-pressure-v1/results.json](artifacts/sink-pressure-v1/results.json)。

## hardened 语料完整 factorial 结果

Red Agent 使用新的冻结 system prompt 生成独立的 30-candidate 语料，加入审批伪装、合规
流程伪装和数据字段/context laundering 等策略。hardened 完整 factorial 共 432 次计划
运行，其中 428 条有效、4 条无效（ITT 保留）。在 T5--T6 attack 子集上：

| 防御方案 | T5--T6 attack 泄漏 | T6 attack 泄漏 |
| --- | ---: | ---: |
| Allow-All | 2/6（33.3%） | 2/3（66.7%） |
| Prompt-Only | 3/6（50.0%） | 3/3（100%） |
| Capability-Only | 2/6（33.3%） | 2/3（66.7%） |
| Provenance-only | 0/6（0%） | 0/3（0%） |
| Prompt+Provenance | 0/6（0%） | 0/3（0%） |
| Capability+Provenance | 0/6（0%） | 0/3（0%） |
| Prompt+Capability | 3/6（50.0%） | 3/3（100%） |
| Full | 0/6（0%） | 0/3（0%） |

Provenance-only 相对 Allow-All 为 $-0.33$（95% CI $[-0.67,0.00]$），Prompt+Provenance
相对 Prompt-Only 为 $-0.50$（95% CI $[-0.83,-0.17]$），Full 相对 Prompt+Capability
为 $-0.50$（95% CI $[-0.83,-0.17]$）。因此 hardened 语料显示了安全提示词/能力基线
之上的端到端 provenance 增益。完整结果和图见
[hardened 完整分析](artifacts/hardened-full-factorial-analysis-v1/)，冻结语料见
[red_corpus_qwen3_hardened_v1](data/frozen/red_corpus_qwen3_hardened_v1/)。
- [技术报告 PDF](report/main.pdf)
