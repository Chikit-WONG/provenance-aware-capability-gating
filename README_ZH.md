# 基于来源追踪与能力门控的多 Agent 间接提示注入攻防

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

在专门隔离 provenance 作用的 T5--T6 子集上，Allow-All 和 Capability-Only 各有
3/6 次秘密泄露，Full 为 0/6。完整聚合结果、比较表和图见
[正式分析目录](artifacts/formal-analysis-v1/)：

- [结果摘要](artifacts/formal-analysis-v1/results_summary.json)
- [正式结果表](artifacts/formal-analysis-v1/publication_table.csv)
- [注册比较](artifacts/formal-analysis-v1/registered_comparisons.csv)
- [安全性图](artifacts/formal-analysis-v1/security_outcomes.png)
- [效用图](artifacts/formal-analysis-v1/utility_outcomes.png)
- [任务族图](artifacts/formal-analysis-v1/task_family_outcomes.png)
- [技术报告 PDF](report/main.pdf)

表中百分比使用有效样本分母；无效记录没有被静默替换。
