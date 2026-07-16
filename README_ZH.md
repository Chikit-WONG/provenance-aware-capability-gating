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

