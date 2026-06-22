# 烛龙设计系统（共享 token 层）

`tokens.css` 源自客户端高保真原型 `docs/design/client-hifi/ds.css`，是五端 GUI + 控制台的**唯一视觉 token 源**（ZL-FR-306 / ZL-NFR-003）。

- 颜色：OKLCH 体系，Claude 暖色系，主色黏土橙 clay terracotta（#B4552D）；浅/深双主题
- 控制台消费：`console/src/styles/tokens.css`（在此基础上桥接 Arco `--primary-N`）
- 客户端消费：直接引用 ds.css

修改 token 必须改源（ds.css / 本文件），各端不得私自定义颜色/圆角/阴影。
