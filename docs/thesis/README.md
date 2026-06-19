# 论文初稿（thesis/）

按 `docs/论文大纲.md` 撰写的论文正文初稿。所有内容基于现有原型代码核实，未虚构未实现的功能；系统边界统一为：**软件模拟 TEE，非硬件 SGX，非生产级 KMS**。

## ⭐ 全文 LaTeX 版（推荐）

全部章节（摘要 + 第 1–8 章 + 参考文献 + 附录 A–D）的 LaTeX 初稿见 [`latex/`](latex/)，图表以 TikZ 原生绘制，无需外部图片即可用 XeLaTeX 编译。编译与说明见 [`latex/README.md`](latex/README.md)：

```bash
cd latex && xelatex main.tex && xelatex main.tex   # 或 make
```

## Markdown 版（第 3、4 章，含 Mermaid 图）

以下为先期的 Markdown 初稿，内容已并入上述 LaTeX 全文，可用于在线预览 Mermaid 图：

| 文件 | 章节 | 状态 |
|------|------|------|
| [ch03-威胁模型.md](ch03-威胁模型.md) | 第 3 章 系统威胁模型与安全需求 | 初稿 |
| [ch04-总体设计.md](ch04-总体设计.md) | 第 4 章 系统总体设计 | 初稿 |

## 图表清单

图表以 [Mermaid](https://mermaid.js.org/) 形式内嵌于章节，源文件另存于 `figures/`，便于导出 PNG 用于排版。

| 编号 | 文件 | 内容 |
|------|------|------|
| 图 3-1 | `figures/fig3-1-信任边界.mmd` | 系统信任边界与数据流 |
| 图 4-1 | `figures/fig4-1-系统架构.mmd` | 系统总体架构 |
| 图 4-2 | `figures/fig4-2-密钥层次.mmd` | 密钥层次与信封加密 |
| 图 4-3 | `figures/fig4-3-数据模型.mmd` | 数据模型（ER 图） |
| 图 4-4 | `figures/fig4-4-密钥状态机.mmd` | 密钥生命周期状态机 |

第 3 章另含表 3-1～3-4，第 4 章另含表 4-1～4-4（其中表 4-1 为 API 权限矩阵）。

## 导出 PNG（可选）

```bash
# 安装 mermaid-cli（需 Node.js）
npm install -g @mermaid-js/mermaid-cli

# 在 figures/ 下逐个导出
mmdc -i figures/fig4-1-系统架构.mmd -o figures/fig4-1-系统架构.png
```

GitHub、Typora、VS Code（Markdown Preview Mermaid 插件）等可直接预览内嵌的 Mermaid。

## 写作约定

- 章节均以"初稿"标注，含可信模式为主、本地模式为对照的叙事。
- 涉及实现的论断均给出代码位置（文件/函数），便于核对与答辩。
- 每章末尾以"诚实边界"小节明确不防护范围，避免过度表述。
