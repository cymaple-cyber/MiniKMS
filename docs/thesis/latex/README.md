# 论文 LaTeX 工程（全文初稿）

按 `docs/论文大纲.md` 撰写的**全部章节** LaTeX 初稿，内容基于现有原型代码核实，未虚构未实现功能。系统边界统一为：软件模拟 TEE，非硬件 SGX，非生产级 KMS。

## 编译方式

本工程为中文论文，需使用 **XeLaTeX**（含 `ctex`）。连续编译两次以生成目录、图表索引与交叉引用：

```bash
cd docs/thesis/latex
xelatex main.tex
xelatex main.tex
# 或：latexmk -xelatex main.tex   或   make
```

产物为 `main.pdf`。

> ✅ 已用 **tectonic 0.16.9** 实际编译验证：53 页，无错误、无缺字；中文、带圈编号 ①②、TikZ 图与表格均正常渲染。为跨引擎稳定，已设 `fontset=fandol`（开源中文字体，tectonic 会自动下载）。用 TeX Live + XeLaTeX 亦可编译；若要 macOS 系统字体，将 `main.tex` 中 `fontset=fandol` 改为 `fontset=mac`。

### 依赖（标准 TeX Live / MiKTeX 完整安装均自带）

`ctex`、`tikz`（含 `automata` 等库）、`tabularx`、`longtable`、`booktabs`、`listings`、`hyperref`、`caption`、`geometry`、`enumitem`、`underscore`。

> 若提示缺少 `underscore.sty`：`tlmgr install underscore`。该宏包用于让正文中的下划线（如 `USE_ENCLAVE`）正常显示。

## 目录结构

```text
latex/
├── main.tex                # 主文档（导言、装订顺序）
├── preamble.tex            # 宏包、样式、TikZ 与代码样式
├── chapters/
│   ├── abstract.tex        # 中英文摘要 + 关键词
│   ├── ch01-introduction.tex   # 绪论
│   ├── ch02-background.tex      # 相关技术与理论基础
│   ├── ch03-threat-model.tex   # 威胁模型与安全需求
│   ├── ch04-design.tex         # 总体设计
│   ├── ch05-protocol.tex       # 关键协议与算法实现
│   ├── ch06-implementation.tex # 系统实现与部署
│   ├── ch07-evaluation.tex     # 测试与实验评估
│   ├── ch08-conclusion.tex     # 总结与展望
│   ├── references.tex          # 参考文献（thebibliography，无需 BibTeX）
│   └── appendix.tex            # 附录 A–D
├── Makefile
└── .latexmkrc
```

## 图表

全部图表以 **TikZ** 原生绘制并内嵌，无需外部图片即可编译，包括：信任边界图（图 3-1）、系统架构（图 4-1）、密钥层次（图 4-2）、数据模型 ER（图 4-3）、密钥状态机（图 4-4）、远程认证时序（图 5-1）、加密时序（图 5-2）；以及 API 权限矩阵等表格。

## 说明与约定

- 各章开头以引述块标注“初稿/边界”，每章末有“诚实边界”或局限说明，避免过度表述。
- 涉及实现的论断均给出代码位置（文件/函数），便于核对与答辩。
- 参考文献采用手写 `thebibliography`（17 条），**无需运行 BibTeX**；如需 GB/T 7714 样式，可改用 `gbt7714` 宏包与 `.bib`。
- 代码清单中的中文注释在 XeLaTeX 下可正常显示；若个别等宽字体缺字，可在导言区设置 `\setCJKmonofont`。
- 本工程为通用 `ctexbook` 模板，便于替换为院校论文模板：各 `chapters/*.tex` 可直接 `\input` 到院校模板中复用。
- 第 7 章性能对比表为**实验设计 + 待测栏位**，未填入虚构数值。
