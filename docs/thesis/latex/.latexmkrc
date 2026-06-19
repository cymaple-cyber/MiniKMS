# 使用 XeLaTeX 编译（中文 ctex）
$pdf_mode = 5;      # 5 = xelatex
$xelatex  = 'xelatex -interaction=nonstopmode -halt-on-error -synctex=1 %O %S';
$clean_ext = 'aux log toc lof lot out synctex.gz';
