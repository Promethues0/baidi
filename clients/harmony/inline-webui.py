#!/usr/bin/env python3
"""把前端构建产物内联成**单个 HTML**，供 ArkWeb 从 rawfile 加载。

★为什么必须内联：ArkWeb 的 `resource://rawfile/` 不在它自己的 CORS 白名单里——
内核只信任 arkweb / chrome / data / http / https 这几个 scheme。于是 index.html
能加载，而它引用的 CSS 与 JS 全被 CORS 拦掉，表现为**纯白屏且不报加载失败**
（错误只出现在 ARKWEB-CONSOLE 的日志里）。

把 JS/CSS 内联进 HTML 之后就没有子资源请求，整条 CORS 路径不再涉及。
另外两条可选路径都更重：自定义 scheme handler（要在 ArkTS 侧实现 rawfile 伺服），
或起一个本地 HTTP server（多一个常驻端口，还要处理端口冲突）。
"""
import io, re, sys
from pathlib import Path

def main() -> int:
    dist = Path(sys.argv[1] if len(sys.argv) > 1 else 'webui/dist')
    html_path = dist / 'index.html'
    html = html_path.read_text(encoding='utf-8')

    def inline_css(m: re.Match) -> str:
        href = m.group(1)
        p = dist / href.lstrip('./')
        if not p.exists():
            return m.group(0)
        # </style> 出现在 CSS 里会提前闭合标签
        css = p.read_text(encoding='utf-8').replace('</style', '<\\/style')
        return f'<style>{css}</style>'

    def inline_js(m: re.Match) -> str:
        src = m.group(1)
        p = dist / src.lstrip('./')
        if not p.exists():
            return m.group(0)
        # </script> 出现在字符串字面量里会提前闭合标签
        js = p.read_text(encoding='utf-8').replace('</script', '<\\/script')
        return f'<script type="module">{js}</script>'

    html = re.sub(r'<link[^>]*rel="stylesheet"[^>]*href="([^"]+)"[^>]*>', inline_css, html)
    html = re.sub(r'<script[^>]*src="([^"]+)"[^>]*></script>', inline_js, html)

    left = re.findall(r'(?:src|href)="\./assets/[^"]+"', html)
    if left:
        print(f'✗ 仍有未内联的子资源，ArkWeb 会因 CORS 拦掉它们（白屏）：{left}', file=sys.stderr)
        return 1

    out = dist / 'index.html'
    out.write_text(html, encoding='utf-8')
    print(f'  已内联成单文件：{out.stat().st_size / 1024 / 1024:.2f} MB')
    return 0

if __name__ == '__main__':
    sys.exit(main())
