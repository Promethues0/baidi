#!/usr/bin/env bash
# 全仓扫描：`$VAR` 后面紧跟全角字符（`）`、`」`、`，`…）必须改写成 `${VAR}`。
#
# ★为什么这是个真 bug 而不是风格问题：macOS 自带的 bash 3.2 在 UTF-8 locale 下会把
#   紧跟 `$VAR` 的全角字符**首字节吞进变量名**，于是查的是 `VAR\xef` 这个不存在的变量。
#
#   ☠ 本文件自己也要过这条检查，所以下面**不能**把那个字节序列原样写出来
#     （第一版就这么栽了：反例写成 `$A` 紧跟全角右括号，本机跑时它还没被 git 跟踪、
#      ls-files 看不见自己，一提交 CI 就红）。反例改用文字描述，要复现请自己敲：
#
#     A=1; 在双引号里写一个全角左括号 + $A + 全角右括号，分别用两种 locale 跑：
#       LC_ALL=en_US.UTF-8 → 报 unbound variable（变量名被吞掉一个字节）
#       LC_ALL=C           → 正常输出
#
#   本项目所有提示语都是中文，这个写法极易复发。
#
# ★`set -u` 让它当场炸是运气好：没开 `set -u` 的脚本里它**静默展开成空串**——
#   `rm -rf "$PREFIX/x"` 这类地方错成什么样不用多说。真实踩到过的一次是
#   deploy/build.sh 的限流自检：报错句里把循环变量紧贴在全角引号前面，
#   于是在 mac 上恰好丢掉它唯一要传达的信息（到底是哪一条指令没了）。
#
# ★为什么抽成独立脚本：这条检查是**全仓**的（git ls-files '*.sh'），
#   而它此前只挂在 clients.yml 一条流水线上，那条流水线的 paths 又只盯 clients/**。
#   于是 deploy/*.sh 里引入的同类 bug 潜伏了三次提交才被撞见——
#   一条全仓的检查，触发面却只有一个子树。现在 clients.yml 与 server.yml 都调它，
#   两处共用这一份实现（不是各抄一遍）。
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

python3 - <<'PY'
import re, subprocess, pathlib, sys
VENDORED = {"clients/mobile/native/android/gradlew"}  # 第三方文件，不归我们管
pat = re.compile(rb'\$([A-Za-z_][A-Za-z0-9_]*)(?=[\x80-\xff])')
hits = []
files = subprocess.run(["git", "ls-files", "*.sh", "*.bash"],
                       capture_output=True, text=True).stdout.split()
for f in files:
    if f in VENDORED:
        continue
    for i, line in enumerate(pathlib.Path(f).read_bytes().split(b"\n"), 1):
        for m in pat.finditer(line):
            hits.append(f"{f}:{i}\t${m.group(1).decode()}"
                        f"  →  {line.decode('utf-8','replace').strip()[:100]}")
if hits:
    print("✗ 下列位置的 $变量 后面紧跟非 ASCII 字符，请改成 ${变量}：")
    print("\n".join("  " + h for h in hits))
    sys.exit(1)
print(f"✓ 无裸 $变量 紧邻全角字符（扫了 {len(files)} 个 shell 脚本）")
PY
