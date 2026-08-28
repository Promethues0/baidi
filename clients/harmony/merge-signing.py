#!/usr/bin/env python3
"""把本机签名材料（signing-local.json5，不入库）合并进 build-profile.json5。

★为什么要这么绕：profile/密钥路径是本机绝对路径、密码由 DevEco 用本机主密钥加密，
换台机器都无效；而凭据材料一律不进版本库（同 certs/ 的纪律）。于是版本库里那份
signingConfigs 恒为空，构建时临时合并、构建完还原。
"""
import io, re, sys

PROF, LOCAL = 'build-profile.json5', 'signing-local.json5'
SEG = re.compile(r'(    signingConfigs: \[\n.*?\n    \],\n)', re.S)

def main() -> int:
    try:
        local = io.open(LOCAL, encoding='utf-8').read()
    except FileNotFoundError:
        return 0  # 没有本机材料：构建仍继续，只是产不出 signed.hap
    seg = SEG.search(local)
    if not seg:
        print(f'{LOCAL} 里找不到 signingConfigs 段', file=sys.stderr)
        return 1
    prof = io.open(PROF, encoding='utf-8').read()
    if 'signingConfigs: [],' not in prof:
        return 0  # 已经填过（比如 DevEco 刚写回），不重复合并
    io.open(PROF, 'w', encoding='utf-8').write(
        prof.replace('    signingConfigs: [],\n', seg.group(1), 1))
    return 0

if __name__ == '__main__':
    sys.exit(main())
