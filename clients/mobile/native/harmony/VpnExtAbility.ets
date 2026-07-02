// 白帝鸿蒙数据面 · VpnExtensionAbility（ArkTS 骨架）
// 鸿蒙用 @ohos.net.vpnExtension 建立系统级 VPN TUN；Go 引擎(baidimobile)经 NAPI/.so 调用。
// ArkWeb 宿主用 registerJavaScriptProxy 注入 __BAIDI_NATIVE__（同安卓桥语义）。
//
// 说明：鸿蒙工程需 DevEco Studio 编译；Go 引擎需编成 .so 经 NAPI 暴露 start(fd,cfg)/stop()。
// 本文件为对接骨架，标注关键步骤。

import VpnExtensionAbility from '@ohos.app.ability.VpnExtensionAbility';
import vpnExt from '@ohos.net.vpnExtension';
// import baidimobile from 'libbaidimobile.so';  // NAPI 暴露的 Go 引擎

// UI 下传的接入配置（经 ArkWeb registerJavaScriptProxy 的 startTunnel(token, cfg) → want.parameters）
interface AccessCfg {
  gateway?: string; spaPort?: string; proxyPort?: string;
  route?: string; ip?: string; gm?: boolean; control?: string; token?: string;
}

export default class BaidiVpnExtAbility extends VpnExtensionAbility {
  private tunFd: number = -1;

  onCreate(want?: { parameters?: Record<string, Object> }): void {
    // 从 want 参数取 UI 配置（缺省回退演示值），不再在原生侧写死
    const c: AccessCfg = (want?.parameters?.['cfg'] as AccessCfg) ?? {};
    const gateway = c.gateway || 'gw.baidi.local';
    const vip = c.ip || '10.99.0.2';
    const net = (c.route || '10.99.0.0/24').split('/');
    const netAddr = net[0] || '10.99.0.0';
    const prefix = parseInt(net[1] || '24', 10) || 24;

    // 1) 建立 TUN：虚拟 IP + 受保护网段（来自配置）路由
    const cfg: vpnExt.VpnConfig = {
      addresses: [{ address: { address: vip, family: 1 }, prefixLength: 32 }],
      routes: [{ interface: 'baidi-tun', destination: { address: { address: netAddr, family: 1 }, prefixLength: prefix }, gateway: { address: '0.0.0.0', family: 1 } }],
      mtu: 1420,
    };
    // vpnExt.createVpnConnection(this.context).setUp(cfg) → 得到 tunFd
    // this.tunFd = <fd from setUp>;

    // 2) 启动 Go 引擎（NAPI）：baidimobile.start(this.tunFd, {
    //      spaAddr: `${gateway}:${c.spaPort||'18201'}`, proxyAddr: `${gateway}:${c.proxyPort||'18443'}`,
    //      token: c.token, control: c.control||'', gm: c.gm ?? true, serverName: 'baidi-gateway' })
  }

  onDestroy(): void {
    // baidimobile.stop();
  }
}
