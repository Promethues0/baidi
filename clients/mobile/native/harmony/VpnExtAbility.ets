// 白帝鸿蒙数据面 · VpnExtensionAbility（ArkTS 骨架）
// 鸿蒙用 @ohos.net.vpnExtension 建立系统级 VPN TUN；Go 引擎(baidimobile)经 NAPI/.so 调用。
// ArkWeb 宿主用 registerJavaScriptProxy 注入 __BAIDI_NATIVE__（同安卓桥语义）。
//
// 说明：鸿蒙工程需 DevEco Studio 编译；Go 引擎需编成 .so 经 NAPI 暴露 start(fd,cfg)/stop()。
// 本文件为对接骨架，标注关键步骤。

import VpnExtensionAbility from '@ohos.app.ability.VpnExtensionAbility';
import vpnExt from '@ohos.net.vpnExtension';
// import baidimobile from 'libbaidimobile.so';  // NAPI 暴露的 Go 引擎

export default class BaidiVpnExtAbility extends VpnExtensionAbility {
  private tunFd: number = -1;

  onCreate(): void {
    // 1) 建立 TUN：虚拟 IP + 受保护网段路由
    const cfg: vpnExt.VpnConfig = {
      addresses: [{ address: { address: '10.99.0.2', family: 1 }, prefixLength: 32 }],
      routes: [{ interface: 'baidi-tun', destination: { address: { address: '10.99.0.0', family: 1 }, prefixLength: 24 }, gateway: { address: '0.0.0.0', family: 1 } }],
      mtu: 1420,
    };
    // vpnExt.createVpnConnection(this.context).setUp(cfg) → 得到 tunFd
    // this.tunFd = <fd from setUp>;

    // 2) 启动 Go 引擎（NAPI）：baidimobile.start(this.tunFd, { spaAddr, proxyAddr, token, gm:true, caPEM, serverName })
  }

  onDestroy(): void {
    // baidimobile.stop();
  }
}
