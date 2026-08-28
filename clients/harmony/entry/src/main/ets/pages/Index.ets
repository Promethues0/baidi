/**
 * 白帝 · 鸿蒙桌面客户端 —— ArkWeb 壳。
 *
 * 形态与安卓/iOS 壳同构：UI 是 clients/mobile 那套 Vue（构建产物打进 rawfile），
 * 原生能力经 window.__BAIDI_NATIVE__ 暴露（契约见 clients/mobile/src/lib/vpn.ts）。
 *
 * ★数据面（VpnExtensionAbility + Go 引擎）**尚未实现**，桥里 startTunnel 如实返回
 * 失败并说明原因——绝不返回 {ok:true} 骗 UI 画出"已接入"。理由见 README 的
 * 「当前能做什么 / 不能做什么」。
 */
import { webview } from '@kit.ArkWeb';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { BusinessError } from '@kit.BasicServicesKit';

const DOMAIN = 0x0001;
const TAG = 'baidi';

/** 注入到 webview 的原生宿主对象（同步方法；JS 侧再包一层 Promise）。 */
class BaidiHost {
  /** 本端平台标识：UI 的「我的」页据此显示端类型，控制面灰度也按它分桶。 */
  platform(): string {
    return 'harmony';
  }

  /**
   * 启动数据面。**当前未实现**：鸿蒙侧要经 VpnExtensionAbility 建 TUN，
   * 再由 NAPI 调 Go 引擎做 SPA 敲门 + 隧道，两者都还没有。
   * 如实回失败——桌面端「显示已接入而实际没引流」正是本项目反复消灭的形态。
   */
  startTunnel(_token: string, _cfgJson: string): string {
    hilog.warn(DOMAIN, TAG, '收到接入请求，但鸿蒙数据面尚未实现');
    return JSON.stringify({
      ok: false,
      detail: '鸿蒙端数据面尚未实现（需 VpnExtensionAbility + Go 引擎经 NAPI 接入）。' +
        '当前版本可登录、看应用清单与门户，但不能建立隧道。'
    });
  }

  stopTunnel(): string {
    return JSON.stringify({ ok: true });
  }
}

/** 在页面脚本跑起来之前注入桥。把同步的宿主方法包成 UI 期望的 Promise 形状。 */
const BRIDGE_JS: string = `
(function () {
  if (window.__BAIDI_NATIVE__) return;
  var h = window.__BAIDI_HOST__;
  window.__BAIDI_NATIVE__ = {
    platform: h ? h.platform() : 'harmony',
    startTunnel: function (token, cfg) {
      if (!h) return Promise.resolve({ ok: false, detail: '原生桥未注入' });
      try { return Promise.resolve(JSON.parse(h.startTunnel(token || '', JSON.stringify(cfg || {})))); }
      catch (e) { return Promise.resolve({ ok: false, detail: String(e) }); }
    },
    stopTunnel: function () {
      if (h) { try { h.stopTunnel(); } catch (e) {} }
      return Promise.resolve();
    }
  };
})();
`;

@Entry
@Component
struct Index {
  controller: webview.WebviewController = new webview.WebviewController();
  private host: BaidiHost = new BaidiHost();

  build() {
    Column() {
      Web({ src: $rawfile('index.html'), controller: this.controller })
        .javaScriptAccess(true)
        .domStorageAccess(true)      // UI 用 localStorage 存令牌与配置
        .fileAccess(true)
        .mixedMode(MixedMode.All)    // 允许 https 页面里调 http 控制面（内网部署常见）
        .javaScriptProxy({
          object: this.host,
          name: '__BAIDI_HOST__',
          methodList: ['platform', 'startTunnel', 'stopTunnel'],
          controller: this.controller
        })
        .onControllerAttached(() => {
          try {
            this.controller.runJavaScript(BRIDGE_JS);
          } catch (err) {
            const e = err as BusinessError;
            hilog.error(DOMAIN, TAG, '注入原生桥失败: %{public}s', e.message);
          }
        })
        .onPageBegin(() => {
          // 每次导航后重注入：单页应用内部跳转不会走这里，但整页刷新会。
          try {
            this.controller.runJavaScript(BRIDGE_JS);
          } catch (_err) { /* 组件尚未 attach，onControllerAttached 会补上 */ }
        })
        .width('100%')
        .height('100%')
    }
    .width('100%')
    .height('100%')
  }
}
