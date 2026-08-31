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
import { common, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { BusinessError } from '@kit.BasicServicesKit';

const DOMAIN = 0x0001;
const TAG = 'baidi';

/**
 * 控制中心默认地址（调试期）。
 *
 * desktop 那套 UI 的默认值是 http://127.0.0.1:8090——在鸿蒙壳里 127.0.0.1 是**设备本机**，
 * 控制面不在那儿。这里预置成在线演示站，只在用户从未配置过时写入；
 * 「设置」页改过之后以用户配置为准。
 */
const DEFAULT_CONTROL: string = 'https://101.43.125.131';

/**
 * 是否接受演示站的自签 TLS 证书。
 *
 * ★演示站的证书是自签的（CN=baidi 自签自），ArkWeb 默认会拒。这与桌面端连它要带
 * `-insecure` 是同一件事，也同样是**调试期逃生舱**：放开之后这条 HTTPS 只加密不认证，
 * 中间人可以无声接管。正式部署必须换成可信证书并把这里置 false。
 * 每次放行都打 ERROR 级日志——不让它悄悄生效。
 */
const ALLOW_INSECURE_TLS: boolean = true;

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

  /** 隧道运行态。数据面还不存在，如实回 running=false —— 不编造一个"在跑"。 */
  tunnelStatus(): string {
    return JSON.stringify({ running: false, pid: '', log: '' });
  }

  /** 用系统浏览器打开应用地址。只放行 http/https，同桌面端 Rust 侧的白名单。 */
  openUrl(url: string): string {
    const u: string = url.trim();
    if (!u.startsWith('http://') && !u.startsWith('https://')) {
      hilog.warn(DOMAIN, TAG, '拒绝打开非 http(s) 地址');
      return JSON.stringify({ ok: false, detail: '只允许 http/https' });
    }
    try {
      const ctx = getContext(this) as common.UIAbilityContext;
      const want: Want = { action: 'ohos.want.action.viewData', uri: u };
      ctx.startAbility(want);
      return JSON.stringify({ ok: true });
    } catch (err) {
      hilog.error(DOMAIN, TAG, '打开外部地址失败: %{public}s', JSON.stringify(err));
      return JSON.stringify({ ok: false, detail: '打开失败' });
    }
  }
}

/** 在页面脚本跑起来之前注入桥。把同步的宿主方法包成 UI 期望的 Promise 形状。 */
const BRIDGE_JS: string = `
(function () {
  if (window.__BAIDI_NATIVE__) return;
  var h = window.__BAIDI_HOST__;
  // ★注入 __TAURI_INTERNALS__：desktop 那套 UI 用它判断"是否在原生壳里"
  // （tauriRuntime()）。不注入的话 UI 会走浏览器 dev 的退化路径——那条路依赖本机的
  // baidi-knock-agent 代理，鸿蒙上根本没有，表现为点接入毫无反应。
  if (!window.__TAURI_INTERNALS__) window.__TAURI_INTERNALS__ = { harmony: true };
  // 首次启动预置控制中心地址。desktop 的默认值是 127.0.0.1:8090，在鸿蒙壳里指向设备本机。
  // 只在从未配置过时写入——用户在「设置」页改过就不再覆盖。
  try {
    if (!localStorage.getItem('baidi_cfg_control')) {
      localStorage.setItem('baidi_cfg_control', '__DEFAULT_CONTROL__');
    }
  } catch (e) { /* 隐私模式等取不到 localStorage：UI 会退回自己的默认值 */ }
  window.__BAIDI_NATIVE__ = {
    platform: h ? h.platform() : 'harmony',
    tunnelStatus: function () {
      if (!h) return Promise.resolve({ running: false, pid: '', log: '' });
      try { return Promise.resolve(JSON.parse(h.tunnelStatus())); }
      catch (e) { return Promise.resolve({ running: false, pid: '', log: '' }); }
    },
    openUrl: function (url) {
      if (!h) return Promise.reject(new Error('原生桥未注入'));
      var r = {};
      try { r = JSON.parse(h.openUrl(url || '')); } catch (e) { r = { ok: false, detail: String(e) }; }
      return r.ok ? Promise.resolve() : Promise.reject(new Error(r.detail || '打开失败'));
    },
    quit: function () { return Promise.resolve(); },
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

/**
 * 启动自检：页面就绪后打一次控制面的免认证端点，结果经 console.log 进 hilog。
 *
 * ★为什么值得常驻：这条链路上会静默失败的环节不少——控制面地址配错、设备到控制面
 * 网络不通、自签证书被 ArkWeb 拒。三者在 UI 上的表现**完全一样**（登录转圈然后报
 * 一句"网络错误"），而它们的处置完全不同。启动就把真实结果写进日志，
 * `hdc shell hilog | grep 白帝自检` 一眼能分辨。
 *
 * 只读一个免认证端点（GET /api/v1/auth/domains，返回已配置的认证域清单），
 * 不带任何凭据、不改变任何状态。
 */
const SELFTEST_JS: string = `
(function () {
  try {
    var base = localStorage.getItem('baidi_cfg_control') || '(未配置)';
    console.log('[白帝自检] 控制面地址 = ' + base);
    fetch(base + '/api/v1/auth/domains')
      .then(function (r) {
        console.log('[白帝自检] HTTP ' + r.status + ' ' + r.statusText);
        return r.text();
      })
      .then(function (t) { console.log('[白帝自检] 响应体 ' + t.slice(0, 200)); })
      .catch(function (e) { console.log('[白帝自检] 失败：' + (e && e.message ? e.message : e)); });
  } catch (e) {
    console.log('[白帝自检] 脚本异常：' + e);
  }
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
          methodList: ['platform', 'startTunnel', 'stopTunnel', 'tunnelStatus', 'openUrl'],
          controller: this.controller
        })
        .onControllerAttached(() => {
          try {
            this.controller.runJavaScript(BRIDGE_JS.replace('__DEFAULT_CONTROL__', DEFAULT_CONTROL));
          } catch (err) {
            const e = err as BusinessError;
            hilog.error(DOMAIN, TAG, '注入原生桥失败: %{public}s', e.message);
          }
        })
        .onSslErrorEvent((event: SslErrorEvent) => {
          // ★必须用 onSslErrorEvent 而不是 onSslErrorEventReceive：
          // 后者只覆盖**主框架导航**，而 UI 的每一次 fetch 都是子资源请求——
          // 于是页面本身能加载，登录/拉剖面全部 `Failed to fetch`，
          // 且**一条 SSL 日志都不打**（回调根本没被调用）。两者的事件类型不同，
          // 新的那个带 isMainFrame，正说明它管子资源。
          if (ALLOW_INSECURE_TLS) {
            hilog.error(DOMAIN, TAG,
              '⚠ 接受了无效的 TLS 证书（调试期逃生舱）：本条 HTTPS 只加密不认证，中间人可无声接管。' +
              'mainFrame=%{public}d fatal=%{public}d err=%{public}d url=%{public}s',
              event.isMainFrame ? 1 : 0, event.isFatalError ? 1 : 0, event.error, event.url);
            event.handler.handleConfirm();
          } else {
            hilog.error(DOMAIN, TAG, 'TLS 证书校验失败，已拒绝连接。url=%{public}s', event.url);
            event.handler.handleCancel();
          }
        })
        .onPageEnd(() => {
          try {
            this.controller.runJavaScript(SELFTEST_JS);
          } catch (_err) { /* 页面未就绪，跳过本次自检 */ }
        })
        .onPageBegin(() => {
          // 每次导航后重注入：单页应用内部跳转不会走这里，但整页刷新会。
          try {
            this.controller.runJavaScript(BRIDGE_JS.replace('__DEFAULT_CONTROL__', DEFAULT_CONTROL));
          } catch (_err) { /* 组件尚未 attach，onControllerAttached 会补上 */ }
        })
        .width('100%')
        .height('100%')
    }
    .width('100%')
    .height('100%')
  }
}
