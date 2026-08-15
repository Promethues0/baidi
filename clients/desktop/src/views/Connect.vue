<template>
  <div class="ck">
    <!-- 未登录：登录 -->
    <div v-if="!authedNow" class="ck-login">
      <div class="dk-card ck-login__card">
        <div class="ck-login__logo">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#fff" opacity=".95" />
            <path d="M9 12l2 2 4-4" stroke="#165DFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </div>
        <div class="ck-login__t">登录白帝安全接入</div>
        <div class="ck-login__s">{{ needTotp ? '请输入认证器 App 的动态验证码' : needMfa ? '请完成二次认证' : '使用企业账号登录终端客户端' }}</div>

        <template v-if="!needMfa && !needTotp">
          <a-input v-model="form.username" size="large" placeholder="企业账号" class="ck-inp"><template #prefix><icon-user /></template></a-input>
          <a-input-password v-model="form.password" size="large" placeholder="登录口令" class="ck-inp" @keyup.enter="doLogin(false)"><template #prefix><icon-lock /></template></a-input-password>
        </template>
        <template v-else-if="needTotp">
          <div class="ck-mfa-tip"><icon-exclamation-circle-fill /> {{ mfaReason || '该账号已启用 TOTP 二次认证' }}</div>
          <a-input v-model="form.mfaCode" size="large" placeholder="6 位动态验证码" class="ck-inp" :max-length="6" @keyup.enter="doTotp"><template #prefix><icon-safe /></template></a-input>
        </template>
        <template v-else>
          <div class="ck-mfa-tip"><icon-exclamation-circle-fill /> {{ mfaReason }}</div>
          <a-input v-model="form.mfaCode" size="large" placeholder="验证码" class="ck-inp" @keyup.enter="doLogin(true)"><template #prefix><icon-safe /></template></a-input>
        </template>

        <div v-if="err" class="ck-err"><icon-close-circle-fill /> {{ err }}</div>
        <button class="dk-btn ck-login__btn" :disabled="loading" @click="needTotp ? doTotp() : doLogin(needMfa)">{{ loading ? '验证中…' : (needMfa || needTotp) ? '验证并登录' : '登 录' }}</button>
        <div class="ck-login__hint">演示 <code>li.fang / baidi@123</code> · passkey 二次认证请用浏览器门户，TOTP 可直接在此输入</div>
      </div>
    </div>

    <!-- 已登录：接入 hub -->
    <div v-else class="ck-shell">
      <!--
        客户端灰度更新提示（FR-UPG-19 的终端侧最后一跳）。
        ★判据只有服务端下发的 update 一个布尔值：灰度分桶、定向名单、版本高低比较
        全在控制面做完了，客户端再判一次就等于造第二个版本真相。
        ★横幅只是"提示"，客户端不下载也不安装——文案必须说清，否则用户会以为
        点了按钮就在自动升级，然后在一个什么都没发生的界面前等下去。
      -->
      <div v-if="update?.update" class="ck-upd">
        <icon-download class="ck-upd__ic" />
        <div class="ck-upd__b">
          <!--
            刻意不额外画一枚「灰度批次」标签：inGray 在 percent=100 时对所有人为真，
            标上去就会出现「灰度批次」与下一行「已全量发布」当面打架。
            命中原因由服务端下发的 reason 一句话说清，那是唯一权威的措辞。
            ★但**未命中**灰度时不能直接抄 reason：那时服务端回的是稳定版（update 仍可能为真，
            因为稳定版也比本机新），而 reason 写着「未落入 N% 灰度批次」——照抄就成了
            「已发布新版 v0.4.0」+「未落入 10% 灰度批次」这种自相矛盾的一句。见 updateWhy。
          -->
          <div class="ck-upd__t">
            控制中心已发布新版客户端 v{{ update.latest }}<span v-if="update.current"> · 本机 v{{ update.current }}</span>
          </div>
          <div class="ck-upd__r">{{ updateWhy }} · 客户端不会自动下载或安装，请到门户下载中心手动获取安装包。</div>
        </div>
        <button class="dk-btn dk-btn--ghost ck-upd__btn" @click="openDownloads"><icon-launch />下载中心</button>
      </div>

      <div class="ck-hub">
        <!-- 左：接入状态环 -->
        <div class="dk-card ck-main">
          <div class="ck-ring" :class="stage">
            <div class="ck-ring__inner">
              <component :is="stage === 'connected' ? 'IconCheck' : 'IconLock'" class="ck-ring__ic" />
              <div class="ck-ring__txt">{{ stageLabel }}</div>
            </div>
            <span v-if="stage === 'connecting'" class="ck-ring__pulse" />
          </div>

          <div class="ck-hello">你好，<b>{{ session.user }}</b></div>

          <div v-if="stage === 'connecting'" class="ck-steps">
            <div v-for="(s, i) in STEPS" :key="s" class="ck-step" :class="{ done: i < step, cur: i === step }">
              <span class="ck-step__d"><icon-check v-if="i < step" /></span>{{ s }}
            </div>
          </div>

          <div v-if="denied" class="ck-denied">
            <icon-stop class="ck-denied__ic" />
            <div class="ck-denied__b">
              <div class="ck-denied__t">接入已被控制面拒绝</div>
              <div class="ck-denied__r">{{ deniedReason }}</div>
              <div class="ck-denied__h">隧道已断开。请联系管理员解除后重试——重复接入不会成功。</div>
            </div>
          </div>

          <button v-if="stage === 'idle'" class="dk-btn ck-cta" @click="connect"><icon-link />接入企业内网</button>
          <button v-else-if="stage === 'connected'" class="dk-btn dk-btn--ghost ck-cta" @click="disconnect"><icon-poweroff />断开连接</button>
          <button v-else-if="connectTimedOut" class="dk-btn dk-btn--ghost ck-cta" @click="disconnect"><icon-poweroff />停止接入</button>
          <div v-else class="ck-connecting">接入中…</div>

          <div v-if="err2" class="ck-err2"><icon-exclamation-circle-fill /> {{ err2 }}</div>
          <div v-if="!isTauri" class="ck-devnote">浏览器联调模式 · 真 utun 接管流量需打包客户端运行（需管理员授权）</div>
        </div>

        <!-- 右：环境检测 + 接入信息 -->
        <div class="ck-side">
          <div class="dk-card ck-posture">
            <div class="ck-card__h">终端环境检测
              <span class="ck-trust" :class="{ bad: postureVerdict?.verdict === 'block' || hasFail }">
                {{ trustText }}
              </span>
            </div>
            <!--
              三态渲染：通过 / 关注 / 无法判定。★先看 unknown 再看 ok——探不到时 ok 恒 false，
              只看 ok 会把「这项探不到」画成「这项不合规」，用户于是去排查一个根本不存在的问题
              （Linux 非 root 读不到防火墙、Windows 非管理员读不到 BitLocker 都是常态）。
            -->
            <div v-for="p in posture" :key="p.key" class="ck-pi" :title="p.value">
              <component
                :is="p.unknown ? 'IconQuestionCircleFill' : p.ok ? 'IconCheckCircleFill' : 'IconExclamationCircleFill'"
                :style="{ color: p.unknown ? '#86909C' : p.ok ? '#00B42A' : '#FF7D00' }"
              />
              <span class="ck-pi__l">{{ p.label }}</span>
              <span class="ck-pi__v" :class="{ warn: !p.ok && !p.unknown, undet: p.unknown }">
                {{ p.unknown ? '无法判定' : p.ok ? '通过' : '关注' }}
              </span>
            </div>
            <div v-if="posture.length === 0" class="ck-pi" style="color: var(--bd-t3)">正在采集终端环境…</div>
            <div class="ck-report">
              {{ postureVerdict ? `已上报控制中心 · 判定 ${VERDICT_ZH[postureVerdict.verdict]} · 评分 ${postureVerdict.score}` : '每 60s 周期上报控制中心 · 风险驱动动态收缩权限' }}
            </div>
          </div>

          <div class="dk-card ck-conn" :class="{ off: stage !== 'connected' }">
            <div class="ck-card__h">接入信息<span v-if="stage === 'connected'" class="ck-live">● 隧道活动</span></div>
            <!--
              剖面拿不到 = 接入退回本机默认配置（单网段、无资源映射、无证书钉扎），
              隧道会照常建起来、UI 也会走到「已接入」，但真实业务网段一条都没接管。
              这正是本轮要消灭的「隧道通了却什么都访问不到」，只是换成了无声版本，
              所以必须在接入信息里显著呈现，而不是只写进 store 没人读。
            -->
            <div v-if="profile.error" class="ck-pwarn ck-pwarn--err">
              <icon-exclamation-circle-fill />
              <span>接入剖面拉取失败：{{ profile.error }}。当前用本机默认配置接入，业务网段可能未被接管——请检查控制中心连通性后重新接入。</span>
            </div>
            <!--
              控制面视角下落点全离线。**只提示不拦**：控制面的心跳视角断了（mTLS 口不通、
              控制面刚重启清空了内存台账）并不代表终端连不上网关，硬拦会在那种时候把
              全员挡在门外，而报错指向的恰恰是唯一没问题的组件。
            -->
            <div v-if="allOffline" class="ck-pwarn">
              <icon-exclamation-circle-fill />
              <span>控制中心显示所有网关落点当前离线（心跳未更新）。这不代表终端连不上——已照常尝试接入；若最终超时，请确认 baidi-gateway 已启动，以及它到控制中心 mTLS 端口的注册是否正常。</span>
            </div>
            <!-- 控制面下发的降级告警（如网关未上报证书指纹、应用未关联受控资源） -->
            <div v-for="w in profileWarnings" :key="w" class="ck-pwarn">
              <icon-exclamation-circle-fill />
              <span>{{ w }}</span>
            </div>
            <!--
              隧道参数在拉起那一刻定死：授权范围之后变了（合规降级恢复、管理员新授权、
              JIT 审批通过），运行中的隧道并不会重配接口路由。不呈现的话，用户看到的是
              「已接入、控制台说已恢复、资源还是打不开」——无报错、无线索，最难查的一类。
            -->
            <div v-if="tun.stale" class="ck-pwarn">
              <icon-exclamation-circle-fill />
              <span>{{ tun.staleReason }}</span>
            </div>
            <!--
              故障转移必须让用户知道。切换是静悄悄发生的（数据面自己换了落点），
              不呈现的话用户只会感到「我明明连着但很慢」，而现场没有任何线索指向
              「你现在走的是备用那台异地网关」——那正是最该被看见的一件事。
            -->
            <div v-if="switchedEndpoint" class="ck-pwarn">
              <icon-exclamation-circle-fill />
              <span>已故障转移到备用网关落点（第 {{ tun.endpointIndex }}/{{ tun.endpointTotal }} 个{{ tun.endpointId ? ' · ' + tun.endpointId : '' }}）：{{ tun.endpointReason }}。业务不中断，但链路可能更长；首选落点恢复后需断开重连才会切回。</span>
            </div>
            <template v-if="stage === 'connected'">
              <div class="ck-kv">
                <span>安全代理网关</span>
                <b class="dk-mono">{{ tun.gateway }}<template v-if="tun.endpointId"> · {{ tun.endpointId }}</template></b>
              </div>
              <div class="ck-kv">
                <span>网关落点</span>
                <b :class="{ ok: !switchedEndpoint }">第 {{ tun.endpointIndex }} / 共 {{ tun.endpointTotal }} 个{{ tun.endpointTotal > 1 ? '（失败自动切下一个）' : '（单落点，无容灾余量）' }}</b>
              </div>
              <div class="ck-kv"><span>加密隧道</span><b class="ok">已建立 · {{ tun.cipher }}</b></div>
              <div class="ck-kv"><span>SPA 服务隐身</span><b class="ok">{{ tun.keepalive ? '敲门保活中 · 业务对外不可见' : '已敲门 · 业务对外不可见' }}</b></div>
              <div class="ck-kv"><span>虚拟网卡 / IP</span><b class="dk-mono">{{ tun.dev || 'utun' }} · {{ tun.vip }}</b></div>
              <div class="ck-kv"><span>引流网段</span><b class="dk-mono">{{ tun.route }} → 隧道</b></div>
              <div v-if="isTauri" class="ck-logwrap">
                <div class="ck-log__h" @click="showLog = !showLog"><icon-code /> 数据面日志 <icon-down :class="{ flip: showLog }" /></div>
                <pre v-if="showLog" class="ck-log">{{ tun.lines.join('\n') || '（暂无日志）' }}</pre>
              </div>
            </template>
            <div v-else class="ck-conn__off">接入后展示网关 / 隧道 / 隐身 / 虚拟 IP / 引流网段</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, watch, onMounted, onBeforeUnmount } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, fetchProfile, checkClientUpdate, type PortalLoginResp, type ClientUpdateResp } from '@/lib/api';
import { session, login, authed, validateConfig, profile, setProfile, setProfileError, config } from '@/lib/store';
import { knock } from '@/lib/knock';
import { tauriRuntime, tunnelStart, tunnelStop, tunnelStatus, openAppUrl, type TunView } from '@/lib/tunnel';
import { postureState, collectPosture } from '@/lib/posture';

const authedNow = computed(() => authed());
const isTauri = tauriRuntime();

/* 登录 */
const form = reactive({ username: 'li.fang', password: '', mfaCode: '' });
const needMfa = ref(false);
const needTotp = ref(false);
const totpTicket = ref(''); // 「口令已验」一次性票据（3min），TOTP 第二回合凭它绑定账号
const mfaReason = ref('');
const err = ref('');
const loading = ref(false);
/** 登录时带上本机终端指纹：控制面的认证策略用它判「授信终端」豁免
 *  （这台设备以本账号上报过 posture 且判定通过 → 免掉策略性二次认证）。
 *  ★采集失败不阻断登录：不带指纹 = 未知设备 = 不给豁免，方向是 fail-closed。
 *  指纹与 posture 上报用的是同一个值，两边对不上就等于豁免永远命不中。 */
async function localDeviceID(): Promise<string> {
  try {
    return (await collectPosture()).device;
  } catch {
    return '';
  }
}

async function doLogin(withMfa: boolean) {
  loading.value = true; err.value = '';
  try {
    const r = await api<PortalLoginResp>('/portal/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: form.username, password: form.password,
        mfaCode: withMfa ? form.mfaCode : '', deviceId: await localDeviceID()
      })
    });
    if (r.ok && r.token) {
      login(r.token, r.displayName || form.username);
      await loadProfile(); // 登录即取接入剖面：接入所需的网关落点/路由表/资源映射全在其中
      void checkUpdate();  // 不 await：检查更新是旁路观测，不该让登录多等一个 RTT
    }
    else if (r.needTotp && r.ticket) { needTotp.value = true; totpTicket.value = r.ticket; mfaReason.value = r.reason || ''; form.mfaCode = ''; err.value = ''; }
    else if (r.needWebauthn) { err.value = '该账号已启用 passkey 二次认证：客户端无法完成断言，请改用浏览器门户，或在门户「我的安全」改用 TOTP。'; }
    else if (r.needMfa) { needMfa.value = true; mfaReason.value = r.reason || ''; err.value = ''; }
    else { err.value = r.reason || '登录失败'; }
  } catch { err.value = '无法连接控制中心（检查「设置」里的控制中心地址）'; } finally { loading.value = false; }
}

/** TOTP 第二回合：口令已验票据 + 动态验证码换会话令牌（同码只能成功一次）。 */
async function doTotp() {
  if (!totpTicket.value) { needTotp.value = false; return; }
  if (!/^\d{6}$/.test(form.mfaCode.trim())) { err.value = '请输入 6 位数字验证码'; return; }
  loading.value = true; err.value = '';
  try {
    const r = await api<PortalLoginResp>('/auth/totp', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ticket: totpTicket.value, code: form.mfaCode.trim() })
    });
    if (r.ok && r.token) {
      needTotp.value = false; totpTicket.value = '';
      login(r.token, r.displayName || form.username);
      await loadProfile();
      void checkUpdate();
    } else { err.value = r.reason || '验证码不正确或已使用'; }
  } catch (e) {
    const msg = String((e as Error)?.message ?? '');
    if (msg.startsWith('401') && msg.includes('票据')) { err.value = '认证超时，请重新登录'; needTotp.value = false; totpTicket.value = ''; }
    else { err.value = '验证码不正确或已使用，请输入 App 当前显示的验证码'; }
  } finally { loading.value = false; }
}

/* ── 客户端灰度更新提示（FR-UPG-19 终端侧）── */
const update = ref<ClientUpdateResp | null>(null);

/**
 * 问一次控制面「这台机器此刻该拿哪个版本」。
 *
 * ★平台与版本号取 posture 采集器那一份，不另立来源：Tauri 侧 clientVersion 就是
 * `env!("CARGO_PKG_VERSION")`（真正在跑的这个二进制的版本），platform 也已经是
 * 控制面强枚举里的值。前端再写一份常量的话，包升了而常量没改时，横幅会在新版本上继续挂着。
 * ★取不到版本就**不检查**：服务端把空版本当作「客户端没报，由它自行比对」而无条件
 * 回 update=true，横幅会在早已最新的机器上常亮——那比没有这个功能更糟。
 * ★失败一律静默：旧控制面没有这个端点（404）、控制中心不可达、灰度配置暂不可读（503）
 * 都不该在接入页弹错误。它是观测能力，报不出来的代价是少一条提示，
 * 报出来的代价是把接入页变成噪声源，用户从此连真的告警也不看了。
 */
/**
 * 横幅第二行的措辞。命中灰度时用服务端的 reason（那是权威判定），
 * 未命中时改口说"当前稳定版"——未命中却仍提示升级是**正确**的（他该装的就是稳定版），
 * 但把「未落入 10% 灰度批次」直接摆在「已发布新版 v0.4.0」下面，读起来是自相矛盾的一句。
 */
const updateWhy = computed(() => {
  const u = update.value;
  if (!u) return '';
  return u.inGray === false ? `当前稳定版（${u.reason}）` : u.reason;
});

async function checkUpdate(): Promise<void> {
  // ★先清空再查：登出不卸载本组件（App.vue 只是把 tab 切回接入页）。
  // 不清的话，下一个账号登录时若这次查询失败（控制面不可达 / 旧控制面 404），
  // 他的接入页上会挂着上一个账号的横幅，写着他从未查过的版本号。
  update.value = null;
  try {
    const info = postureState.info ?? (await collectPosture());
    const ver = info.clientVersion?.trim() ?? '';
    if (!ver || !info.platform) return;
    update.value = await checkClientUpdate(info.platform.toLowerCase(), ver);
  } catch { /* 静默：见上方说明 */ }
}

/**
 * 打开门户下载中心。
 *
 * 基址用「控制中心地址」而不是另配一个：标准部署里 nginx 同源服务 console 静态页与
 * /api 反代（deploy/nginx/baidi.conf），门户下载中心就是那个源上的 /portal/downloads。
 * 打开动作走 Rust 侧 open_app_url（前端不放开 shell:allow-open，理由见 main.rs）。
 */
async function openDownloads() {
  const url = config.control.replace(/\/+$/, '') + '/portal/downloads';
  try {
    if (isTauri) await openAppUrl(url);
    else window.open(url, '_blank', 'noopener');
  } catch {
    // 打不开就把地址给他，让他自己粘到浏览器——比一句"打开失败"有用
    Message.info(`请在浏览器打开下载中心：${url}`);
  }
}

/* 接入状态机 —— 真 utun 数据面 */
const STEPS = ['请求管理员授权', '创建 utun 虚拟网卡', 'SPA 敲门 · 建立加密隧道', '受保护网段引流接管'];
const stage = ref<'idle' | 'connecting' | 'connected'>('idle');
const step = ref(0);
const err2 = ref('');
const showLog = ref(false);
const EMPTY_TUN: TunView = { running: false, ready: false, dev: '', vip: '', route: '', gateway: '', cipher: '', keepalive: false, error: '', denied: false, deniedReason: '', stale: false, staleReason: '', endpointIndex: 1, endpointTotal: 1, endpointId: '', endpointReason: '', lines: [] };
const tun = ref<TunView>({ ...EMPTY_TUN });
const stageLabel = computed(() => (stage.value === 'connected' ? '已接入' : stage.value === 'connecting' ? '接入中' : '待接入'));
// 控制面在剖面里下发的降级告警：网关未上报隧道证书指纹（隧道加密但不认证）、
// 应用未关联受控资源（点开必然不走隧道）等。这些都是「配置齐全、就是不生效」
// 的静默失效，控制面已经识别出来了，客户端不呈现等于白识别。
const profileWarnings = computed(() => profile.data?.warnings ?? []);
// 控制面视角下所有落点都离线：只提示、不拦接入（判据见 connect() 里的说明）。
const allOffline = ref(false);
// 当前隧道是否已经不在首选落点上（= 发生过故障转移）。判据取数据面日志解析出的序号，
// 而不是"剖面里第几个"——剖面随时会刷新，运行中的隧道用的是拉起那一刻的清单。
const switchedEndpoint = computed(() => tun.value.running && tun.value.endpointIndex > 1);

let pollTimer = 0;
let pollGen = 0;         // 轮询代次：断开/重连后自增，令过期的在途轮询失效
let connectTO = 0;      // 接入超时计时器
const connectTimedOut = ref(false);
const denied = ref(false);            // 被控制面强制下线 / 账号禁用（不可自愈）
const deniedReason = ref('');
function stepFromTun(v: TunView): number {
  if (v.ready) return STEPS.length;
  if (v.keepalive) return 3;
  if (v.dev) return 2;
  return 1;
}

/**
 * 拉取接入剖面（网关落点 + 路由表 + 资源映射）。
 * 拉不到不阻断接入——用设置页配置兜底试一把，但把原因记下来供「接入」页显示，
 * 因为此时的接入很可能是「隧道起来了却没有正确路由」的半成功状态，必须让用户看见。
 */
async function loadProfile(): Promise<void> {
  try {
    setProfile(await fetchProfile());
  } catch (e) {
    setProfileError(String((e as Error)?.message ?? e));
  }
}

async function connect() {
  err2.value = ''; connectTimedOut.value = false; denied.value = false; deniedReason.value = '';
  if (!isTauri) { await connectDev(); return; }   // 浏览器联调：真敲门探测，不接管流量
  // 剖面可能过期（管理员改了资源/网关重启换了证书指纹），接入前刷新一次，
  // 拿到的路由表与钉扎指纹才与当前策略一致。
  await loadProfile();
  const bad = validateConfig();
  if (bad) { err2.value = bad; return; }          // 接入前配置校验（端口/网段/URL）
  // ★「控制面认为它离线」与「终端连不上它」是两个视角，只有后者才是接入能不能成的事实。
  //
  // 这里此前是 fail-fast 硬拦（一个在线的都没有就连 tunnel_start 都不调），与控制面
  // 「离线也照发落点、让终端自己试」的设计（clientprofile.profileGateways 注释②）
  // 直接矛盾，也与数据面刻意不收 online 字段（dataplane.Endpoint）不一致。
  // 后果很具体：网关经 mTLS 口（8092）注册心跳，客户端走明文管理口（8090）——
  // 8092 证书配错 / 防火墙挡住 / 控制面刚重启（网关台账是内存 map，重启即清空），
  // 此时网关进程、隧道口、敲门口、客户端到控制面的 8090 全都正常，接入本可 100% 成功，
  // 却被自家 UI 拦在门外，报错还指向那个唯一没问题的组件。
  // 现在改成**照常尝试 + 显著提示**：真连不上会在下面 25s 超时那条路上如实报出来。
  const gws = profile.data?.gateways?.length ? profile.data.gateways : profile.data ? [profile.data.gateway] : [];
  allOffline.value = gws.length > 0 && !gws.some((g) => g.online);
  stage.value = 'connecting'; step.value = 0;
  try {
    await tunnelStart();                            // 触发管理员授权 + 后台拉起 baidi-tun（root）
  } catch (e) {
    stage.value = 'idle';
    err2.value = String((e as Error)?.message ?? e);
    return;
  }
  step.value = 1;
  startPolling();
  clearTimeout(connectTO);
  connectTO = window.setTimeout(() => {
    if (stage.value === 'connecting') {
      connectTimedOut.value = true;
      err2.value = '接入超时：数据面已启动但未就绪，请确认网关已运行、且「国密隧道」开关与网关一致';
    }
  }, 25000);
}

function startPolling() {
  clearInterval(pollTimer);
  const gen = ++pollGen;
  pollTimer = window.setInterval(async () => {
    if (gen !== pollGen) return;                 // 代次守卫：忽略过期轮询
    let v: TunView;
    try { v = await tunnelStatus(); } catch { return; }
    if (gen !== pollGen) return;                 // await 期间可能已断开
    tun.value = v;
    if (!v.running) {
      clearInterval(pollTimer);
      session.connected = false;
      if (stage.value !== 'idle') {
        stage.value = 'idle';
        clearTimeout(connectTO); connectTimedOut.value = false;
        if (v.denied) { err2.value = ''; }               // 定性拒绝走专属提示条，不占通用错误位
        else if (v.error) { err2.value = '数据面退出：' + v.error; }
      }
      denied.value = v.denied;
      deniedReason.value = v.deniedReason;
      return;
    }
    step.value = stepFromTun(v);
    if (v.ready) {
      stage.value = 'connected'; session.connected = true;
      connectTimedOut.value = false; err2.value = ''; clearTimeout(connectTO);
    }
  }, 1500);
}

async function disconnect() {
  try { await tunnelStop(); } catch (e) { err2.value = String((e as Error)?.message ?? e); return; }
  pollGen++; clearInterval(pollTimer); clearTimeout(connectTO);
  stage.value = 'idle'; session.connected = false; connectTimedOut.value = false; err2.value = '';
  denied.value = false; deniedReason.value = '';
  tun.value = { ...EMPTY_TUN };
}

/* 浏览器联调：经 knock-agent 真实敲门，UI 走通（不接管系统流量） */
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function connectDev() {
  stage.value = 'connecting'; step.value = 1;
  await sleep(400); step.value = 2; await sleep(300);
  const r = await knock(session.token);
  if (!r.ok) { stage.value = 'idle'; err2.value = 'SPA 敲门失败：' + (r.detail || '网关不可达'); return; }
  step.value = 3; await sleep(300); step.value = STEPS.length;
  tun.value = { ...EMPTY_TUN, running: true, ready: true, dev: 'utun(dev)', vip: '10.99.0.2', route: '10.99.0.0/24', gateway: '127.0.0.1:18443', cipher: '通用 TLS 1.3', lines: [(r.detail || 'SPA 敲门成功')] };
  stage.value = 'connected'; session.connected = true;
  Message.success('（联调）已敲门 · 真 utun 接管需打包运行');
}

/* 环境检测：读 App 级共享状态（上报循环脱离视图，切 Tab 不中断） */
const postureVerdict = computed(() => postureState.verdict);
const posture = computed(() => postureState.info?.checks ?? []);
// 「确定不合规」与「探不到」必须分开统计：混在一起会把一台控制面判为 allow 的机器
// 标成"存在风险"，用户去查一个不存在的问题；反过来把探不到当通过则是虚假的安心。
const hasFail = computed(() => posture.value.some((p) => !p.ok && !p.unknown));
const hasUndet = computed(() => posture.value.some((p) => p.unknown));
const allOk = computed(() => posture.value.length > 0 && !hasFail.value && !hasUndet.value);
const VERDICT_ZH: Record<string, string> = { allow: '合规', degrade: '降权', gray: '灰度', block: '阻断' };
// 判定文案以**控制面判定**为准（判定权在控制面），本地采集只用来解释原因。
const trustText = computed(() => {
  const v = postureVerdict.value;
  if (!v) return '采集中…';
  if (v.verdict === 'block') return '接入受限';
  if (hasFail.value || v.verdict !== 'allow') return '存在风险';
  return hasUndet.value ? '部分项无法判定' : '终端可信';
});

/**
 * 控制面判定档位一变就重拉剖面。
 *
 * ★没有这条的话，「因终端合规降级：xx 已暂停访问」这句话要等到用户下次点接入
 * （或切到「应用」页）才会出现——而降权恰恰发生在**已经接入之后**：用户看到的是
 * 环境检测那枚"存在风险"的小标签，以及一个打不开的财务系统，两者之间没有任何连线。
 * 剖面在这一刻重拉，接入信息卡里就会立刻多出那条写明原因与影响面的告警。
 * 只在档位真的变化时拉，不跟着 60s 心跳空转。
 */
watch(() => postureVerdict.value?.verdict, (now, before) => {
  if (!authedNow.value || !now || now === before) return;
  void loadProfile();
});

/* 重开 app 时若隧道仍在跑，恢复已接入态 */
onMounted(async () => {
  if (!authedNow.value) return;
  // 令牌存在 localStorage：重开 app 是直接落在已登录态的，登录那条路径根本不跑。
  // 少了这一句，只有"当次输过密码"的人才看得到新版提示，而常驻用户几乎从不重新登录。
  void checkUpdate();
  if (!isTauri) return;
  try {
    const v = await tunnelStatus();
    if (v.running) { tun.value = v; stage.value = v.ready ? 'connected' : 'connecting'; session.connected = v.ready; if (!v.ready) startPolling(); else startPolling(); }
  } catch { /* ignore */ }
});
onBeforeUnmount(() => { pollGen++; clearInterval(pollTimer); clearTimeout(connectTO); });
</script>

<style scoped>
.ck { height: 100%; padding: 24px; }

/* 登录 */
.ck-login { height: 100%; display: flex; align-items: center; justify-content: center; }
.ck-login__card { width: 340px; padding: 32px 28px 24px; text-align: center; }
.ck-login__logo { width: 48px; height: 48px; border-radius: 13px; margin: 0 auto; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d)); box-shadow: 0 4px 12px rgba(22, 93, 255, .32); }
.ck-login__t { font-size: 17px; font-weight: 700; margin-top: 14px; }
.ck-login__s { font-size: 12px; color: var(--bd-t3); margin: 5px 0 20px; }
.ck-inp { margin-bottom: 13px; }
.ck-mfa-tip { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--bd-warning); background: var(--bd-tag-gold-bg); border-radius: 7px; padding: 8px 10px; margin-bottom: 12px; }
.ck-err { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--bd-danger); margin: -4px 0 10px; }
.ck-login__btn { width: 100%; height: 40px; justify-content: center; font-size: 14px; letter-spacing: 2px; margin-top: 2px; }
.ck-login__hint { font-size: 11.5px; color: var(--bd-t3); margin-top: 14px; line-height: 1.7; }
.ck-login__hint code { color: var(--bd-primary); background: var(--bd-primary-1); padding: 1px 5px; border-radius: 4px; font-family: ui-monospace, monospace; }

/* 接入 hub */
.ck-shell { height: 100%; display: flex; flex-direction: column; gap: 14px; }
/* min-height:0 不能省：flex 子项默认 min-height:auto，内容一多会把 hub 顶出容器，
   表现为整页出现滚动条而卡片自身不再滚动 */
.ck-hub { display: flex; gap: 18px; flex: 1; min-height: 0; }

/* 新版本横幅：蓝色信息色而非橙/红——有新版是通知，不是故障，用告警色会与
   上面那批"配置没生效"的橙条抢注意力，而它们的紧急程度完全不同 */
.ck-upd { flex: none; display: flex; align-items: center; gap: 12px; padding: 12px 16px;
  border-radius: 10px; background: var(--bd-primary-1); border: 1px solid rgba(22, 93, 255, .26); }
.ck-upd__ic { font-size: 20px; color: var(--bd-primary); flex: none; }
.ck-upd__b { flex: 1; min-width: 0; }
.ck-upd__t { font-size: 13px; font-weight: 600; color: var(--bd-t1); }
.ck-upd__r { font-size: 11.5px; color: var(--bd-t3); margin-top: 4px; line-height: 1.6; }
.ck-upd__btn { flex: none; height: 32px; padding: 0 14px; font-size: 12.5px; }
.ck-main { flex: 1; min-width: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 24px; }
.ck-ring { width: 152px; height: 152px; border-radius: 50%; position: relative; display: flex; align-items: center; justify-content: center; background: var(--bd-fill-2); border: 3px solid var(--bd-t4); transition: all .3s; }
.ck-ring.connecting { border-color: var(--bd-primary); background: var(--bd-primary-1); }
.ck-ring.connected { border-color: var(--bd-success); background: #E8FFEA; }
.ck-ring__inner { text-align: center; }
.ck-ring__ic { font-size: 40px; color: var(--bd-t3); }
.ck-ring.connecting .ck-ring__ic { color: var(--bd-primary); }
.ck-ring.connected .ck-ring__ic { color: var(--bd-success); }
.ck-ring__txt { font-size: 15px; font-weight: 700; margin-top: 6px; color: var(--bd-t1); }
.ck-ring__pulse { position: absolute; inset: -3px; border-radius: 50%; border: 3px solid var(--bd-primary); animation: ckpulse 1.4s ease-out infinite; }
@keyframes ckpulse { 0% { transform: scale(1); opacity: .6; } 100% { transform: scale(1.25); opacity: 0; } }
.ck-hello { font-size: 14px; color: var(--bd-t2); margin: 18px 0 6px; }
.ck-hello b { color: var(--bd-t1); }
.ck-steps { margin: 8px 0 14px; width: 240px; }
.ck-step { display: flex; align-items: center; gap: 8px; font-size: 12.5px; color: var(--bd-t3); padding: 4px 0; }
.ck-step.cur { color: var(--bd-primary); font-weight: 600; }
.ck-step.done { color: var(--bd-t2); }
.ck-step__d { width: 16px; height: 16px; border-radius: 50%; border: 1.5px solid currentColor; display: inline-flex; align-items: center; justify-content: center; font-size: 10px; }
.ck-cta { height: 42px; padding: 0 28px; font-size: 14px; margin-top: 10px; }
.ck-connecting { font-size: 13px; color: var(--bd-primary); margin-top: 12px; }
.ck-err2 { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--bd-danger); margin-top: 12px; max-width: 280px; text-align: left; }
.ck-denied { display: flex; gap: 10px; align-items: flex-start; margin-top: 16px; max-width: 300px; text-align: left; padding: 12px 14px; border-radius: 10px; background: rgba(245, 63, 63, .08); border: 1px solid rgba(245, 63, 63, .28); }
.ck-denied__ic { font-size: 20px; color: var(--bd-danger); flex: none; margin-top: 1px; }
.ck-denied__t { font-size: 13px; font-weight: 600; color: var(--bd-danger); }
.ck-denied__r { font-size: 12px; color: var(--bd-t1); margin-top: 4px; line-height: 1.5; }
.ck-denied__h { font-size: 11px; color: var(--bd-t3); margin-top: 6px; line-height: 1.6; }
.ck-devnote { font-size: 11px; color: var(--bd-t3); margin-top: 14px; max-width: 260px; text-align: center; line-height: 1.6; }

/* 剖面告警：橙=控制面下发的降级提示，红=剖面根本没拿到（接入已退回本机默认配置） */
.ck-pwarn { display: flex; gap: 6px; align-items: flex-start; font-size: 11px; line-height: 1.55;
  color: var(--bd-warning, #FF7D00); padding: 8px 10px; margin-bottom: 8px; border-radius: 8px;
  background: rgba(255, 125, 0, .08); border: 1px solid rgba(255, 125, 0, .24); }
.ck-pwarn--err { color: var(--bd-danger); background: rgba(245, 63, 63, .08); border-color: rgba(245, 63, 63, .28); }

.ck-side { width: 320px; flex: none; display: flex; flex-direction: column; gap: 16px; }
.ck-card__h { font-size: 14px; font-weight: 600; padding: 14px 16px; border-bottom: 1px solid var(--bd-fill-2); display: flex; align-items: center; justify-content: space-between; }
.ck-trust { font-size: 11px; font-weight: 500; color: var(--bd-success); background: #E8FFEA; padding: 2px 8px; border-radius: 10px; }
.ck-trust.bad { color: var(--bd-warning); background: var(--bd-tag-gold-bg); }
.ck-live { font-size: 11px; font-weight: 500; color: var(--bd-success); }
.ck-posture { padding-bottom: 6px; }
.ck-pi { display: flex; align-items: center; gap: 9px; padding: 9px 16px; font-size: 13px; }
.ck-pi__l { flex: 1; color: var(--bd-t1); }
.ck-pi__v { font-size: 12px; color: var(--bd-success); }
.ck-pi__v.warn { color: var(--bd-warning); }
/* 无法判定：中性灰。用红/橙会被读成"不合规"，那正是三态要区分开的东西 */
.ck-pi__v.undet { color: var(--bd-t3); }
.ck-report { font-size: 11px; color: var(--bd-t3); padding: 8px 16px 12px; border-top: 1px solid var(--bd-fill-2); margin-top: 4px; }
.ck-conn { padding-bottom: 8px; }
.ck-conn.off { opacity: .8; }
.ck-kv { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 16px; font-size: 13px; border-bottom: 1px solid var(--bd-fill-1); }
.ck-kv:last-child { border-bottom: none; }
.ck-kv span { color: var(--bd-t3); flex: none; }
.ck-kv b { font-weight: 500; color: var(--bd-t1); text-align: right; }
.ck-kv b.ok { color: var(--bd-success); }
.ck-conn__off { padding: 18px 16px; font-size: 12.5px; color: var(--bd-t3); }
.ck-logwrap { padding: 4px 16px 10px; }
.ck-log__h { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--bd-t3); cursor: pointer; padding: 6px 0; }
.ck-log__h .flip { transform: rotate(180deg); }
.ck-log { margin: 4px 0 0; padding: 10px; background: #0e1f33; color: #9fd0ff; border-radius: 7px; font-size: 11px; line-height: 1.5; max-height: 150px; overflow: auto; white-space: pre-wrap; word-break: break-all; font-family: ui-monospace, monospace; }
</style>
