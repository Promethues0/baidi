<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">账号安全<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">会话 / 时段 / 并发 / 防爆破 / 上线通知 · 所有「0 / 关闭」=不启用，等价旧行为，向后兼容</div>
      </div>
      <a-space>
        <a-button size="small" @click="resetDefault">恢复默认</a-button>
        <a-button type="primary" size="small" @click="save">保存策略</a-button>
      </a-space>
    </div>

    <div class="zl-grid" style="grid-template-columns: repeat(2, 1fr); align-items:start;">
      <!-- 并发控制 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title">并发控制</div>
        <div class="sp-sub">同一账号允许的并发在线数（白帝语义：0 = 不限制并发，并非禁止登录）</div>
        <div class="sp-rows">
          <div class="sp-row">
            <div class="sp-row__lab">最大并发数
              <span class="sp-hint">0=不限制</span>
            </div>
            <a-input-number v-model="doc.concurrency.max" :min="0" size="small" style="width:160px">
              <template #suffix>端</template>
            </a-input-number>
          </div>
          <div class="sp-row">
            <div class="sp-row__lab">分平台限制
              <span class="sp-hint">PC 与移动端各自计数</span>
            </div>
            <a-switch v-model="doc.concurrency.splitPlatform" size="small" />
          </div>
          <template v-if="doc.concurrency.splitPlatform">
            <div class="sp-row sp-row--sub">
              <div class="sp-row__lab">PC 端上限<span class="sp-hint">0=不限制</span></div>
              <a-input-number v-model="doc.concurrency.maxPC" :min="0" size="small" style="width:160px">
                <template #suffix>端</template>
              </a-input-number>
            </div>
            <div class="sp-row sp-row--sub">
              <div class="sp-row__lab">移动端上限<span class="sp-hint">0=不限制</span></div>
              <a-input-number v-model="doc.concurrency.maxMobile" :min="0" size="small" style="width:160px">
                <template #suffix>端</template>
              </a-input-number>
            </div>
          </template>
        </div>
      </div>

      <!-- 会话超时 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title">会话超时</div>
        <div class="sp-sub">空闲与无操作自动注销，降低会话被劫持的窗口期</div>
        <div class="sp-rows">
          <div class="sp-row">
            <div class="sp-row__lab">会话空闲注销
              <span class="sp-hint">0=不启用</span>
            </div>
            <a-input-number v-model="doc.idleTimeoutMin" :min="0" size="small" style="width:160px">
              <template #suffix>分钟</template>
            </a-input-number>
          </div>
          <div class="sp-row">
            <div class="sp-row__lab">PC 无操作注销
              <span class="sp-hint">0=不启用</span>
            </div>
            <a-input-number v-model="doc.pcInactivityMin" :min="0" size="small" style="width:160px">
              <template #suffix>分钟</template>
            </a-input-number>
          </div>
        </div>
      </div>

      <!-- 闲置扫描 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title">闲置账号扫描</div>
        <div class="sp-sub">超过阈值未登录的账号判定为「闲置」，此值驱动用户列表的「闲置」徽标显示</div>
        <div class="sp-rows">
          <div class="sp-row">
            <div class="sp-row__lab">闲置判定阈值
              <span class="sp-hint">0=不扫描</span>
            </div>
            <a-input-number v-model="doc.idleThresholdDays" :min="0" size="small" style="width:160px">
              <template #suffix>天</template>
            </a-input-number>
          </div>
          <div class="sp-row">
            <div class="sp-row__lab">自动处置扫描周期
              <span class="sp-hint">0=不启用内置定时扫描</span>
            </div>
            <a-input-number v-model="doc.idleScanIntervalH" :min="0" size="small" style="width:160px">
              <template #suffix>小时</template>
            </a-input-number>
          </div>
          <div class="sp-row">
            <div class="sp-row__lab">闲置账号自动禁用</div>
            <a-switch v-model="doc.autoLockIdle" size="small" />
          </div>
          <div class="sp-row">
            <div class="sp-row__lab">过期账号自动禁用</div>
            <a-switch v-model="doc.autoLockExpired" size="small" />
          </div>
        </div>
        <div class="sp-note">
          阈值由控制面在拉取用户列表时计算 lastLoginAt 与当前时间差；设为 <b>0</b> 即停止扫描（等价旧行为）。
          开启<b>自动禁用</b>后，控制面内置定时任务按上述周期扫描并将闲置/过期账号置为「已禁用」（写审计），
          关闭则仅标注徽标、不自动处置。
        </div>
      </div>

      <!-- 访问时段 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title">访问时段</div>
        <div class="sp-sub">限制账号仅在指定星期与时间段内可登录（关闭=全天不限）</div>
        <div class="sp-rows">
          <div class="sp-row">
            <div class="sp-row__lab">启用时段限制
              <span class="sp-hint">关闭=不限制</span>
            </div>
            <a-switch v-model="doc.accessWindow.enabled" size="small" />
          </div>
          <template v-if="doc.accessWindow.enabled">
            <div class="sp-row sp-row--col sp-row--sub">
              <div class="sp-row__lab">允许的星期</div>
              <a-checkbox-group v-model="doc.accessWindow.days" style="margin-top:6px">
                <a-checkbox v-for="d in WEEK" :key="d.value" :value="d.value">{{ d.label }}</a-checkbox>
              </a-checkbox-group>
            </div>
            <div class="sp-row sp-row--sub">
              <div class="sp-row__lab">起止时间</div>
              <a-space>
                <a-time-picker v-model="doc.accessWindow.start" format="HH:mm" size="small" style="width:120px" />
                <span style="color:var(--ink-3)">至</span>
                <a-time-picker v-model="doc.accessWindow.end" format="HH:mm" size="small" style="width:120px" />
              </a-space>
            </div>
            <div class="sp-row sp-row--sub">
              <div class="sp-row__lab">有效期类型</div>
              <a-select v-model="doc.accessWindow.validity" size="small" style="width:200px">
                <a-option value="permanent">长期有效</a-option>
                <a-option value="range">指定日期区间</a-option>
                <a-option value="once">仅一次</a-option>
              </a-select>
            </div>
          </template>
        </div>
      </div>

      <!-- 防爆破 -->
      <div class="zl-card zl-card__pad" style="grid-column:1 / -1">
        <div class="zl-card__title">防爆破（暴力破解防护）</div>
        <div class="sp-sub">连续登录失败时按来源 IP / 账号维度锁定，可叠加图形验证码（REQ-SEC-012）</div>
        <div class="zl-grid" style="grid-template-columns: repeat(2, 1fr); gap:0 28px;">
          <!-- IP 维度 -->
          <div class="sp-rows">
            <div class="sp-row">
              <div class="sp-row__lab">按 IP 锁定
                <span class="sp-hint">同源 IP 失败计数</span>
              </div>
              <a-switch v-model="doc.bruteForce.ipEnabled" size="small" />
            </div>
            <template v-if="doc.bruteForce.ipEnabled">
              <div class="sp-row sp-row--sub">
                <div class="sp-row__lab">失败阈值</div>
                <a-input-number v-model="doc.bruteForce.ipThreshold" :min="1" size="small" style="width:150px">
                  <template #suffix>次</template>
                </a-input-number>
              </div>
              <div class="sp-row sp-row--sub">
                <div class="sp-row__lab">锁定时长</div>
                <a-input-number v-model="doc.bruteForce.ipLockMin" :min="0" size="small" style="width:150px">
                  <template #suffix>分钟</template>
                </a-input-number>
              </div>
            </template>
          </div>
          <!-- 账号维度 -->
          <div class="sp-rows">
            <div class="sp-row">
              <div class="sp-row__lab">按账号锁定
                <span class="sp-hint">单账号失败计数</span>
              </div>
              <a-switch v-model="doc.bruteForce.userEnabled" size="small" />
            </div>
            <template v-if="doc.bruteForce.userEnabled">
              <div class="sp-row sp-row--sub">
                <div class="sp-row__lab">失败阈值</div>
                <a-input-number v-model="doc.bruteForce.userThreshold" :min="1" size="small" style="width:150px">
                  <template #suffix>次</template>
                </a-input-number>
              </div>
              <div class="sp-row sp-row--sub">
                <div class="sp-row__lab">锁定时长
                  <span class="sp-hint">0=需管理员解锁</span>
                </div>
                <a-input-number v-model="doc.bruteForce.userLockMin" :min="0" size="small" style="width:150px">
                  <template #suffix>分钟</template>
                </a-input-number>
              </div>
            </template>
          </div>
        </div>
        <div class="sp-row" style="border-top:1px solid var(--line);margin-top:6px;padding-top:14px">
          <div class="sp-row__lab">触发后要求图形验证码
            <span class="sp-hint">达阈值前先弹验证码缓冲</span>
          </div>
          <a-switch v-model="doc.bruteForce.captcha" size="small" />
        </div>
      </div>

      <!-- 风险通知 -->
      <div class="zl-card zl-card__pad" style="grid-column:1 / -1">
        <div class="zl-card__title">风险通知（上线 / 异常提醒）</div>
        <div class="sp-sub">命中以下场景时向账号本人推送提醒（全部关闭=不通知）</div>
        <div class="zl-grid" style="grid-template-columns: repeat(2, 1fr); gap:0 28px;">
          <div class="sp-row">
            <div class="sp-row__lab">首次登录提醒
              <span class="sp-hint">账号首次成功登录</span>
            </div>
            <a-switch v-model="doc.riskNotify.firstLogin" size="small" />
          </div>
          <div class="sp-row">
            <div class="sp-row__lab">新设备登录提醒
              <span class="sp-hint">未见过的设备指纹</span>
            </div>
            <a-switch v-model="doc.riskNotify.newDevice" size="small" />
          </div>
          <div class="sp-row">
            <div class="sp-row__lab">异地登录提醒
              <span class="sp-hint">常用地之外的登录地</span>
            </div>
            <a-switch v-model="doc.riskNotify.newLocation" size="small" />
          </div>
          <div class="sp-row">
            <div class="sp-row__lab">爆破锁定提醒
              <span class="sp-hint">触发防爆破锁定时</span>
            </div>
            <a-switch v-model="doc.riskNotify.bruteForceLock" size="small" />
          </div>
        </div>
      </div>
    </div>

    <div class="sp-foot">
      <span class="sp-foot__tip">改动保存后 ≤60s 下发并写审计{{ live ? ' · 已对接持久化' : ' · 当前 mock 演示' }}</span>
      <a-space>
        <a-button size="small" @click="resetDefault">恢复默认</a-button>
        <a-button type="primary" size="small" @click="save">保存策略</a-button>
      </a-space>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';

// 账号安全策略单文档：kind=secpolicy, key=default。
// 语义约定：所有 enabled:false / 数值 0 = 不启用 = 旧行为（向后兼容）。
type SecPolicy = {
  concurrency: { max: number; splitPlatform: boolean; maxPC: number; maxMobile: number };
  idleTimeoutMin: number;
  pcInactivityMin: number;
  idleThresholdDays: number;
  idleScanIntervalH: number;
  autoLockIdle: boolean;
  autoLockExpired: boolean;
  accessWindow: { enabled: boolean; days: number[]; start: string; end: string; validity: string };
  bruteForce: {
    ipEnabled: boolean; ipThreshold: number; ipLockMin: number;
    userEnabled: boolean; userThreshold: number; userLockMin: number;
    captcha: boolean;
  };
  riskNotify: { firstLogin: boolean; newDevice: boolean; newLocation: boolean; bruteForceLock: boolean };
};

// 星期取值：周一..周六=1..6，周日=0（与后端 seed accessWindow.days 一致）。
const WEEK = [
  { label: '周一', value: 1 }, { label: '周二', value: 2 }, { label: '周三', value: 3 },
  { label: '周四', value: 4 }, { label: '周五', value: 5 }, { label: '周六', value: 6 },
  { label: '周日', value: 0 }
];

// 默认策略（与后端 seedColls secpolicy/default 对齐：idleThresholdDays=90, IP 10/30, 账号 5/15）。
function defaults(): SecPolicy {
  return {
    concurrency: { max: 0, splitPlatform: false, maxPC: 0, maxMobile: 0 },
    idleTimeoutMin: 0,
    pcInactivityMin: 0,
    idleThresholdDays: 90,
    idleScanIntervalH: 12,
    autoLockIdle: false,
    autoLockExpired: false,
    accessWindow: { enabled: false, days: [1, 2, 3, 4, 5], start: '08:00', end: '21:00', validity: 'permanent' },
    bruteForce: {
      ipEnabled: true, ipThreshold: 10, ipLockMin: 30,
      userEnabled: true, userThreshold: 5, userLockMin: 15,
      captcha: false
    },
    riskNotify: { firstLogin: false, newDevice: true, newLocation: true, bruteForceLock: true }
  };
}

const doc = ref<SecPolicy>(defaults());
const live = ref(false);

// 深合并后端文档到默认值，缺字段回落默认（向后兼容旧文档）。
function mergeDoc(d: any): SecPolicy {
  const base = defaults();
  if (!d || typeof d !== 'object') return base;
  return {
    concurrency: { ...base.concurrency, ...(d.concurrency ?? {}) },
    idleTimeoutMin: d.idleTimeoutMin ?? base.idleTimeoutMin,
    pcInactivityMin: d.pcInactivityMin ?? base.pcInactivityMin,
    idleThresholdDays: d.idleThresholdDays ?? base.idleThresholdDays,
    idleScanIntervalH: d.idleScanIntervalH ?? base.idleScanIntervalH,
    autoLockIdle: d.autoLockIdle ?? base.autoLockIdle,
    autoLockExpired: d.autoLockExpired ?? base.autoLockExpired,
    accessWindow: { ...base.accessWindow, ...(d.accessWindow ?? {}) },
    bruteForce: { ...base.bruteForce, ...(d.bruteForce ?? {}) },
    riskNotify: { ...base.riskNotify, ...(d.riskNotify ?? {}) }
  };
}

// 策略来自控制面 /ctl/api/coll?kind=secpolicy（单文档 key=default）；不可达时降级前端默认。
async function load() {
  try {
    const r = await fetch('/ctl/api/coll?kind=secpolicy');
    if (!r.ok) return;
    const docs = await r.json();
    // 单文档集合：直接取首项（不依赖 doc 体内的 key 字段）
    const found = Array.isArray(docs) && docs.length ? docs[0] : null;
    if (found) doc.value = mergeDoc(found);
    live.value = true;
  } catch { live.value = false; }
}
onMounted(load);

// 保存：POST 单文档（后端自动写审计）；mock 态仅前端反馈。
async function save() {
  if (!live.value) {
    Message.success('策略已保存（mock 演示，未持久化）');
    return;
  }
  try {
    const r = await fetch('/ctl/api/coll?kind=secpolicy', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: 'default', doc: doc.value })
    });
    if (!r.ok) return Message.error('保存失败');
    Message.success('账号安全策略已保存 · 已持久化 · ≤60s 下发并写审计');
  } catch { Message.error('保存失败，控制面不可达'); }
}

// 恢复默认：二次确认后重置为 seed 默认值（不立即落库，需再点保存）。
function resetDefault() {
  Modal.warning({
    title: '恢复默认策略',
    content: '将把当前页面所有项重置为系统默认值（与后端种子一致）。重置后需点「保存策略」才会生效。是否继续？',
    okText: '恢复默认',
    hideCancel: false,
    onOk: () => {
      doc.value = defaults();
      Message.info('已恢复默认值，记得点「保存策略」生效');
    }
  });
}
</script>

<style scoped>
.sp-sub { font-size: 11.5px; color: var(--ink-3); margin: 4px 0 12px; line-height: 1.5; }

.sp-rows { display: flex; flex-direction: column; }
.sp-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 11px 0; }
.sp-row + .sp-row { border-top: 1px solid var(--line); }
.sp-row--sub { padding-left: 14px; }
.sp-row--col { flex-direction: column; align-items: flex-start; }
.sp-row__lab { font-size: 13px; font-weight: 600; color: var(--ink); display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.sp-hint { font-size: 10.5px; color: var(--ink-3); font-weight: 400; }

.sp-note { margin-top: 12px; padding: 10px 12px; border-radius: var(--r-md); background: var(--accent-soft); font-size: 11.5px; color: var(--ink-2); line-height: 1.6; }
.sp-note b { color: var(--accent-2); }

.sp-foot { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 16px; padding: 14px 16px; border-radius: var(--r-md); background: var(--fill-1, rgba(0,0,0,.02)); border: 1px solid var(--line); }
.sp-foot__tip { font-size: 11.5px; color: var(--ink-3); }
</style>
