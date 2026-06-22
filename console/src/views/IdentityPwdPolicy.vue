<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">口令策略<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">本地账号库口令的复杂度 / 有效期 / 历史 / 锁定 · 仅对 source=local 账号生效 · 外部目录（LDAP/AD/OIDC）口令由源系统管理</div>
      </div>
    </div>

    <!-- 单文档整体保存：kind=pwdpolicy / key=default -->
    <div class="zl-card zl-card__pad pp-card">
      <a-form :model="doc" layout="vertical" auto-label-width>
        <!-- 适用范围 + 复杂度 -->
        <div class="pp-sec">
          <div class="zl-card__title pp-sec__title">适用范围与复杂度</div>
          <a-grid :cols="2" :col-gap="24" :row-gap="4">
            <a-grid-item>
              <a-form-item field="scope" label="适用范围">
                <a-select v-model="doc.scope" style="max-width:260px">
                  <a-option value="local">本地账号（source=local）</a-option>
                  <a-option value="all">全部账号</a-option>
                </a-select>
                <template #extra>外部目录账号口令由源系统校验，选「全部账号」仅对本地落地凭据生效</template>
              </a-form-item>
            </a-grid-item>
            <a-grid-item>
              <a-form-item field="minLength" label="最小长度">
                <a-input-number v-model="doc.minLength" :min="0" :max="128" style="width:160px">
                  <template #suffix>位</template>
                </a-input-number>
              </a-form-item>
            </a-grid-item>
          </a-grid>

          <a-form-item label="字符复杂度要求" content-class="pp-cplx">
            <div class="pp-cplx__row">
              <div class="pp-cplx__item">
                <a-switch v-model="doc.complexity.lower" size="small" />
                <span>包含小写字母 a-z</span>
              </div>
              <div class="pp-cplx__item">
                <a-switch v-model="doc.complexity.upper" size="small" />
                <span>包含大写字母 A-Z</span>
              </div>
              <div class="pp-cplx__item">
                <a-switch v-model="doc.complexity.digit" size="small" />
                <span>包含数字 0-9</span>
              </div>
              <div class="pp-cplx__item">
                <a-switch v-model="doc.complexity.special" size="small" />
                <span>包含特殊字符 !@#$…</span>
              </div>
            </div>
          </a-form-item>

          <a-form-item field="forbidEmpty" label="禁止空口令">
            <a-switch v-model="doc.forbidEmpty" />
            <template #extra>开启后不允许设置空白口令，强制要求至少满足上述复杂度</template>
          </a-form-item>

          <a-form-item field="weakList" label="弱口令黑名单">
            <a-input-tag v-model="doc.weakList" placeholder="输入弱口令后回车添加" allow-clear style="max-width:520px" />
            <template #extra>命中黑名单的口令直接拒绝（不区分大小写）· 留空=不启用</template>
          </a-form-item>
        </div>

        <!-- 有效期与历史 -->
        <div class="pp-sec">
          <div class="zl-card__title pp-sec__title">有效期与历史</div>
          <a-grid :cols="2" :col-gap="24" :row-gap="4">
            <a-grid-item>
              <a-form-item field="expiryDays" label="有效期">
                <a-input-number v-model="doc.expiryDays" :min="0" :max="3650" style="width:160px">
                  <template #suffix>天</template>
                </a-input-number>
                <template #extra>0 = 永不过期</template>
              </a-form-item>
            </a-grid-item>
            <a-grid-item>
              <a-form-item field="notifyDays" label="到期前提醒">
                <a-input-number v-model="doc.notifyDays" :min="0" :max="365" style="width:160px">
                  <template #suffix>天</template>
                </a-input-number>
                <template #extra>0 = 不提醒</template>
              </a-form-item>
            </a-grid-item>
            <a-grid-item>
              <a-form-item field="reuseForbidN" label="禁止重复使用">
                <a-input-number v-model="doc.reuseForbidN" :min="0" :max="50" style="width:160px">
                  <template #suffix>次</template>
                </a-input-number>
                <template #extra>0 = 不限 · 记录最近 N 次口令历史并禁止复用</template>
              </a-form-item>
            </a-grid-item>
            <a-grid-item>
              <a-form-item field="minChangeIntervalH" label="最小修改间隔">
                <a-input-number v-model="doc.minChangeIntervalH" :min="0" :max="8760" style="width:160px">
                  <template #suffix>小时</template>
                </a-input-number>
                <template #extra>0 = 不限 · 防止用户连续改密绕过历史策略</template>
              </a-form-item>
            </a-grid-item>
          </a-grid>

          <a-form-item field="forceChangeOnFirstLogin" label="首次登录强制改密">
            <a-switch v-model="doc.forceChangeOnFirstLogin" />
            <template #extra>新建 / 重置账号后首次登录必须修改初始口令</template>
          </a-form-item>
        </div>

        <!-- 策略摘要 -->
        <div class="pp-summary">
          <span class="pp-summary__lbl">当前策略摘要</span>
          <span class="pp-summary__txt">{{ summary }}</span>
        </div>

        <!-- 底部操作 -->
        <div class="pp-foot">
          <span class="pp-foot__tip">改动 ≤60s 下发在线端点 · 写审计{{ live ? ' · 持久化' : '（mock 降级，重启丢失）' }}</span>
          <a-space>
            <a-button @click="restoreDefault">恢复默认</a-button>
            <a-button type="primary" :loading="saving" @click="save">保存策略</a-button>
          </a-space>
        </div>
      </a-form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';

const KIND = 'pwdpolicy';
const KEY = 'default';

type PwdPolicy = {
  scope: 'local' | 'all';
  minLength: number;
  complexity: { lower: boolean; upper: boolean; digit: boolean; special: boolean };
  forbidEmpty: boolean;
  weakList: string[];
  expiryDays: number;
  notifyDays: number;
  reuseForbidN: number;
  minChangeIntervalH: number;
  forceChangeOnFirstLogin: boolean;
};

// 默认策略（与后端 seed 对齐）：默认值即下发的口令策略。
const defaults = (): PwdPolicy => ({
  scope: 'local',
  minLength: 8,
  complexity: { lower: true, upper: true, digit: true, special: false },
  forbidEmpty: true,
  weakList: ['12345678', 'password', 'admin@123'],
  expiryDays: 90,
  notifyDays: 7,
  reuseForbidN: 3,
  minChangeIntervalH: 0,
  forceChangeOnFirstLogin: true
});

const doc = ref<PwdPolicy>(defaults());
const live = ref(false);
const saving = ref(false);

// 一句话策略摘要：把当前表单浓缩成可读约束串。
const summary = computed(() => {
  const c = doc.value.complexity;
  const cls = [c.lower && '小写', c.upper && '大写', c.digit && '数字', c.special && '特殊字符'].filter(Boolean);
  const parts: string[] = [];
  parts.push(`≥${doc.value.minLength} 位`);
  parts.push(cls.length ? `需含 ${cls.join('/')}` : '无字符类型要求');
  parts.push(doc.value.expiryDays > 0 ? `${doc.value.expiryDays} 天有效` : '永不过期');
  parts.push(doc.value.reuseForbidN > 0 ? `禁复用前 ${doc.value.reuseForbidN} 次` : '不限历史复用');
  if (doc.value.forceChangeOnFirstLogin) parts.push('首登强制改密');
  return parts.join(' · ') + ` · 适用 ${doc.value.scope === 'all' ? '全部账号' : '本地账号'}`;
});

// 加载：/ctl/api/coll?kind=pwdpolicy（持久化）；后端有文档则覆盖默认，否则保留前端默认（mock 降级）。
async function loadPolicy() {
  try {
    const r = await fetch(`/ctl/api/coll?kind=${KIND}`);
    if (!r.ok) return;
    const docs = await r.json();
    const d = Array.isArray(docs) ? docs.find((x: any) => (x.key ?? x.k) === KEY) ?? docs[0] : docs;
    const cfg = d?.doc ?? d;
    if (cfg && typeof cfg === 'object') {
      const base = defaults();
      doc.value = {
        ...base,
        ...cfg,
        complexity: { ...base.complexity, ...(cfg.complexity ?? {}) },
        weakList: Array.isArray(cfg.weakList) ? cfg.weakList : base.weakList
      };
    }
    live.value = true;
  } catch { live.value = false; }
}
onMounted(loadPolicy);

// 保存：整文档 POST 写入（后端自动写审计）。
async function save() {
  saving.value = true;
  try {
    const r = await fetch(`/ctl/api/coll?kind=${KIND}`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: KEY, doc: doc.value })
    });
    if (!r.ok) throw new Error('http ' + r.status);
    live.value = true;
    Message.success('口令策略已保存 · ≤60s 下发 · 已持久化');
  } catch {
    if (live.value) { Message.error('保存失败，请重试'); }
    else { Message.success('口令策略已保存（mock，重启丢失）'); }
  } finally { saving.value = false; }
}

// 恢复默认 = 删除文档（DELETE）→ 回到无策略 / 默认值。
function restoreDefault() {
  Modal.warning({
    title: '恢复默认策略',
    content: '将删除当前口令策略文档并恢复为系统默认值。已生效的口令不受影响，新设置 / 改密时按默认规则校验。是否继续？',
    okText: '恢复默认',
    cancelText: '取消',
    hideCancel: false,
    async onOk() {
      doc.value = defaults();
      if (!live.value) { Message.success('已恢复默认（mock）'); return; }
      try {
        const r = await fetch(`/ctl/api/coll?kind=${KIND}&key=${KEY}`, { method: 'DELETE' });
        if (!r.ok) throw new Error('http ' + r.status);
        Message.success('已删除策略文档并恢复默认 · 已持久化');
      } catch { Message.error('恢复失败，请重试'); }
    }
  });
}
</script>

<style scoped>
.pp-card { max-width: 880px; }

/* 分段 */
.pp-sec { padding-bottom: 8px; }
.pp-sec + .pp-sec { margin-top: 8px; padding-top: 16px; border-top: 1px solid var(--line); }
.pp-sec__title { margin-bottom: 14px; }

/* 复杂度开关组 */
.pp-cplx { width: 100%; }
.pp-cplx__row { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 28px; }
.pp-cplx__item { display: flex; align-items: center; gap: 10px; }
.pp-cplx__item span { font-size: 13px; color: var(--ink-2); }

/* 策略摘要条 */
.pp-summary { display: flex; align-items: baseline; gap: 10px; margin-top: 18px; padding: 12px 14px; background: var(--accent-soft); border-radius: var(--r-md); }
.pp-summary__lbl { font-size: 11.5px; font-weight: 700; color: var(--accent-2); white-space: nowrap; }
.pp-summary__txt { font-size: 12.5px; color: var(--ink-2); line-height: 1.5; }

/* 底部操作 */
.pp-foot { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--line); }
.pp-foot__tip { font-size: 11.5px; color: var(--ink-3); }
</style>
