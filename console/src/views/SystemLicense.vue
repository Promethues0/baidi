<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">License 与容量<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">授权版本 / 容量上限 / 功能开关 · 容量标定 8C16G ≥1000 SSL · ≥2000 Mesh · ≥50 IPSEC（charter 容量起点）</div>
      </div>
      <a-button size="small" @click="uploadLic"><template #icon><icon-upload /></template>更新授权</a-button>
    </div>

    <div class="zl-grid" style="grid-template-columns: 380px 1fr;">
      <!-- 授权信息 -->
      <div class="zl-card zl-card__pad">
        <div class="lic-edition">
          <div class="lic-edition__badge" :class="expired ? 'bad' : 'ok'">{{ lic.edition }}</div>
          <div class="lic-edition__exp" :class="{warn: daysLeft<90 && !expired, bad: expired}">
            {{ expired ? '已过期' : `剩余 ${daysLeft} 天` }}
          </div>
        </div>
        <div class="cert-detail">
          <div class="cd-row"><span>授权方</span><b>{{ lic.licensee }}</b></div>
          <div class="cd-row"><span>授权编号</span><b class="data">{{ lic.licenseId }}</b></div>
          <div class="cd-row"><span>签发日期</span><b class="data">{{ lic.issued }}</b></div>
          <div class="cd-row"><span>到期日期</span><b class="data">{{ lic.expiry }}</b></div>
          <div class="cd-row"><span>状态</span>
            <span class="zl-badge" :class="expired ? 'zl-badge--danger' : daysLeft<90 ? 'zl-badge--warn' : 'zl-badge--ok'">
              {{ expired ? '已过期' : daysLeft<90 ? '即将到期' : '正常' }}
            </span>
          </div>
        </div>
        <div v-if="daysLeft<90 && !expired" class="cd-tip warn">⚠ 授权将在 90 天内到期，请联系厂商续期，过期后将限制新建会话。</div>
      </div>

      <!-- 容量用量 -->
      <div style="display:flex;flex-direction:column;gap:16px;min-width:0">
        <div class="zl-card zl-card__pad">
          <div class="zl-card__title" style="margin-bottom:14px">容量用量（当前 / 授权上限）</div>
          <div class="cap" v-for="c in caps" :key="c.k">
            <div class="cap-head">
              <span class="cap-name">{{ c.name }}</span>
              <span class="cap-num data"><b>{{ c.use }}</b> / {{ c.cap }} <i>({{ pct(c) }}%)</i></span>
            </div>
            <div class="cap-bar"><div class="cap-fill" :class="tone(c)" :style="{width: Math.min(100,pct(c))+'%'}" /></div>
          </div>
        </div>

        <div class="zl-card zl-card__pad">
          <div class="zl-card__title" style="margin-bottom:10px">功能授权</div>
          <div class="feat-grid">
            <div class="feat" v-for="f in features" :key="f.k" :class="{off: !lic.features[f.k]}">
              <span class="feat-ic">{{ lic.features[f.k] ? '✓' : '—' }}</span>
              <div><div class="feat-name">{{ f.name }}</div><div class="feat-desc">{{ f.desc }}</div></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message } from '@arco-design/web-vue';

const live = ref(false);
const lic = reactive<any>({
  edition: 'Standard 标准版', licensee: 'ACME 集团', licenseId: 'ZL-STD-2026-0042',
  issued: '2026-01-15', expiry: '2027-01-15',
  capSsl: 1000, capMesh: 2000, capIpsec: 50, useSsl: 312, useMesh: 486, useIpsec: 7,
  features: { gm: true, pqc: true, mesh: true, ipsec: true, vpp: false, ha: true }
});

const features = [
  { k: 'gm', name: '国密套件', desc: 'TLCP · SM2/SM3/SM4' },
  { k: 'pqc', name: '抗量子 PQC', desc: '混合密钥交换' },
  { k: 'mesh', name: 'Mesh 组网', desc: 'P2P + DERP 中继' },
  { k: 'ipsec', name: 'IPSEC 站点', desc: 'strongSwan + 国密' },
  { k: 'vpp', name: 'VPP 高性能数据面', desc: '需性能档授权' },
  { k: 'ha', name: '高可用集群', desc: '主备 / 双活' }
];

const caps = computed(() => [
  { k: 'ssl', name: 'SSL / SDP 隧道', use: lic.useSsl, cap: lic.capSsl },
  { k: 'mesh', name: 'Mesh 设备', use: lic.useMesh, cap: lic.capMesh },
  { k: 'ipsec', name: 'IPSEC 站点隧道', use: lic.useIpsec, cap: lic.capIpsec }
]);
const pct = (c: any) => Math.round((c.use / c.cap) * 100);
const tone = (c: any) => { const p = pct(c); return p >= 90 ? 'bad' : p >= 70 ? 'warn' : 'ok'; };

// 演示：以 2026-06-13 为当前日期推算剩余天数
const daysLeft = computed(() => {
  const exp = new Date(lic.expiry).getTime();
  const now = new Date('2026-06-13').getTime();
  return Math.round((exp - now) / 86400000);
});
const expired = computed(() => daysLeft.value < 0);

async function load() {
  try {
    const r = await fetch('/ctl/api/coll?kind=syscfg');
    if (!r.ok) throw new Error();
    const docs = await r.json();
    const d = docs.find((x: any) => x.key === 'license');
    if (d) Object.assign(lic, d);
    live.value = true;
  } catch { live.value = false; }
}
onMounted(load);

const uploadLic = () => Message.info('更新授权：上传 .lic 授权文件（厂商离线签发，SM2 签名校验）·（演示）');
</script>

<style scoped>
.lic-edition { display: flex; align-items: center; justify-content: space-between; padding-bottom: 14px; margin-bottom: 12px; border-bottom: 1px solid var(--line); }
.lic-edition__badge { font-size: 15px; font-weight: 700; padding: 6px 14px; border-radius: var(--r-md); }
.lic-edition__badge.ok { background: var(--accent-soft); color: var(--accent-2); }
.lic-edition__badge.bad { background: rgba(220,38,38,.12); color: var(--danger); }
.lic-edition__exp { font-size: 13px; font-weight: 600; color: var(--ok); }
.lic-edition__exp.warn { color: var(--warn); } .lic-edition__exp.bad { color: var(--danger); }

.cert-detail { display: flex; flex-direction: column; }
.cd-row { display: flex; justify-content: space-between; gap: 12px; padding: 7px 0; border-bottom: 1px solid var(--line); font-size: 12.5px; }
.cd-row:last-child { border-bottom: 0; }
.cd-row span { color: var(--ink-3); flex: none; }
.cd-row b { color: var(--ink); font-weight: 600; text-align: right; }
.cd-tip { margin-top: 12px; font-size: 12px; padding: 9px 11px; border-radius: var(--r-md); line-height: 1.5; }
.cd-tip.warn { background: rgba(217,119,6,.1); color: #b45309; }

.cap { margin-bottom: 16px; }
.cap:last-child { margin-bottom: 0; }
.cap-head { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 6px; }
.cap-name { font-size: 13px; font-weight: 600; color: var(--ink); }
.cap-num { font-size: 12px; color: var(--ink-3); } .cap-num b { color: var(--ink); font-size: 14px; } .cap-num i { font-style: normal; }
.cap-bar { height: 8px; border-radius: 4px; background: var(--surface-2); overflow: hidden; }
.cap-fill { height: 100%; border-radius: 4px; transition: width .4s; }
.cap-fill.ok { background: var(--ok); } .cap-fill.warn { background: var(--warn); } .cap-fill.bad { background: var(--danger); }

.feat-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
.feat { display: flex; align-items: flex-start; gap: 9px; padding: 10px 12px; border: 1px solid var(--line); border-radius: var(--r-md); }
.feat.off { opacity: .5; }
.feat-ic { width: 20px; height: 20px; border-radius: 50%; display: grid; place-items: center; background: var(--accent-soft); color: var(--accent-2); font-size: 12px; font-weight: 700; flex: none; }
.feat.off .feat-ic { background: var(--surface-2); color: var(--ink-3); }
.feat-name { font-size: 12.5px; font-weight: 600; color: var(--ink); }
.feat-desc { font-size: 10.5px; color: var(--ink-3); margin-top: 2px; }
</style>
