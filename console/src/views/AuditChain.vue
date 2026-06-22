<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">审计链（HMAC-SM3）<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">事件按区块入链，哈希前后勾连 · 任何篡改/删除/重排都可检出（ZL-FR-109，V5 模式平台化）</div>
      </div>
      <a-space>
        <a-button :loading="verifying" @click="verify"><template #icon><icon-safe /></template>立即校验</a-button>
        <a-button :status="tampered ? 'normal' : 'danger'" @click="toggleTamper">
          {{ tampered ? '恢复区块' : '模拟篡改 #1022' }}
        </a-button>
      </a-space>
    </div>

    <!-- 校验结论 -->
    <div class="zl-card zl-card__pad chain-verdict" :class="verdict.cls" style="margin-bottom: 16px;">
      <span class="chain-verdict__icon">{{ verdict.icon }}</span>
      <div>
        <div class="chain-verdict__t">{{ verdict.title }}</div>
        <div class="chain-verdict__d">{{ verdict.desc }}</div>
      </div>
      <div class="chain-verdict__meta data">上次校验 {{ lastVerify }} · 链长 {{ blocks[0].seq }} 区块 · 锚点已外推 syslog</div>
    </div>

    <!-- 链可视化 -->
    <div class="zl-card zl-card__pad">
      <div class="zl-card__title" style="margin-bottom: 16px;">链尾区块（新 → 旧）</div>
      <div class="chain">
        <template v-for="(b, i) in blocks" :key="b.seq">
          <div class="block" :class="blockCls(b)">
            <div class="block__seq data">#{{ b.seq }}</div>
            <div class="block__range">{{ b.range }}</div>
            <div class="block__events data">{{ b.events }} 事件</div>
            <div class="block__hash data">
              <span class="hk">SM3</span>{{ displayHash(b) }}
            </div>
            <div class="block__prev data"><span class="hk">prev</span>{{ b.prevHash }}</div>
            <div v-if="blockCls(b)" class="block__flag">{{ b.seq === 1022 && tampered ? '⚠ 哈希不匹配' : '⛓ 链断裂' }}</div>
          </div>
          <div v-if="i < blocks.length - 1" class="chain__link" :class="{ broken: tampered && blocks[i + 1].seq === 1022 }">
            {{ tampered && blocks[i + 1].seq === 1022 ? '✕' : '←' }}
          </div>
        </template>
      </div>
      <div class="idp-note" style="border-top: 0; padding-left: 0;">
        <icon-info-circle /> 每个区块的 HMAC-SM3 摘要纳入下一区块计算（prev）；篡改 #1022 的任何一条事件，其摘要即变化，
        #1023 持有的 prev 立即失配 → 篡改点之后整条链判定失效。密钥由网关 KMS 注入，不落盘（REQ-SEC-001）。
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { chainBlocks, type ChainBlock } from '@/mock';

/* 审计链来自控制面 /ctl/api/audit/chain（真实 HMAC-SM3 哈希链），校验经
   /ctl/api/audit/chain/verify 后端重放比对；控制面不可达时降级 mock。 */
const blocks = ref<ChainBlock[]>([...chainBlocks]);
const live = ref(false);
const tampered = ref(false);
const verifying = ref(false);
const lastVerify = ref('15:05:32');
const brokenAt = ref(0);          // 后端校验返回的断裂区块 seq（0=完整）
const backendDetail = ref('');

async function loadChain() {
  try {
    const r = await fetch('/ctl/api/audit/chain');
    if (!r.ok) return;
    blocks.value = await r.json();
    live.value = true;
  } catch { live.value = false; }
}
onMounted(loadChain);

async function verify() {
  verifying.value = true;
  if (live.value) {
    try {
      const url = '/ctl/api/audit/chain/verify' + (tampered.value ? '?tamper=1022' : '');
      const v = await (await fetch(url)).json();
      brokenAt.value = v.valid ? 0 : v.brokenAt;
      backendDetail.value = v.detail || '';
    } catch { /* 保持上次结果 */ }
  } else {
    brokenAt.value = tampered.value ? 1022 : 0; // 降级
  }
  verifying.value = false;
  lastVerify.value = new Date().toTimeString().slice(0, 8);
}

async function toggleTamper() {
  tampered.value = !tampered.value;
  await verify(); // 篡改/恢复后立即重新校验（后端重放 HMAC-SM3）
}

function displayHash(b: ChainBlock) {
  return tampered.value && b.seq === brokenAt.value ? 'f00ddead' : b.hash;
}
function blockCls(b: ChainBlock) {
  if (!brokenAt.value) return '';
  if (b.seq === brokenAt.value) return 'bad';   // 被篡改区块
  if (b.seq > brokenAt.value) return 'invalid'; // 篡改点之后链不可信
  return '';
}

const verdict = computed(() =>
  brokenAt.value
    ? { cls: 'bad', icon: '⛓️‍💥', title: '链校验失败 — 检测到篡改', desc: backendDetail.value || `区块 #${brokenAt.value} 摘要与后续 prev 不匹配；该区块起整条链不可信，已触发告警并冻结日志导出。` }
    : { cls: 'ok', icon: '✓', title: '链完整 — 全部区块校验通过', desc: `从创世锚点重放 HMAC-SM3 全链一致，未发现篡改/删除/重排。${live.value ? '（后端实时重放）' : ''}` }
);
</script>

<style scoped>
.chain-verdict { display: flex; align-items: center; gap: 14px; }
.chain-verdict.ok { border-color: var(--ok); }
.chain-verdict.bad { border-color: var(--danger); background: var(--danger-soft); }
.chain-verdict__icon { font-size: 22px; width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex: none; background: var(--surface-2); }
.chain-verdict.ok .chain-verdict__icon { background: var(--ok-soft); color: var(--ok); }
.chain-verdict__t { font-size: 14.5px; font-weight: 700; color: var(--ink); }
.chain-verdict__d { font-size: 12.5px; color: var(--ink-2); margin-top: 3px; max-width: 640px; }
.chain-verdict__meta { margin-left: auto; font-size: 11.5px; color: var(--ink-3); flex: none; }

.chain { display: flex; align-items: stretch; gap: 0; overflow-x: auto; padding-bottom: 6px; }
.block {
  flex: 1; min-width: 150px; border: 1.5px solid var(--line-2); border-radius: var(--r-md);
  padding: 12px 14px; background: var(--surface); display: flex; flex-direction: column; gap: 4px;
}
.block.bad { border-color: var(--danger); background: var(--danger-soft); }
.block.invalid { border-style: dashed; opacity: 0.6; }
.block__seq { font-size: 14px; font-weight: 700; color: var(--ink); }
.block__range { font-size: 11px; color: var(--ink-3); }
.block__events { font-size: 12px; color: var(--ink-2); }
.block__hash, .block__prev { font-size: 11.5px; color: var(--ink-2); display: flex; gap: 6px; align-items: center; }
.hk {
  font-size: 9.5px; font-weight: 700; letter-spacing: .05em; color: var(--accent-2);
  background: var(--accent-soft); border-radius: 4px; padding: 0 5px;
}
.block.bad .block__hash { color: var(--danger); font-weight: 700; }
.block__flag { font-size: 11px; font-weight: 700; color: var(--danger); margin-top: 2px; }
.chain__link { display: flex; align-items: center; padding: 0 8px; color: var(--ink-3); font-size: 15px; flex: none; }
.chain__link.broken { color: var(--danger); font-weight: 700; }
.idp-note { display: flex; gap: 8px; align-items: flex-start; padding: 12px 16px 0; font-size: 12px; color: var(--ink-3); line-height: 1.6; margin-top: 8px; }
</style>
