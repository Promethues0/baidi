<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">升级管理</div>
        <div class="bd-page__sub">升级前校验 · 加密配置备份 · 客户端灰度发布</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '未连' }}</a-tag>
      </div>
    </div>

    <!-- 边界声明：由后端下发，前端不得自行编写或省略。
         这一章有大量源产品专有内容，不说清楚管理员会以为界面上没有的是「还没做完」。 -->
    <div v-for="(b, i) in bundle.boundaries" :key="i" class="bd-bound">
      <icon-info-circle-fill /><span>{{ b }}</span>
    </div>

    <div v-if="err" class="bd-bound bd-bound--err"><icon-close-circle-fill /><span>{{ err }}</span></div>

    <div class="bd-two">
      <!-- 版本与组件 -->
      <div class="bd-card bd-vers">
        <div class="bd-vers__h">当前版本</div>
        <div class="bd-vers__big">{{ bundle.control || '—' }}</div>
        <div class="bd-vers__sub">控制面 baidi-control</div>

        <div class="bd-sec2">网关组件</div>
        <div v-if="!gwList.length" class="bd-vers__empty">暂无网关注册</div>
        <div v-for="g in gwList" :key="g.id" class="bd-gwrow">
          <b class="bd-mono">{{ g.id }}</b>
          <span v-if="g.version" class="bd-tg" :style="tagStyle(g.version === bundle.control ? '#00B42A' : '#FF7D00')">
            {{ g.version }}
          </span>
          <!-- 不上报版本的旧网关如实标「无法校验」，绝不当成一致 -->
          <span v-else class="bd-tg bd-unknown" title="该网关版本低于 v0.4，不上报版本号——无法校验组件一致性">
            无法校验
          </span>
        </div>
      </div>

      <div style="flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 14px">
        <!-- 升级包校验 -->
        <div class="bd-card">
          <div class="bd-vers__h">升级包校验</div>
          <div class="bd-hint">
            粘贴升级包随附的 <b class="bd-mono">manifest.json</b> 原文与 <b class="bd-mono">.sig</b> 签名（base64）。
            描述原文必须**原样**粘贴——重新格式化会让签名验不过。
          </div>
          <a-textarea v-model="chk.manifest" :auto-size="{ minRows: 4, maxRows: 8 }"
            placeholder='{"product":"baidi","component":"control","version":"0.4.0","sha256":"…"}' class="bd-mono" />
          <a-input v-model="chk.sig" placeholder="签名（base64）" class="bd-mono" style="margin-top: 8px" />
          <div style="margin-top: 10px">
            <button class="bd-btn" :disabled="chk.busy || !chk.manifest.trim()"
              :style="{ opacity: chk.busy || !chk.manifest.trim() ? .5 : 1 }" @click="doCheck">校验</button>
          </div>
          <div v-if="chk.result" class="bd-chk" :class="chk.result.blocked ? 'bd-chk--bad' : 'bd-chk--ok'">
            <b>{{ chk.result.blocked ? '校验不通过 · 不可升级' : '校验通过' }}</b>
            <div v-for="(r, i) in chk.result.reasons ?? []" :key="'r' + i" class="bd-chk__l">✕ {{ r }}</div>
            <div v-for="(r, i) in chk.result.warnings ?? []" :key="'w' + i" class="bd-chk__l">⚠ {{ r }}</div>
            <div v-if="chk.result.nextHop" class="bd-chk__l">→ 请先升级到 <b>{{ chk.result.nextHop }}</b></div>
          </div>
        </div>

        <!-- 校验规则 -->
        <div class="bd-card">
          <div class="bd-vers__h">校验规则</div>
          <div class="bd-fld bd-fld--row">
            <div><label>允许降级</label><span class="bd-fld__d">默认禁止：数据库结构已被当前版本迁移，旧版读不了</span></div>
            <a-switch v-model="rules.allowDowngrade" @change="saveRules" />
          </div>
          <div class="bd-fld bd-fld--row">
            <div><label>校验组件一致性</label><span class="bd-fld__d">控制面与网关版本不一致时给出警告（不阻断）</span></div>
            <a-switch v-model="rules.requireComponentMatch" @change="saveRules" />
          </div>
          <div class="bd-sec2">强制跳跃链路</div>
          <div class="bd-hint" style="margin-bottom: 8px">
            低于「起始版本」的设备必须先升到「下一跳」，不得直升更高版本。
            白帝目前没有已知的不可直升版本对，故默认为空——留空即不限制。
          </div>
          <div v-for="(h, i) in rules.hops" :key="i" class="bd-hop">
            <a-input v-model="h.below" placeholder="低于此版本" class="bd-mono" size="small" />
            <span>→ 先升到</span>
            <a-input v-model="h.next" placeholder="下一跳版本" class="bd-mono" size="small" />
            <button type="button" class="bd-link bd-link--danger" :aria-label="`删除第 ${i + 1} 条跳跃规则`"
              @click="rules.hops.splice(i, 1); saveRules()"><icon-delete /></button>
          </div>
          <button type="button" class="bd-link" @click="rules.hops.push({ below: '', next: '' })">
            <icon-plus />添加一跳
          </button>
        </div>

        <!-- 客户端灰度 -->
        <div class="bd-card">
          <div class="bd-vers__h">客户端灰度发布</div>
          <div class="bd-hint">
            灰度判定在服务端做，终端只被告知一个版本号。同一账号的分桶稳定——
            扩大比例只会新增命中，不会把已升级的用户退回旧版。
          </div>
          <table class="bd-table" style="margin-top: 10px">
            <thead><tr><th>平台</th><th>稳定版</th><th>灰度版</th><th>比例</th><th>定向</th><th class="r">操作</th></tr></thead>
            <tbody>
              <tr v-for="p in bundle.gray" :key="p.platform">
                <td><b>{{ platformLabel(p.platform) }}</b></td>
                <td class="bd-mono">{{ p.stable || '—' }}</td>
                <td class="bd-mono">{{ p.version }}</td>
                <td>{{ p.percent }}%</td>
                <td class="bd-dim">{{ (p.accounts?.length ?? 0) + (p.groups?.length ?? 0) || '—' }}</td>
                <td class="r">
                  <button type="button" class="bd-link" @click="openGray(p)">编辑</button>
                  <button type="button" class="bd-link bd-link--danger" style="margin-left: 12px"
                    @click="removeGray(p)">撤销</button>
                </td>
              </tr>
              <tr v-if="!bundle.gray.length">
                <td colspan="6" class="bd-vers__empty">尚无灰度计划——所有终端拿各自平台的稳定版。</td>
              </tr>
            </tbody>
          </table>
          <button type="button" class="bd-link" style="margin-top: 8px" @click="openGray()"><icon-plus />新增灰度计划</button>
        </div>

        <!-- 配置备份 -->
        <div class="bd-card">
          <div class="bd-vers__h">配置备份</div>
          <div class="bd-hint">
            备份含数据库、CA 私钥、IPSec PSK、认证源凭据与审计链密钥，
            整体以口令加密（PBKDF2 + AES-256-GCM），**不提供不加密的导出**。
            口令丢失无法找回——白帝不保存它。
          </div>
          <div class="bd-bkrow">
            <a-input-password v-model="bk.pass" placeholder="备份口令（至少 12 位）" />
            <a-input v-model="bk.note" placeholder="备注（如：升级前）" />
            <button class="bd-btn" :disabled="bk.busy || bk.pass.length < 12"
              :style="{ opacity: bk.busy || bk.pass.length < 12 ? .5 : 1 }" @click="doBackup">
              <icon-download />导出备份
            </button>
          </div>
          <div class="bd-hint" style="margin-top: 8px">
            恢复由停机后的部署脚本执行（解开归档覆盖回目录再启动）：在进程运行中就地覆写
            正在使用的数据库与密钥文件，会让一半请求读到旧库、一半读到新库，且失败后没有回头路。
          </div>
        </div>
      </div>
    </div>

    <!-- 灰度计划编辑 -->
    <a-modal v-model:visible="gr.open" :width="520" :title="gr.editing ? '编辑灰度计划' : '新增灰度计划'" :footer="false">
      <div class="bd-uform">
        <div class="bd-fld"><label>平台</label>
          <a-select v-model="gr.platform" :disabled="gr.editing">
            <a-option v-for="p in PLATFORMS" :key="p.key" :value="p.key">{{ p.label }}</a-option>
          </a-select>
        </div>
        <div class="bd-fld"><label>稳定版本</label>
          <a-input v-model="gr.stable" class="bd-mono" placeholder="0.4.0（不在灰度内的终端拿这个）" />
        </div>
        <div class="bd-fld"><label>灰度版本</label>
          <a-input v-model="gr.version" class="bd-mono" placeholder="0.5.0（必须高于稳定版）" />
        </div>
        <div class="bd-fld"><label>灰度比例：{{ gr.percent }}%</label>
          <a-slider v-model="gr.percent" :min="0" :max="100" :step="5" show-ticks />
        </div>
        <div class="bd-fld"><label>定向账号（无视比例，逗号分隔）</label>
          <a-input v-model="gr.accounts" placeholder="qa.liu, dev.wang" class="bd-mono" />
        </div>
        <div class="bd-fld__foot">
          <button class="bd-btn bd-btn--ghost" @click="gr.open = false">取消</button>
          <button class="bd-btn" :disabled="gr.busy" @click="saveGray">保存</button>
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, getToken, type UpgradeBundle, type UpgradeRules, type GrayPlan, type UpgradeCheckResult } from '@/lib/api';

const PLATFORMS = [
  { key: 'macos', label: 'macOS' }, { key: 'windows', label: 'Windows' }, { key: 'linux', label: 'Linux' },
  { key: 'android', label: 'Android' }, { key: 'ios', label: 'iOS' }, { key: 'harmony', label: '鸿蒙' }
];
function platformLabel(k: string) { return PLATFORMS.find((p) => p.key === k)?.label ?? k; }
function tagStyle(color: string) { return { color, background: color + '14' }; }

const live = ref(false);
const err = ref('');
const bundle = ref<UpgradeBundle>({ control: '', gateways: {}, rules: { allowDowngrade: false, requireComponentMatch: true, hops: [] }, gray: [], boundaries: [] });
const rules = reactive<UpgradeRules>({ allowDowngrade: false, requireComponentMatch: true, hops: [] });

const gwList = computed(() => Object.entries(bundle.value.gateways ?? {})
  .map(([id, version]) => ({ id, version })).sort((a, b) => a.id.localeCompare(b.id)));

const chk = reactive({ manifest: '', sig: '', busy: false, result: null as UpgradeCheckResult | null });
const bk = reactive({ pass: '', note: '', busy: false });
const gr = reactive({ open: false, editing: false, busy: false, platform: 'macos', stable: '', version: '', percent: 10, accounts: '' });

async function load() {
  try {
    const b = await api<UpgradeBundle>('/upgrade');
    bundle.value = b;
    Object.assign(rules, b.rules, { hops: b.rules.hops ?? [] });
    live.value = true;
  } catch (e) {
    live.value = false;
    err.value = (e as Error).message || '无法读取升级配置';
  }
}

async function saveRules() {
  try {
    await api('/upgrade/rules', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...rules, hops: rules.hops.filter((h) => h.below && h.next) })
    });
    Message.success('规则已保存');
    await load();
  } catch (e) { err.value = (e as Error).message || '保存规则失败'; }
}

async function doCheck() {
  chk.busy = true; err.value = ''; chk.result = null;
  try {
    // manifest 原文必须原样送到后端验签：这里解析只为了尽早发现 JSON 语法错，
    // 送出去的仍是用户粘贴的原文（重新序列化会改变字节，签名就验不过了）。
    let parsed: unknown;
    try { parsed = JSON.parse(chk.manifest); } catch { throw new Error('描述不是合法 JSON'); }
    chk.result = await api<UpgradeCheckResult>('/upgrade/check', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ manifest: parsed, signature: chk.sig.trim() })
    });
  } catch (e) { err.value = (e as Error).message || '校验失败'; }
  finally { chk.busy = false; }
}

function openGray(p?: GrayPlan) {
  err.value = '';
  Object.assign(gr, {
    open: true, editing: !!p, busy: false,
    platform: p?.platform ?? 'macos', stable: p?.stable ?? '', version: p?.version ?? '',
    percent: p?.percent ?? 10, accounts: (p?.accounts ?? []).join(', ')
  });
}

async function saveGray() {
  gr.busy = true; err.value = '';
  try {
    await api('/upgrade/gray', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        platform: gr.platform, stable: gr.stable.trim(), version: gr.version.trim(),
        percent: gr.percent,
        accounts: gr.accounts.split(',').map((s) => s.trim()).filter(Boolean),
        groups: []
      })
    });
    gr.open = false;
    Message.success('灰度计划已保存');
    await load();
  } catch (e) { err.value = (e as Error).message || '保存灰度计划失败'; }
  finally { gr.busy = false; }
}

async function removeGray(p: GrayPlan) {
  try {
    // version 置空即撤销该平台的计划（后端语义）
    await api('/upgrade/gray', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ platform: p.platform, version: '', stable: p.stable, percent: 0, accounts: [], groups: [] })
    });
    Message.success(`已撤销 ${platformLabel(p.platform)} 的灰度计划`);
    await load();
  } catch (e) { err.value = (e as Error).message || '撤销失败'; }
}

async function doBackup() {
  bk.busy = true; err.value = '';
  try {
    // 备份是二进制附件，走原生 fetch 而不是 api()（后者只处理 JSON）。
    const res = await fetch('/api/v1/upgrade/backup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
      body: JSON.stringify({ passphrase: bk.pass, note: bk.note })
    });
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: { message?: string } } | null;
      throw new Error(body?.error?.message ?? `${res.status} ${res.statusText}`);
    }
    const blob = await res.blob();
    const cd = res.headers.get('Content-Disposition') ?? '';
    const name = /filename=([^;]+)/.exec(cd)?.[1]?.trim() || 'baidi-backup.bak';
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
    Message.success(`备份已导出（${(blob.size / 1024).toFixed(0)} KB）`);
    bk.pass = '';
  } catch (e) { err.value = (e as Error).message || '导出备份失败'; }
  finally { bk.busy = false; }
}

onMounted(load);
</script>

<style scoped>
.bd-bound {
  display: flex; align-items: flex-start; gap: 8px; margin-bottom: 10px; padding: 10px 12px;
  border-radius: 8px; font-size: 12.5px; line-height: 1.7;
  color: var(--bd-t2); background: var(--bd-fill-2); border: 1px solid var(--bd-line);
}
.bd-bound--err { color: var(--bd-danger); background: var(--bd-tag-red-bg); border-color: #FFC2C2; }
.bd-bound > :first-child { flex: none; margin-top: 3px; font-size: 14px; color: var(--bd-t3); }

.bd-vers { width: 300px; flex: none; padding: 16px; align-self: flex-start; }
.bd-vers__h { font-size: 13px; font-weight: 600; margin-bottom: 10px; }
.bd-vers__big { font-size: 30px; font-weight: 700; color: var(--bd-primary); font-family: ui-monospace, monospace; }
.bd-vers__sub { font-size: 12px; color: var(--bd-t3); margin-top: 2px; }
.bd-vers__empty { color: var(--bd-t3); font-size: 12.5px; padding: 14px 0; text-align: center; }
.bd-gwrow { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 7px 0; border-top: 1px solid var(--bd-line); font-size: 12.5px; }
.bd-unknown { color: var(--bd-t3); background: var(--bd-fill-2); cursor: help; }

.bd-sec2 { font-size: 12px; font-weight: 600; color: var(--bd-t2); margin: 16px 0 8px; padding-top: 12px; border-top: 1px solid var(--bd-line); }
.bd-hint { font-size: 12px; color: var(--bd-t3); line-height: 1.7; margin-bottom: 8px; }
.bd-dim { color: var(--bd-t3); }

.bd-chk { margin-top: 12px; padding: 10px 12px; border-radius: 8px; font-size: 12.5px; line-height: 1.8; }
.bd-chk--ok { color: #1D7A38; background: #E8FFEA; border: 1px solid #AFF0B5; }
.bd-chk--bad { color: var(--bd-danger); background: var(--bd-tag-red-bg); border: 1px solid #FFC2C2; }
.bd-chk__l { margin-top: 2px; }

.bd-hop { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; font-size: 12px; color: var(--bd-t3); }
.bd-hop :deep(.arco-input-wrapper) { width: 130px; }
.bd-bkrow { display: flex; align-items: center; gap: 10px; }
.bd-bkrow :deep(.arco-input-wrapper) { flex: 1; }

.bd-fld { margin-bottom: 16px; }
.bd-fld > label { display: block; font-size: 13px; font-weight: 500; color: var(--bd-t1); margin-bottom: 7px; }
.bd-fld :deep(.arco-input-wrapper), .bd-fld :deep(.arco-select-view) { width: 100%; }
.bd-fld--row { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.bd-fld--row label { display: block; margin-bottom: 2px; }
.bd-fld__d { display: block; margin-top: 4px; font-size: 12px; color: var(--bd-t3); line-height: 1.6; }
.bd-fld--row .bd-fld__d { margin-top: 0; }
.bd-fld__foot { display: flex; justify-content: flex-end; gap: 10px; }
</style>
