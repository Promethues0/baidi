<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">告警通知<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">审计事件命中规则 → 去重 → 投递 · webhook / 钉钉真发，邮件 / 短信 / 企业微信待外部网关</div>
      </div>
    </div>

    <!-- 通知渠道 -->
    <div class="zl-card" style="margin-bottom:18px">
      <div class="zl-card__pad nf-head">
        <div>
          <div class="zl-card__title">通知渠道</div>
          <div class="nf-sub">告警最终投递的出口。webhook / 钉钉为 HTTP POST 真发可测；邮件 / 短信 / 企业微信仅落配置占位，待外部网关对接。</div>
        </div>
        <a-button type="primary" size="small" @click="openChannel()"><template #icon><icon-plus /></template>新建渠道</a-button>
      </div>
      <a-table :data="channels" :pagination="false" :bordered="false" row-key="key">
        <template #columns>
          <a-table-column title="渠道名称" :width="200">
            <template #cell="{ record }">
              <span style="font-weight:600;color:var(--ink)">{{ record.name }}</span>
              <div class="data" style="font-size:11px;color:var(--ink-3);margin-top:2px">{{ record.key }}</div>
            </template>
          </a-table-column>
          <a-table-column title="类型" :width="110" align="center">
            <template #cell="{ record }">
              <span class="zl-badge" :class="chTypeClass(record.type)">{{ chTypeLabel(record.type) }}</span>
            </template>
          </a-table-column>
          <a-table-column title="投递地址">
            <template #cell="{ record }">
              <span v-if="record.url" class="data" style="font-size:12px;color:var(--ink-2);word-break:break-all">{{ record.url }}</span>
              <span v-else class="nf-hint">{{ realSend(record.type) ? '—' : '待外部网关 · 无需地址' }}</span>
            </template>
          </a-table-column>
          <a-table-column title="启用" align="center" :width="80">
            <template #cell="{ record }">
              <a-switch v-model="record.enabled" size="small" @change="toggleChannel(record)" />
            </template>
          </a-table-column>
          <a-table-column title="操作" align="center" :width="190">
            <template #cell="{ record }">
              <a-space>
                <a-button size="mini" @click="openChannel(record)">编辑</a-button>
                <a-button size="mini" status="success" :loading="testingKey===record.key" @click="testChannel(record)">测试</a-button>
                <a-button size="mini" type="text" status="danger" @click="delChannel(record)">删除</a-button>
              </a-space>
            </template>
          </a-table-column>
        </template>
        <template #empty>
          <div class="nf-empty">
            <div class="nf-empty__big">未配置通知渠道 · 告警仅落审计不外发（旧行为）</div>
            <div class="nf-empty__sub">没有任何渠道时，命中规则的事件只进审计链，不向外投递。新建 webhook / 钉钉渠道后可点「测试」验证连通性。</div>
          </div>
        </template>
      </a-table>
    </div>

    <!-- 告警规则 -->
    <div class="zl-card">
      <div class="zl-card__pad nf-head">
        <div>
          <div class="zl-card__title">告警规则</div>
          <div class="nf-sub">审计事件按「匹配类别 + 匹配判定」命中规则，经去重窗口抑制重复后，投递到选中的通知渠道。类别 / 判定留空 = 任意匹配。</div>
        </div>
        <a-button type="primary" size="small" @click="openRule()"><template #icon><icon-plus /></template>新建规则</a-button>
      </div>
      <a-table :data="rules" :pagination="false" :bordered="false" row-key="key">
        <template #columns>
          <a-table-column title="规则名称" :width="180">
            <template #cell="{ record }">
              <span style="font-weight:600;color:var(--ink)">{{ record.name }}</span>
              <div class="data" style="font-size:11px;color:var(--ink-3);margin-top:2px">{{ record.key }}</div>
            </template>
          </a-table-column>
          <a-table-column title="匹配类别" :width="110" align="center">
            <template #cell="{ record }">
              <span v-if="record.category" class="zl-badge" :class="catClass(record.category)" style="font-size:10.5px">{{ record.category }}</span>
              <span v-else class="nf-hint">任意</span>
            </template>
          </a-table-column>
          <a-table-column title="匹配判定" :width="180">
            <template #cell="{ record }">
              <a-space v-if="record.decisions.length" wrap size="mini">
                <a-tag v-for="d in record.decisions" :key="d" size="small" :color="decColor(d)">{{ decLabel(d) }}</a-tag>
              </a-space>
              <span v-else class="nf-hint">任意</span>
            </template>
          </a-table-column>
          <a-table-column title="投递渠道">
            <template #cell="{ record }">
              <a-space v-if="record.channels.length" wrap size="mini">
                <a-tag v-for="c in record.channels" :key="c" size="small" :color="channelExists(c) ? undefined : 'red'">{{ channelName(c) }}</a-tag>
              </a-space>
              <span v-else class="nf-hint">未选渠道 · 不投递</span>
            </template>
          </a-table-column>
          <a-table-column title="去重" align="center" :width="92">
            <template #cell="{ record }">
              <span class="data" style="font-size:12px;color:var(--ink-2)">{{ record.dedupMin > 0 ? record.dedupMin + ' 分钟' : '不去重' }}</span>
            </template>
          </a-table-column>
          <a-table-column title="启用" align="center" :width="80">
            <template #cell="{ record }">
              <a-switch v-model="record.enabled" size="small" @change="toggleRule(record)" />
            </template>
          </a-table-column>
          <a-table-column title="操作" align="center" :width="120">
            <template #cell="{ record }">
              <a-space>
                <a-button size="mini" @click="openRule(record)">编辑</a-button>
                <a-button size="mini" type="text" status="danger" @click="delRule(record)">删除</a-button>
              </a-space>
            </template>
          </a-table-column>
        </template>
        <template #empty>
          <div class="nf-empty">
            <div class="nf-empty__big">未配置告警规则 · 不触发任何外发</div>
            <div class="nf-empty__sub">没有规则时，审计事件不会命中投递。新建规则可按类别 / 判定筛选事件，并选择投递渠道与去重窗口。</div>
          </div>
        </template>
      </a-table>
    </div>

    <!-- 渠道 编辑 / 新建 -->
    <a-modal v-model:visible="chShow" :title="chEditing ? '编辑通知渠道' : '新建通知渠道'" width="540px" @ok="submitChannel" :ok-text="chEditing ? '保存' : '创建'">
      <a-form :model="chForm" layout="vertical">
        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="渠道标识（key）" required>
              <a-input v-model="chForm.key" placeholder="例如：ops-webhook" :disabled="chEditing" />
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="渠道名称" required>
              <a-input v-model="chForm.name" placeholder="例如：运维 Webhook" />
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-form-item label="渠道类型（type）">
          <a-select v-model="chForm.type">
            <a-option v-for="t in chTypeOpts" :key="t.value" :value="t.value">{{ t.label }}</a-option>
          </a-select>
        </a-form-item>

        <a-form-item :label="realSend(chForm.type) ? '投递地址（url）' : '投递地址（url，可空）'" :required="realSend(chForm.type)">
          <a-input v-model="chForm.url" :placeholder="realSend(chForm.type) ? 'https://… 的 webhook / 钉钉机器人地址' : '待外部网关，可留空'" />
          <div v-if="!realSend(chForm.type)" class="nf-modal-hint">{{ chTypeLabel(chForm.type) }} 渠道待外部网关对接，本轮不真发；地址可留空，仅落配置占位。</div>
          <div v-else class="nf-modal-hint">webhook 收结构化事件 JSON；钉钉按其 text 机器人消息格式投递。</div>
        </a-form-item>

        <a-form-item label="启用本渠道">
          <a-switch v-model="chForm.enabled" />
          <span class="nf-modal-hint" style="margin-left:10px">关闭 = 规则命中也不向此渠道投递。</span>
        </a-form-item>
      </a-form>
      <div class="nf-modal-note">提示：渠道调整 ≤60s 生效 · 写审计。webhook / 钉钉可在列表点「测试」做连通性验证。</div>
    </a-modal>

    <!-- 规则 编辑 / 新建 -->
    <a-modal v-model:visible="ruleShow" :title="ruleEditing ? '编辑告警规则' : '新建告警规则'" width="560px" @ok="submitRule" :ok-text="ruleEditing ? '保存' : '创建'">
      <a-form :model="ruleForm" layout="vertical">
        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="规则标识（key）" required>
              <a-input v-model="ruleForm.key" placeholder="例如：rule-deny" :disabled="ruleEditing" />
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="规则名称" required>
              <a-input v-model="ruleForm.name" placeholder="例如：拒绝 / 失败即告警" />
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="匹配类别（category）">
              <a-select v-model="ruleForm.category" allow-clear placeholder="留空 = 任意类别">
                <a-option v-for="c in catOpts" :key="c" :value="c">{{ c }}</a-option>
              </a-select>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="去重窗口（dedupMin）">
              <a-input-number v-model="ruleForm.dedupMin" :min="0" :style="{width:'100%'}">
                <template #suffix>分钟</template>
              </a-input-number>
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-form-item label="匹配判定（decisions）">
          <a-input-tag v-model="ruleForm.decisions" placeholder="如 deny / fail / lock / step-up，回车添加；留空 = 任意" allow-clear />
          <div class="nf-modal-hint">命中事件的判定标签；留空表示该类别下所有判定都命中。常用：deny 拒绝 / fail 失败 / lock 锁定 / step-up 二次鉴权。</div>
        </a-form-item>

        <a-form-item label="投递渠道（channels）">
          <a-select v-model="ruleForm.channels" multiple allow-clear placeholder="选择已配置的通知渠道">
            <a-option v-for="c in channels" :key="c.key" :value="c.key">{{ c.name }} · {{ chTypeLabel(c.type) }}</a-option>
          </a-select>
          <div v-if="!channels.length" class="nf-modal-hint">尚无可选渠道，请先到上方「通知渠道」新建。</div>
          <div v-else class="nf-modal-hint">命中后投递到选中的全部渠道；未选渠道 = 命中也不外发。</div>
        </a-form-item>

        <a-form-item label="启用本规则">
          <a-switch v-model="ruleForm.enabled" />
          <span class="nf-modal-hint" style="margin-left:10px">关闭 = 不参与命中匹配。</span>
        </a-form-item>
      </a-form>
      <div class="nf-modal-note">提示：规则在控制面 emitAudit 落库后即时匹配 → 去重 → 投递 · 调整 ≤60s 生效并写审计。</div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';

/* —— 类型（与后端 controlplane/notify.go 同构） —— */
// 通知渠道文档（kind=notifychannel，每条一文档）。
interface Channel {
  key: string;
  name: string;
  type: 'webhook' | 'dingtalk' | 'email' | 'sms' | 'wecom';
  url: string;        // webhook/dingtalk 真发地址；其余可空
  enabled: boolean;
}
// 告警规则文档（kind=alertrule，每条一文档）。
interface Rule {
  key: string;
  name: string;
  category: string;     // 匹配类别，空=任意
  decisions: string[];  // 匹配判定，空=任意
  channels: string[];   // 投递渠道 key
  dedupMin: number;     // 去重窗口（分钟），0=不去重
  enabled: boolean;
}

/* —— 选项与中文化 —— */
const chTypeOpts = [
  { value: 'webhook', label: 'Webhook' },
  { value: 'dingtalk', label: '钉钉' },
  { value: 'email', label: '邮件' },
  { value: 'sms', label: '短信' },
  { value: 'wecom', label: '企业微信' }
];
const catOpts = ['主动防御', '访问决策', '系统告警', '配置变更', '登录认证'];
const chTypeLabel = (t: string) => chTypeOpts.find((x) => x.value === t)?.label ?? t;
// webhook / dingtalk 为真发渠道（需地址），其余待外部网关。
const realSend = (t: string) => t === 'webhook' || t === 'dingtalk';
const chTypeClass = (t: string) =>
  t === 'webhook' ? 'zl-badge--accent' : t === 'dingtalk' ? 'zl-badge--ok' : 'zl-badge--idle';
const catClass = (c: string) =>
  ({ '访问决策': 'zl-badge--accent', '配置变更': 'zl-badge--idle', '系统告警': 'zl-badge--warn', '登录认证': 'zl-badge--ok', '主动防御': 'zl-badge--danger' } as Record<string, string>)[c] || 'zl-badge--idle';
const decLabel = (d: string) =>
  ({ deny: '拒绝', fail: '失败', lock: '锁定', 'step-up': '二次鉴权', allow: '允许', success: '成功' } as Record<string, string>)[d] || d;
const decColor = (d: string) =>
  ({ deny: 'red', fail: 'red', lock: 'orange', 'step-up': 'orange' } as Record<string, string>)[d] || 'gray';

/* —— 前端默认（mock，加载后端后覆盖；与后端 seed 同形） —— */
const channelFallback: Channel[] = [
  { key: 'ops-webhook', name: '运维 Webhook', type: 'webhook', url: 'https://hook.corp.example/zhulong', enabled: true },
  { key: 'soc-dingtalk', name: 'SOC 钉钉群机器人', type: 'dingtalk', url: 'https://oapi.dingtalk.com/robot/send?access_token=***', enabled: true },
  { key: 'admin-sms', name: '管理员短信', type: 'sms', url: '', enabled: false }
];
const ruleFallback: Rule[] = [
  { key: 'rule-deny-fail', name: '拒绝 / 失败即告警', category: '', decisions: ['deny', 'fail'], channels: ['ops-webhook', 'soc-dingtalk'], dedupMin: 5, enabled: true },
  { key: 'rule-defense', name: '主动防御处置告警', category: '主动防御', decisions: ['lock'], channels: ['soc-dingtalk'], dedupMin: 10, enabled: true },
  { key: 'rule-config', name: '配置变更留痕', category: '配置变更', decisions: [], channels: ['ops-webhook'], dedupMin: 0, enabled: false }
];

const channels = ref<Channel[]>(channelFallback.map((c) => ({ ...c })));
const rules = ref<Rule[]>(ruleFallback.map((r) => ({ ...r, decisions: [...r.decisions], channels: [...r.channels] })));

const liveCh = ref(false);
const liveRule = ref(false);
// 页头徽标：两类任一持久化即视为 live。
const live = ref(false);

/* —— 加载（各自探活；失败保留前端默认 mock 降级） —— */
async function loadChannels() {
  try {
    const r = await fetch('/ctl/api/coll?kind=notifychannel');
    if (!r.ok) return;
    const docs = await r.json();
    channels.value = (docs as any[]).map((d) => ({
      key: d.key ?? d.k,
      name: d.name ?? '',
      type: ['webhook', 'dingtalk', 'email', 'sms', 'wecom'].includes(d.type) ? d.type : 'webhook',
      url: d.url ?? '',
      enabled: typeof d.enabled === 'boolean' ? d.enabled : true
    }));
    liveCh.value = true;
  } catch { liveCh.value = false; }
}
async function loadRules() {
  try {
    const r = await fetch('/ctl/api/coll?kind=alertrule');
    if (!r.ok) return;
    const docs = await r.json();
    rules.value = (docs as any[]).map((d) => ({
      key: d.key ?? d.k,
      name: d.name ?? '',
      category: typeof d.category === 'string' ? d.category : '',
      decisions: Array.isArray(d.decisions) ? d.decisions : [],
      channels: Array.isArray(d.channels) ? d.channels : [],
      dedupMin: typeof d.dedupMin === 'number' ? d.dedupMin : 0,
      enabled: typeof d.enabled === 'boolean' ? d.enabled : true
    }));
    liveRule.value = true;
  } catch { liveRule.value = false; }
}
onMounted(async () => {
  await Promise.all([loadChannels(), loadRules()]);
  live.value = liveCh.value || liveRule.value;
});

/* —— 渠道引用辅助 —— */
const channelExists = (key: string) => channels.value.some((c) => c.key === key);
const channelName = (key: string) => channels.value.find((c) => c.key === key)?.name ?? key + '（已删）';

/* —— 持久化（POST 单条文档，后端写审计） —— */
async function persistChannel(c: Channel) {
  if (!liveCh.value) return true;
  try {
    const res = await fetch('/ctl/api/coll?kind=notifychannel', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: c.key, doc: { ...c } })
    });
    return res.ok;
  } catch { return false; }
}
async function persistRule(r: Rule) {
  if (!liveRule.value) return true;
  try {
    const res = await fetch('/ctl/api/coll?kind=alertrule', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: r.key, doc: { ...r, decisions: [...r.decisions], channels: [...r.channels] } })
    });
    return res.ok;
  } catch { return false; }
}

/* —— 行内启用开关：即时 toggle，写失败回滚 —— */
async function toggleChannel(c: Channel) {
  const ok = await persistChannel(c);
  if (!ok && liveCh.value) { c.enabled = !c.enabled; return Message.error('操作失败，已回滚'); }
  Message.info(`渠道「${c.name}」已${c.enabled ? '启用' : '停用'}${liveCh.value ? ' · 已持久化' : ''}`);
}
async function toggleRule(r: Rule) {
  const ok = await persistRule(r);
  if (!ok && liveRule.value) { r.enabled = !r.enabled; return Message.error('操作失败，已回滚'); }
  Message.info(`规则「${r.name}」已${r.enabled ? '启用' : '停用'}${liveRule.value ? ' · 已持久化' : ''}`);
}

/* —— 渠道测试：POST /ctl/api/notify/test?key=K —— */
const testingKey = ref('');
async function testChannel(c: Channel) {
  if (!liveCh.value) {
    if (realSend(c.type)) Message.success(`已向「${c.name}」投递测试通知（mock 演示，未真发）`);
    else Message.info(`${chTypeLabel(c.type)} 渠道待外部网关对接，未真发（mock 演示）`);
    return;
  }
  testingKey.value = c.key;
  try {
    const res = await fetch(`/ctl/api/notify/test?key=${encodeURIComponent(c.key)}`, { method: 'POST' });
    const data = await res.json().catch(() => ({}));
    if (res.ok && data.ok) Message.success(`「${c.name}」投递成功`);
    else if (data.pending) Message.info(data.msg || `${chTypeLabel(c.type)} 渠道待外部网关`);
    else Message.error(data.error || `「${c.name}」投递失败`);
  } catch {
    Message.error('控制面不可达，测试失败');
  } finally {
    testingKey.value = '';
  }
}

/* —— 渠道 新建 / 编辑 —— */
const chShow = ref(false);
const chEditing = ref(false);
const chForm = reactive<Channel>({ key: '', name: '', type: 'webhook', url: '', enabled: true });
function openChannel(r?: Channel) {
  chEditing.value = !!r;
  if (r) Object.assign(chForm, JSON.parse(JSON.stringify(r)));
  else Object.assign(chForm, { key: '', name: '', type: 'webhook', url: '', enabled: true });
  chShow.value = true;
}
async function submitChannel() {
  if (!chForm.key) return Message.warning('请填写渠道标识（key）');
  if (!chForm.name) return Message.warning('请填写渠道名称');
  if (realSend(chForm.type) && !chForm.url.trim()) return Message.warning(`${chTypeLabel(chForm.type)} 渠道需填写投递地址（url）`);
  if (!chEditing.value && channels.value.some((x) => x.key === chForm.key)) return Message.warning(`渠道标识「${chForm.key}」已存在`);
  const doc: Channel = { ...chForm, url: chForm.url.trim() };
  if (chEditing.value) {
    if (!(await persistChannel(doc))) return Message.error('保存失败');
    const i = channels.value.findIndex((x) => x.key === doc.key);
    if (i >= 0) channels.value[i] = doc;
    Message.success(`渠道「${doc.name}」已更新${liveCh.value ? ' · 已持久化' : '（mock）'}`);
  } else {
    if (!(await persistChannel(doc))) return Message.error('创建失败');
    channels.value.push(doc);
    Message.success(`渠道「${doc.name}」已创建${liveCh.value ? ' · 已持久化' : '（mock）'}`);
  }
  chShow.value = false;
}

/* —— 规则 新建 / 编辑 —— */
const ruleShow = ref(false);
const ruleEditing = ref(false);
const ruleForm = reactive<Rule>({ key: '', name: '', category: '', decisions: [], channels: [], dedupMin: 0, enabled: true });
function openRule(r?: Rule) {
  ruleEditing.value = !!r;
  if (r) Object.assign(ruleForm, JSON.parse(JSON.stringify(r)));
  else Object.assign(ruleForm, { key: '', name: '', category: '', decisions: [], channels: [], dedupMin: 0, enabled: true });
  ruleShow.value = true;
}
async function submitRule() {
  if (!ruleForm.key) return Message.warning('请填写规则标识（key）');
  if (!ruleForm.name) return Message.warning('请填写规则名称');
  if (!ruleEditing.value && rules.value.some((x) => x.key === ruleForm.key)) return Message.warning(`规则标识「${ruleForm.key}」已存在`);
  const doc: Rule = {
    key: ruleForm.key, name: ruleForm.name, category: ruleForm.category || '',
    decisions: [...ruleForm.decisions], channels: [...ruleForm.channels],
    dedupMin: ruleForm.dedupMin || 0, enabled: ruleForm.enabled
  };
  if (ruleEditing.value) {
    if (!(await persistRule(doc))) return Message.error('保存失败');
    const i = rules.value.findIndex((x) => x.key === doc.key);
    if (i >= 0) rules.value[i] = doc;
    Message.success(`规则「${doc.name}」已更新${liveRule.value ? ' · 已持久化' : '（mock）'}`);
  } else {
    if (!(await persistRule(doc))) return Message.error('创建失败');
    rules.value.push(doc);
    Message.success(`规则「${doc.name}」已创建${liveRule.value ? ' · 已持久化' : '（mock）'}`);
  }
  ruleShow.value = false;
}

/* —— 删除（二次确认 + DELETE） —— */
function delChannel(c: Channel) {
  const refs = rules.value.filter((r) => r.channels.includes(c.key)).map((r) => r.name);
  Modal.warning({
    title: `删除通知渠道「${c.name}」？`, hideCancel: false, okText: '确认删除', cancelText: '取消',
    content: refs.length
      ? `删除后将不再向此渠道投递。当前有 ${refs.length} 条规则仍引用它（${refs.join('、')}），这些规则的该渠道投递会失效。此操作进入审计链。`
      : '删除后该渠道不再可用于任何规则投递。此操作进入审计链。',
    onOk: async () => {
      if (liveCh.value) {
        try {
          const res = await fetch(`/ctl/api/coll?kind=notifychannel&key=${encodeURIComponent(c.key)}`, { method: 'DELETE' });
          if (!res.ok) return Message.error('删除失败');
        } catch { return Message.error('控制面不可达'); }
      }
      channels.value = channels.value.filter((x) => x.key !== c.key);
      Message.success(`渠道「${c.name}」已删除${liveCh.value ? ' · 已持久化' : ''}`);
    }
  });
}
function delRule(r: Rule) {
  Modal.warning({
    title: `删除告警规则「${r.name}」？`, hideCancel: false, okText: '确认删除', cancelText: '取消',
    content: '删除后命中该规则的事件不再触发投递（仍正常进审计链）。此操作进入审计链。',
    onOk: async () => {
      if (liveRule.value) {
        try {
          const res = await fetch(`/ctl/api/coll?kind=alertrule&key=${encodeURIComponent(r.key)}`, { method: 'DELETE' });
          if (!res.ok) return Message.error('删除失败');
        } catch { return Message.error('控制面不可达'); }
      }
      rules.value = rules.value.filter((x) => x.key !== r.key);
      Message.success(`规则「${r.name}」已删除${liveRule.value ? ' · 已持久化' : ''}`);
    }
  });
}
</script>

<style scoped>
:deep(.arco-table-tr) { cursor: default; }

.nf-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding-bottom: 14px; border-bottom: 1px solid var(--line); }
.nf-sub { font-size: 11.5px; color: var(--ink-3); margin-top: 4px; line-height: 1.5; max-width: 720px; }
.nf-hint { font-size: 11.5px; color: var(--ink-3); }

/* 空态 */
.nf-empty { padding: 30px 16px; text-align: center; }
.nf-empty__big { font-size: 14px; font-weight: 650; color: var(--ink-2); }
.nf-empty__sub { font-size: 12px; color: var(--ink-3); margin-top: 8px; line-height: 1.6; max-width: 560px; margin-left: auto; margin-right: auto; }

/* modal 文案 */
.nf-modal-hint { font-size: 11px; color: var(--ink-3); margin-top: 6px; line-height: 1.5; }
.nf-modal-note { font-size: 11.5px; color: var(--ink-3); line-height: 1.6; margin-top: 4px; }
</style>
