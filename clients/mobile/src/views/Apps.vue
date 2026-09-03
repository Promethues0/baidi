<template>
  <div class="m-page">
    <div class="m-page__title">应用门户</div>
    <!-- 不写「高敏类需先申请」：要不要申请只看**有没有授权**，与敏感度无关
         （已授权的高敏资源直接可访问，未授权的普通资源同样进不去）。 -->
    <div class="m-page__sub">已发布的企业应用 · 未获授权的可提交访问申请</div>

    <!-- 三种「进不去」在这里是两种成因，措辞必须分开：没开隧道要用户去开，
         开了但门没敲开则开一百次也没用——那条要说清是**敲门失败**并给出原文。 -->
    <div v-if="session.notReady" class="ap__warn ap__warn--bad">
      <icon-exclamation-circle-fill /> 隧道已下发但未就绪（{{ session.notReady }}）：隧道类应用暂时访问不到，重开隧道无用
    </div>
    <div v-else-if="!session.connected" class="ap__warn"><icon-info-circle /> 未接入企业内网，隧道类应用需先在「接入」开启</div>
    <!-- 门已敲开、但隧道拨号在失败：**不拦**（可能只是某一个后端不可达），但必须说出来——
         否则用户点开应用只会看到一个转圈或超时，而真正的原因（指纹不匹配 / 网关没带 -pf /
         gm 开关不一致）在健康行里躺着没人读。与上面两条互斥：那两条是"进不去"，这条是"进得去但可能拉不通"。 -->
    <div v-else-if="session.tunnelNote" class="ap__warn ap__warn--bad">
      <icon-exclamation-circle-fill /> 已接入，但隧道拨号在失败（{{ session.tunnelNote }}）：应用可能打不开，重试即会再拨一次
    </div>

    <div class="ap__grid">
      <button v-for="a in apps" :key="a.id" class="ap__tile" :class="{ locked: !a.accessible }" @click="open(a)">
        <span class="ap__ic" :style="{ background: iconBg(a.mode) }"><component :is="modeIcon(a.mode)" /></span>
        <div class="ap__name">{{ a.name }}</div>
        <div class="ap__addr m-mono">{{ a.addr }}</div>
        <!-- ★徽标按**服务端的授权结论**画，不按 sensitivity 自己推。
             按 sensitivity 推的老写法有两个方向都错：已授权的高敏应用照样挂着「需申请」
             （用户会去为自己已有的权限提审批单），而未授权的普通应用一个提示都没有、
             点下去只会拿到 403。三种"不可访问"的下一步动作也不同，必须分开说。 -->
        <span v-if="a.degraded" class="ap__tag ap__tag--deg">终端降级 · 暂停</span>
        <span v-else-if="a.unavailable" class="ap__tag ap__tag--deg">配置缺口 · 不可用</span>
        <span v-else-if="!a.accessible" class="ap__tag">
          {{ a.sensitivity === 'high' ? '高敏 · 需申请' : '未授权 · 可申请' }}
        </span>
      </button>
    </div>
    <div v-if="!apps.length && loaded" class="ap__empty">暂无可访问应用</div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { IconCompass, IconCodeSquare, IconPublic } from '@arco-design/web-vue/es/icon';
import { api, type PortalTile, type PortalAppsResp } from '@/lib/api';
import { session } from '@/lib/store';

const apps = ref<PortalTile[]>([]);
const loaded = ref(false);

function modeIcon(m: string) { return m === 'tunnel' ? IconCodeSquare : m === 'global' ? IconPublic : IconCompass; }
function iconBg(m: string) { return m === 'tunnel' ? '#722ED1' : m === 'global' ? '#00B42A' : '#165DFF'; }

function open(a: PortalTile) {
  // 提示语必须点名真实原因：三者的下一步动作分别是「修终端」「找管理员」「去门户提申请」，
  // 统一说成「高敏需审批」会把前两种人支去做一件必然无效的事。
  if (a.degraded) { Message.warning(`「${a.name}」因终端环境不合规已暂停访问，请先修复终端（此状态下申请审批无效）`); return; }
  if (a.unavailable) { Message.warning(`「${a.name}」无法访问，请联系管理员：${a.unavailableReason || '配置缺口'}`); return; }
  if (!a.accessible) { Message.warning(`「${a.name}」你当前未获授权，请到浏览器门户提交访问申请`); return; }
  // 闸仍是 fail-closed（门没敲开确实过不去），但「进不去」的第三种成因要单独说：
  // 隧道开着 ≠ 门敲开了。笼统地说「请先开启隧道」会让用户对着一条已经开着的隧道反复开关。
  if (a.mode === 'tunnel' && !session.connected) {
    if (session.notReady) {
      Message.warning(`隧道已下发但未就绪：${session.notReady}。重开隧道无用，请到「接入」页查看详情`);
      return;
    }
    Message.warning('请先在「接入」开启企业内网隧道');
    return;
  }
  // ★三处名字统一成「直连书签」（向导 / 门户 / 这里）：它不经网关、不受访问控制，
  // 叫「全网资源」会让人以为是一种受控发布形态（wave8 行动 14）。
  Message.success(`正在打开「${a.name}」（${a.mode === 'web' ? 'Web 代理' : a.mode === 'global' ? '直连书签 · 不经隧道' : '隧道访问'}）`);
}

async function load() {
  try {
    const r = await api<PortalAppsResp>('/portal/apps');
    apps.value = r.apps;
  } catch { /* 降级 */ } finally { loaded.value = true; }
}
onMounted(load);
</script>

<style scoped>
.ap__warn { display: flex; align-items: center; gap: 7px; margin: 14px 0 4px; padding: 10px 12px; font-size: 13px;
  color: var(--bd-warning); background: var(--bd-tag-gold-bg, #FFF7E8); border-radius: 10px; }
/* 金 = 还有下一步可做（去「接入」开隧道）；红 = 此路不通，开一百次也没用（门没敲开）。
   与磁贴徽标同一条配色约定。 */
.ap__warn--bad { color: var(--bd-danger); background: var(--bd-tag-red-bg, #FFECE8); align-items: flex-start; line-height: 1.6; }
.ap__grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 14px; }
.ap__tile { position: relative; text-align: left; background: #fff; border: 1px solid var(--bd-border); border-radius: var(--bd-radius);
  padding: 14px; cursor: pointer; display: flex; flex-direction: column; gap: 4px; }
.ap__tile:active { background: var(--bd-fill-1); }
.ap__tile.locked { opacity: 0.7; }
.ap__ic { width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center;
  color: #fff; font-size: 21px; margin-bottom: 6px; }
.ap__name { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.ap__addr { font-size: 11px; color: var(--bd-t3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
/* 金 = 还有下一步可做（去门户提申请）；红 = 此路不通，做什么都没用（先修终端 / 找管理员）。
   与门户 PortalApps.vue 的配色约定一致，两端对同一状态给同一个视觉信号。 */
.ap__tag { margin-top: 4px; align-self: flex-start; font-size: 10px; padding: 1px 7px; border-radius: 4px;
  background: var(--bd-tag-gold-bg, #FFF7E8); color: var(--bd-warning); }
.ap__tag--deg { background: var(--bd-tag-red-bg, #FFECE8); color: var(--bd-danger); }
.ap__empty { text-align: center; color: var(--bd-t3); padding: 40px 0; font-size: 13px; }
</style>
