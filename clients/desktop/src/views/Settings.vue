<template>
  <div class="st">
    <div class="dk-page__title" style="margin-bottom: 18px">设置</div>

    <div class="dk-card st__sec">
      <div class="st__h">接入配置</div>
      <div class="st__row">
        <div><div class="st__l">控制中心地址</div><div class="st__d">客户端注册与策略拉取的入口</div></div>
        <a-input v-model="session.serverAddr" style="width: 220px" @change="save('baidi_client_server', session.serverAddr)" />
      </div>
      <div class="st__row">
        <div><div class="st__l">开机自动启动</div><div class="st__d">登录系统后自动拉起客户端并静默接入</div></div>
        <a-switch v-model="session.autostart" @change="save('baidi_client_autostart', session.autostart ? '1' : '0')" />
      </div>
    </div>

    <div class="dk-card st__sec">
      <div class="st__h">账户</div>
      <div class="st__row">
        <div class="st__acct">
          <span class="st__av">{{ (session.user || '·').slice(0, 1).toUpperCase() }}</span>
          <div><div class="st__l">{{ session.user || '未登录' }}</div><div class="st__d">{{ session.connected ? '已接入企业内网' : '未接入' }}</div></div>
        </div>
        <button v-if="session.user" class="dk-btn dk-btn--ghost" @click="$emit('logout')"><icon-export />退出登录</button>
      </div>
    </div>

    <div class="dk-card st__sec">
      <div class="st__h">关于</div>
      <div class="st__kv"><span>客户端</span><b>白帝安全接入客户端 v0.1.0（桌面端壳 · Tauri-ready）</b></div>
      <div class="st__kv"><span>架构</span><b>控制中心 baidi-control + 安全代理网关 + 终端 Agent</b></div>
      <div class="st__kv"><span>能力</span><b>一键接入 · 环境检测上报 · SPA 隐身 · 流量打标引流 · 自助诊断</b></div>
      <div class="st__note">数据面网关 <b>baidi-gateway</b> 已实现真链路（SPA 单包授权 + 门控 SSL 隧道代理 + JWT 身份绑定，见 <span class="dk-mono">gateway/</span>）。客户端"接入"接入真链路只差一步：Tauri sidecar 打包 baidi-knock，登录拿 JWT 后发起真实敲门。</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { session } from '@/lib/store';
defineEmits<{ logout: [] }>();
function save(k: string, v: string) { localStorage.setItem(k, v); }
</script>

<style scoped>
.st { padding: 22px 24px; max-width: 640px; }
.st__sec { margin-bottom: 16px; }
.st__h { font-size: 13px; font-weight: 600; color: var(--bd-t2); padding: 13px 18px; border-bottom: 1px solid var(--bd-fill-2); }
.st__row { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 15px 18px; border-bottom: 1px solid var(--bd-fill-1); }
.st__row:last-child { border-bottom: none; }
.st__l { font-size: 13.5px; font-weight: 500; color: var(--bd-t1); }
.st__d { font-size: 12px; color: var(--bd-t3); margin-top: 2px; }
.st__acct { display: flex; align-items: center; gap: 12px; }
.st__av { width: 38px; height: 38px; border-radius: 50%; background: linear-gradient(135deg, var(--bd-purple), var(--bd-primary)); color: #fff; font-weight: 600; display: inline-flex; align-items: center; justify-content: center; }
.st__kv { display: flex; gap: 14px; padding: 11px 18px; font-size: 13px; border-bottom: 1px solid var(--bd-fill-1); }
.st__kv span { color: var(--bd-t3); width: 48px; flex: none; }
.st__kv b { font-weight: 500; color: var(--bd-t1); }
.st__note { font-size: 11.5px; color: var(--bd-t3); padding: 12px 18px; line-height: 1.7; border-top: 1px solid var(--bd-fill-2); }
</style>
