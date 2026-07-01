<template>
  <div class="st">
    <div class="dk-page__title" style="margin-bottom: 18px">设置</div>

    <div class="dk-card st__sec">
      <div class="st__h">接入配置</div>
      <div class="st__row">
        <div><div class="st__l">控制中心地址</div><div class="st__d">登录 / 拉应用 / 取短时效敲门令牌的入口</div></div>
        <a-input v-model="config.control" style="width: 240px" placeholder="http://127.0.0.1:8090" @change="saveConfig" />
      </div>
      <div class="st__row">
        <div><div class="st__l">安全代理网关</div><div class="st__d">SPA 敲门与加密隧道的网关主机</div></div>
        <a-input v-model="config.gateway" style="width: 240px" placeholder="127.0.0.1" @change="saveConfig" />
      </div>
      <div class="st__row">
        <div><div class="st__l">受保护网段</div><div class="st__d">接入后该网段流量由 utun 接管进隧道</div></div>
        <a-input v-model="config.route" style="width: 240px" placeholder="10.99.0.0/24" @change="saveConfig" />
      </div>
      <div class="st__row">
        <div><div class="st__l">虚拟 IP</div><div class="st__d">utun 虚拟网卡地址</div></div>
        <a-input v-model="config.ip" style="width: 240px" placeholder="10.99.0.2" @change="saveConfig" />
      </div>
      <div class="st__row">
        <div><div class="st__l">国密隧道（TLCP）</div><div class="st__d">隧道走国密 SM2/SM4/SM3（自签网关证书自动跳过校验）</div></div>
        <a-switch v-model="config.gm" @change="saveConfig" />
      </div>
      <div class="st__row">
        <div><div class="st__l">高级 · 端口</div><div class="st__d">SPA 敲门(UDP) / 隧道代理(TCP) 端口</div></div>
        <div style="display: flex; gap: 8px">
          <a-input v-model="config.spaPort" style="width: 116px" placeholder="18201" @change="saveConfig" />
          <a-input v-model="config.proxyPort" style="width: 116px" placeholder="18443" @change="saveConfig" />
        </div>
      </div>
      <div class="st__row">
        <div><div class="st__l">开机自动启动</div><div class="st__d">登录系统后自动拉起客户端</div></div>
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
      <div class="st__kv"><span>客户端</span><b>白帝安全接入客户端 v0.1.0（Tauri · 真 utun 数据面）</b></div>
      <div class="st__kv"><span>架构</span><b>控制中心 baidi-control + 安全代理网关 baidi-gateway + 终端数据面 baidi-tun</b></div>
      <div class="st__kv"><span>能力</span><b>一键接入 · SPA 单包授权 · 国密/通用隧道 · utun 真引流接管 · 敲门保活</b></div>
      <div class="st__note">「接入」以管理员权限拉起 <span class="dk-mono">baidi-tun</span>：创建 utun 虚拟网卡，把<b>受保护网段</b>流量接管进隧道——逐流 SPA 敲门 + 加密隧道送达网关。不启客户端时该网段不可达（路由不存在），即"先认证后连接 + 真引流"。</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { session, config, saveConfig } from '@/lib/store';
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
.st__d { font-size: 12px; color: var(--bd-t3); margin-top: 2px; max-width: 300px; }
.st__acct { display: flex; align-items: center; gap: 12px; }
.st__av { width: 38px; height: 38px; border-radius: 50%; background: linear-gradient(135deg, var(--bd-purple), var(--bd-primary)); color: #fff; font-weight: 600; display: inline-flex; align-items: center; justify-content: center; }
.st__kv { display: flex; gap: 14px; padding: 11px 18px; font-size: 13px; border-bottom: 1px solid var(--bd-fill-1); }
.st__kv span { color: var(--bd-t3); width: 48px; flex: none; }
.st__kv b { font-weight: 500; color: var(--bd-t1); }
.st__note { font-size: 11.5px; color: var(--bd-t3); padding: 12px 18px; line-height: 1.7; border-top: 1px solid var(--bd-fill-2); }
</style>
