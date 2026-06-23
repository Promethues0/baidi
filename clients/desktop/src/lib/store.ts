import { reactive } from 'vue';

/** 客户端会话与接入状态（终端 Agent 全局状态）。 */
export const session = reactive({
  token: localStorage.getItem('baidi_client_token') || '',
  user: localStorage.getItem('baidi_client_user') || '',
  connected: false,            // 是否已接入企业内网
  serverAddr: localStorage.getItem('baidi_client_server') || 'sdp.baidi.local',
  autostart: localStorage.getItem('baidi_client_autostart') === '1'
});

export function authed(): boolean { return !!session.token; }

export function login(token: string, user: string): void {
  session.token = token;
  session.user = user;
  localStorage.setItem('baidi_client_token', token);
  localStorage.setItem('baidi_client_user', user);
}

export function logout(): void {
  session.token = '';
  session.user = '';
  session.connected = false;
  localStorage.removeItem('baidi_client_token');
  localStorage.removeItem('baidi_client_user');
}
