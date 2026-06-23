import { reactive } from 'vue';

/** 移动端会话与接入状态（终端 Agent 全局状态）。 */
export const session = reactive({
  token: localStorage.getItem('baidi_m_token') || '',
  user: localStorage.getItem('baidi_m_user') || '',
  connected: false,
  serverAddr: localStorage.getItem('baidi_m_server') || 'sdp.baidi.local'
});

export function authed(): boolean { return !!session.token; }

export function login(token: string, user: string): void {
  session.token = token;
  session.user = user;
  localStorage.setItem('baidi_m_token', token);
  localStorage.setItem('baidi_m_user', user);
}

export function logout(): void {
  session.token = '';
  session.user = '';
  session.connected = false;
  localStorage.removeItem('baidi_m_token');
  localStorage.removeItem('baidi_m_user');
}
