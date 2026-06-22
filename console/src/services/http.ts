/**
 * 白帝控制台 · HTTP 基础客户端
 * 管理 API 走 vite 反代 /ctl → zhulong-control（:5273，gateway/ssl-gw/cmd/zhulong-control）。
 * 该控制面 REST 返回裸 JSON（数组或对象），无统一信封。
 */
const BASE = '/ctl';

export async function getJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    headers: { Accept: 'application/json' },
    ...init
  });
  if (!res.ok) {
    throw new Error(`control API ${path} → HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}
