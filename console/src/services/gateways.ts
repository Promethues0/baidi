/** 网关服务 · GET /api/gateways（zhulong-control）。DTO 与 Gateway 视图模型同构。 */
import { getJSON } from './http';
import type { Gateway } from '@/mock';

interface GatewayDTO {
  name: string;
  role: string;
  modes: ('ssl' | 'mesh' | 'ipsec')[];
  status: 'online' | 'degraded' | 'offline';
  cpu: number;
  mem: number;
  sessions: number;
  version: string;
}

export async function listGateways(): Promise<Gateway[]> {
  const rows = await getJSON<GatewayDTO[]>('/api/gateways');
  return rows.map((g) => ({
    name: g.name,
    role: g.role,
    modes: g.modes,
    status: g.status,
    cpu: g.cpu,
    mem: g.mem,
    sessions: g.sessions,
    version: g.version
  }));
}
