<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">IPSec VPN 组网</div>
        <div class="bd-page__sub">站点到站点隧道 · 白帝自研 IKEv2/ESP（用户态） · 运行态由网关实测回报</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        <button class="bd-btn bd-btn--ghost" @click="load"><icon-refresh />刷新</button>
        <button class="bd-btn" :disabled="!live" :title="live ? '' : '降级演示模式下不可写入'" @click="openCreate"><icon-plus />新建站点</button>
      </div>
    </div>

    <!-- 诚实边界：把「哪些是实测、哪些本轮不支持」写在产品里，而不是只写在文档里。
         文档没人翻，界面天天看——边界只有摆在这里才拦得住误用。 -->
    <div class="bd-note">
      <icon-info-circle-fill class="bd-note__ic" />
      <div>
        状态 / SPI / 流量 / 剩余寿命<b>全部来自网关经 mTLS 心跳回报的实测值</b>（15s 一跳，控制面不再自行改写运行态）。
        <b>「期望」列是管理意图，「实际状态」列才是隧道真实情况</b>——两列不一致的行就是要排查的行。
        本轮认证方式<b>只支持 PSK</b>（证书认证未实现）；国密套件走白帝私有码点（IANA 私有段 1024+），
        <b>仅白帝↔白帝互通，与 GM/T 0022 无关，不可对外称「国密 IPSec」</b>。
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'topo' }" @click="tab = 'topo'">拓扑总览</span>
      <span class="bd-tab" :class="{ on: tab === 'list' }" @click="tab = 'list'">站点清单 <em>{{ sites.length }}</em></span>
    </div>

    <!-- ============ 拓扑总览（P8 SVG）============ -->
    <div v-show="tab === 'topo'">
      <!-- 聚合统计：刻意不做「国密站点数 / 后量子站点数」——那两个数来自配置字段，
           回答的是「配了什么」而不是「协商成了什么」，摆在监控位置上会被当成运行事实读。 -->
      <div class="bd-stats">
        <div class="bd-card bd-stat">
          <div class="bd-stat__n">{{ sites.length }}</div>
          <div class="bd-stat__c">站点总数</div>
        </div>
        <div class="bd-card bd-stat">
          <div class="bd-stat__n">{{ enabledCount }}</div>
          <div class="bd-stat__c">期望启用（管理意图）</div>
        </div>
        <div class="bd-card bd-stat">
          <div class="bd-stat__n" style="color: #00B42A">{{ upCount }}</div>
          <div class="bd-stat__c">隧道已建立（实测）</div>
        </div>
        <div class="bd-card bd-stat">
          <div class="bd-stat__n" style="color: #F53F3F">{{ failedCount }}</div>
          <div class="bd-stat__c">协商失败</div>
        </div>
        <div class="bd-card bd-stat">
          <div class="bd-stat__n" style="color: #FF7D00">{{ silentCount }}</div>
          <div class="bd-stat__c">已启用但无回报</div>
        </div>
      </div>

      <div class="bd-card bd-topo">
        <svg viewBox="0 0 960 460" width="100%" preserveAspectRatio="xMidYMid meet" font-family="-apple-system, 'PingFang SC', 'Segoe UI', sans-serif">
          <!-- 中心到各站点连线 -->
          <g v-for="(r, i) in decorated" :key="'edge-' + r.s.id">
            <line
              :x1="hubCx" :y1="hubCy" :x2="nodePos(i).x" :y2="nodePos(i).y"
              fill="none" :stroke="stateColor(r.vs)" stroke-width="2"
              :stroke-dasharray="r.vs === 'up' || r.vs === 'rekeying' ? '' : '5 5'"
            />
          </g>

          <!-- 各站点节点 -->
          <g v-for="(r, i) in decorated" :key="'node-' + r.s.id">
            <rect
              :x="nodePos(i).x - 86" :y="nodePos(i).y - 30" width="172" height="60" rx="10"
              fill="#FFFFFF" :stroke="stateColor(r.vs)" stroke-width="1.5"
            />
            <circle :cx="nodePos(i).x - 70" :cy="nodePos(i).y - 12" r="5" :fill="stateColor(r.vs)" />
            <text :x="nodePos(i).x - 58" :y="nodePos(i).y - 8" font-size="13" font-weight="600" fill="#1D2129">{{ r.s.name }}</text>
            <text :x="nodePos(i).x - 70" :y="nodePos(i).y + 14" font-size="11" fill="#86909C" font-family="ui-monospace, monospace">{{ r.s.remoteSubnet || '—' }}</text>
            <!-- 国密角标：SVG 里没法挂 tooltip 组件，用原生 <title> 把边界写清楚 -->
            <g v-if="r.s.suite === 'gm'">
              <title>国密套件走白帝私有码点（IANA 私有使用段 1024+），仅白帝↔白帝互通，与 GM/T 0022 无关</title>
              <rect :x="nodePos(i).x + 8" :y="nodePos(i).y + 4" width="58" height="18" rx="9" fill="#FEF1F0" />
              <text :x="nodePos(i).x + 37" :y="nodePos(i).y + 17" font-size="10" font-weight="600" fill="#F53F3F" text-anchor="middle">私有码点</text>
            </g>
          </g>

          <!-- 中心：本端网关 · 总部 -->
          <g>
            <rect :x="hubCx - 92" :y="hubCy - 34" width="184" height="68" rx="12" fill="#F2F7FF" stroke="#BEDAFF" stroke-width="1.5" />
            <circle :cx="hubCx - 66" :cy="hubCy - 8" r="9" fill="#165DFF" />
            <text :x="hubCx - 50" :y="hubCy - 3" font-size="14" font-weight="700" fill="#1D2129">本端网关</text>
            <text :x="hubCx" :y="hubCy + 20" font-size="11.5" fill="#86909C" text-anchor="middle">白帝自研 IKEv2/ESP（用户态）</text>
          </g>

          <!-- 图例：五态各一色。down 用灰不用红——「没启用」是管理意图不是故障，
               画成红色会让运维在满屏红里找不到真正 failed 的那条。 -->
          <g transform="translate(24, 432)">
            <text x="0" y="12" font-size="12" font-weight="600" fill="#4E5969">图例</text>
            <g v-for="(lg, k) in LEGEND" :key="lg.v">
              <line :x1="56 + k * 148" y1="8" :x2="80 + k * 148" y2="8" :stroke="stateColor(lg.v)" stroke-width="2" :stroke-dasharray="lg.v === 'up' || lg.v === 'rekeying' ? '' : '5 5'" />
              <text :x="88 + k * 148" y="12" font-size="12" fill="#86909C">{{ lg.t }}</text>
            </g>
          </g>
        </svg>
      </div>
    </div>

    <!-- ============ 站点清单 ============ -->
    <div v-show="tab === 'list'" class="bd-tablecard">
      <div class="bd-toolbar">
        <span class="bd-toolbar__c">站点到站点隧道 · {{ shownRows.length }} 个</span>
        <span v-if="polling && live" class="bd-polling"><icon-loading spin />有站点在途，每 {{ POLL_SEC }}s 自动刷新</span>
        <div style="flex: 1" />
        <div class="bd-searchbox" style="width: 240px">
          <icon-search />
          <input v-model="kw" class="bd-searchbox__in" placeholder="按站点 / 网段 / 对端搜索" />
        </div>
      </div>
      <table class="bd-table">
        <thead>
          <tr>
            <th>站点</th><th>网段</th><th>期望（管理意图）</th><th>实际状态（实测）</th>
            <th>套件：配置 vs 实际</th><th>SA 剩余寿命</th><th>流量（实测）</th><th class="r">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in shownRows" :key="r.s.id">
            <!-- 站点 -->
            <td>
              <b style="color: var(--bd-t1); font-weight: 500">{{ r.s.name }}</b>
              <div class="bd-mono bd-sub3">{{ r.s.peer }}</div>
              <div class="bd-sub3">
                承载网关
                <span class="bd-mono">{{ r.s.gatewayId || '未指派' }}</span>
                <!-- 没指派网关 = 没有任何进程会拉到这条站点，界面表现为永远「未回报」，
                     且全程零报错。这正是 apps.resource_id 那类静默断裂的形态，必须点名。 -->
                <span v-if="!r.s.gatewayId" class="bd-err">· 无网关承载，永远不会协商</span>
                <span v-else-if="r.s.sa && r.s.sa.gatewayId && r.s.sa.gatewayId !== r.s.gatewayId" class="bd-err">
                  · 回报来自 {{ r.s.sa.gatewayId }}，与指派不符（两台网关在抢同一条站点）
                </span>
              </div>
            </td>

            <!-- 网段 -->
            <td>
              <span class="bd-mono" style="font-size: 11.5px">{{ r.s.localSubnet || '—' }} ⇄ {{ r.s.remoteSubnet || '—' }}</span>
            </td>

            <!-- 期望态：管理员想让它开不开 -->
            <td>
              <span class="bd-pill" :class="r.s.enabled ? 'on' : 'off'">{{ r.s.enabled ? '已启用' : '已停用' }}</span>
              <div class="bd-sub2">
                <span class="bd-tg" :style="tagStyle(authColor(r.s.auth))" :title="authHint(r.s.auth)">{{ authText(r.s.auth) }}</span>
                <span
                  v-if="r.s.auth === 'psk'"
                  class="bd-tg"
                  :style="tagStyle(r.s.hasPsk ? '#00B42A' : '#F53F3F')"
                  :title="r.s.hasPsk ? '指纹供两端核对是否为同一把密钥；控制面永不回显原文' : '空 PSK 会让网关在装载期拒绝启动该站点'"
                >{{ r.s.hasPsk ? (r.s.pskFingerprint ? '指纹 ' + r.s.pskFingerprint : 'PSK 已配置') : '未配置 PSK' }}</span>
              </div>
            </td>

            <!-- 实际状态：只信网关回报 -->
            <td>
              <span class="bd-st">
                <icon-loading v-if="r.vs === 'pending' || r.vs === 'connecting'" spin :style="{ color: stateColor(r.vs) }" />
                <span v-else class="d" :style="{ background: stateColor(r.vs) }" />
                {{ stateText(r.vs) }}
              </span>
              <div v-if="r.timedOut" class="bd-err">
                已下发 {{ Math.round((nowSec - (busy[r.s.id] || nowSec))) }}s 仍无回报 · 检查该网关的 baidi-ipsec 是否在线
              </div>
              <div v-else-if="r.vs === 'pending'" class="bd-sub3">意图已落库，等待网关下一跳（≤{{ HEARTBEAT_SEC }}s）开始协商</div>
              <div v-else-if="r.vs === 'unreported'" class="bd-sub3">该站点从未被任何网关回报过</div>
              <!-- 失败原因必须留在一级视图：IPSec 的协商失败率远高于 TLS，
                   把原因收进抽屉等于把这个功能做成不可运维。 -->
              <div v-else-if="r.vs === 'failed'" class="bd-fail">
                <span class="bd-tg" :style="tagStyle('#F53F3F')">{{ r.s.sa?.lastErrorCode || 'IKE 协商失败' }}</span>
                <div class="bd-fail__msg" :title="r.s.sa?.lastError || ''">{{ r.s.sa?.lastError || '网关未给出原因（建议查 baidi-ipsec 日志）' }}</div>
                <div class="bd-sub3">{{ fmtTs(r.s.sa?.lastErrorAt || 0) }}</div>
              </div>
              <div v-else-if="r.stale" class="bd-warn">网关已 {{ ageText(nowSec - (r.s.sa?.reportedAt || 0)) }}未回报，下方数字非当前值</div>
            </td>

            <!-- 套件：配置期望 vs 实际协商结果 -->
            <td>
              <div class="bd-cmp bd-mono">
                <div>配置 {{ phText(r.s.phase1) }}</div>
                <div :class="'v-' + r.cmp.v">实际 {{ r.s.sa?.negotiatedProposal || '—' }} {{ CMP_ICON[r.cmp.v] }}</div>
              </div>
              <div class="bd-sub2">
                <span v-if="r.s.suite === 'gm'" class="bd-tg" :style="tagStyle('#F53F3F')" title="IANA 私有使用段码点（1024+），仅白帝↔白帝互通，非 GM/T 0022 合规">国密 · 私有码点</span>
                <span v-if="r.s.pfs" class="bd-tg" :style="tagStyle('#00B42A')">PFS</span>
                <span v-if="r.s.pqHybrid" class="bd-tg" :style="tagStyle('#86909C')" title="pqHybrid 字段保留但本版本未实现 ML-KEM 混合，网关会在装载期拒绝">PQ 未实现</span>
              </div>
              <div v-if="r.cmp.v === 'mismatch'" class="bd-err">实际套件缺少：{{ r.cmp.miss.join(' / ') }} —— 谈成的不是配的那套</div>
              <div v-if="r.unsupported.length" class="bd-err">本实现不支持：{{ r.unsupported.join('、') }} · 网关装载期会直接拒绝</div>
            </td>

            <!-- SA 剩余寿命：假数据不会倒数 -->
            <td>
              <template v-if="r.s.sa && (r.vs === 'up' || r.vs === 'rekeying') && r.s.sa.rekeyAt > 0">
                <div class="bd-life" :class="{ soon: lifePct(r.s.sa) < 0.1 }">{{ remainText(r.s.sa.rekeyAt - nowSec) }}</div>
                <a-progress :percent="lifePct(r.s.sa)" :show-text="false" size="mini" :color="lifePct(r.s.sa) < 0.1 ? '#FF7D00' : '#00B42A'" />
                <div class="bd-sub3">距重协商 · 硬到期 {{ remainText(r.s.sa.expiresAt - nowSec) }}</div>
              </template>
              <span v-else class="bd-dash">—</span>
            </td>

            <!-- 流量：只读 sa 的实测计数 -->
            <td>
              <template v-if="r.s.sa && r.s.sa.reportedAt > 0">
                <div class="bd-mono bd-flow">↓ {{ formatBytes(r.s.sa.rxBytes) }} <span class="bd-dim">/ {{ r.s.sa.packetsIn }} 包</span></div>
                <div class="bd-mono bd-flow">↑ {{ formatBytes(r.s.sa.txBytes) }} <span class="bd-dim">/ {{ r.s.sa.packetsOut }} 包</span></div>
                <div class="bd-sub3" :class="{ warn: r.stale }">{{ freshText(r.s) }}</div>
              </template>
              <template v-else>
                <span class="bd-dash">—</span>
                <div class="bd-sub3">网关未回报计数</div>
              </template>
            </td>

            <!-- 操作 -->
            <td class="r">
              <div class="bd-ops">
                <span class="bd-link" :class="{ 'bd-link--grey': r.vs === 'pending' }" @click="toggle(r)">
                  {{ r.s.enabled ? '停用' : '启用' }}
                </span>
                <span v-if="r.s.auth === 'psk'" class="bd-link" @click="openPsk(r.s)">PSK</span>
                <span class="bd-link" @click="detailId = r.s.id">详情</span>
                <span class="bd-link" @click="openEdit(r.s)">编辑</span>
                <a-popconfirm content="确定删除该站点隧道？" @ok="del(r.s)">
                  <span class="bd-link bd-link--danger">删除</span>
                </a-popconfirm>
              </div>
            </td>
          </tr>
          <tr v-if="!shownRows.length"><td colspan="8" class="bd-empty">{{ kw ? '无匹配站点' : '暂无站点，点右上「新建站点」创建' }}</td></tr>
        </tbody>
      </table>
    </div>

    <!-- ============ 运行态详情抽屉 ============ -->
    <a-drawer v-model:visible="detailOpen" :width="520" :footer="false" unmount-on-close>
      <template #title>{{ detailRow?.s.name || '站点详情' }} · 运行态</template>
      <template v-if="detailRow">
        <div class="bd-dsec">协商证据</div>
        <!-- SPI 是「真的协商过」最硬的证据：单端伪造不出与对端交叉相等的一对 SPI。
             这几行是空的，就说明这条隧道从来没谈成过，与界面上任何绿色无关。 -->
        <div class="bd-kv"><span>IKE SPI(i)</span><b class="bd-mono">{{ detailRow.s.sa?.ikeSpiI || '—' }}</b></div>
        <div class="bd-kv"><span>IKE SPI(r)</span><b class="bd-mono">{{ detailRow.s.sa?.ikeSpiR || '—' }}</b></div>
        <div class="bd-kv"><span>ESP SPI 入向</span><b class="bd-mono">{{ spiHex(detailRow.s.sa?.childSpiIn) }}</b></div>
        <div class="bd-kv"><span>ESP SPI 出向</span><b class="bd-mono">{{ spiHex(detailRow.s.sa?.childSpiOut) }}</b></div>
        <div class="bd-dhint">本端入向 SPI 必然等于对端出向 SPI；两端都拿到这一对且交叉相等，才是隧道真的谈成了。</div>

        <div class="bd-dsec">套件对比</div>
        <div class="bd-kv"><span>相一配置</span><b class="bd-mono">{{ phText(detailRow.s.phase1) }}</b></div>
        <div class="bd-kv"><span>相一实际</span><b class="bd-mono" :class="'v-' + detailRow.cmp.v">{{ detailRow.s.sa?.negotiatedProposal || '—' }} {{ CMP_ICON[detailRow.cmp.v] }}</b></div>
        <div class="bd-kv"><span>相二配置</span><b class="bd-mono">{{ phText(detailRow.s.phase2) }}</b></div>
        <div class="bd-dhint">相二（Child SA）的实际套件本轮不回报，这里只有配置值——没有的东西不假装有。</div>

        <div class="bd-dsec">计数与时间</div>
        <div class="bd-kv"><span>入向</span><b class="bd-mono">{{ formatBytes(detailRow.s.sa?.rxBytes || 0) }} / {{ detailRow.s.sa?.packetsIn || 0 }} 包</b></div>
        <div class="bd-kv"><span>出向</span><b class="bd-mono">{{ formatBytes(detailRow.s.sa?.txBytes || 0) }} / {{ detailRow.s.sa?.packetsOut || 0 }} 包</b></div>
        <div class="bd-kv"><span>建立于</span><b class="bd-mono">{{ fmtTs(detailRow.s.sa?.establishedAt || 0) }}</b></div>
        <div class="bd-kv"><span>重协商</span><b class="bd-mono">{{ fmtTs(detailRow.s.sa?.rekeyAt || 0) }}</b></div>
        <div class="bd-kv"><span>硬到期</span><b class="bd-mono">{{ fmtTs(detailRow.s.sa?.expiresAt || 0) }}</b></div>
        <div class="bd-kv"><span>最近回报</span><b class="bd-mono">{{ fmtTs(detailRow.s.sa?.reportedAt || 0) }}</b></div>

        <template v-if="detailRow.s.sa?.lastError">
          <div class="bd-dsec">最近失败</div>
          <div class="bd-kv"><span>码点</span><b class="bd-mono">{{ detailRow.s.sa?.lastErrorCode || '—' }}</b></div>
          <div class="bd-kv"><span>原因</span><b>{{ detailRow.s.sa?.lastError }}</b></div>
          <div class="bd-kv"><span>时间</span><b class="bd-mono">{{ fmtTs(detailRow.s.sa?.lastErrorAt || 0) }}</b></div>
        </template>

        <div class="bd-dsec">密钥材料</div>
        <div class="bd-kv"><span>PSK</span><b>{{ detailRow.s.hasPsk ? `已配置 · 指纹 ${detailRow.s.pskFingerprint || '—'} · v${detailRow.s.pskVersion ?? 1}` : '未配置' }}</b></div>
        <div class="bd-dhint">控制面只保存密文并只回指纹，任何接口都不回显原文；下发只走 mTLS 通道。</div>
      </template>
    </a-drawer>

    <!-- ============ PSK 设置 ============ -->
    <a-modal v-model:visible="pskOpen" :title="`设置 PSK · ${pskSite?.name || ''}`" :width="520" :footer="false" unmount-on-close>
      <div class="bd-uform">
        <div v-if="pskSite?.hasPsk" class="bd-pskcur">
          已配置 · 指纹 <span class="bd-mono">{{ pskSite?.pskFingerprint || '—' }}</span> · 版本 v{{ pskSite?.pskVersion ?? 1 }}
          <div class="bd-sub3">指纹用于核对两端是不是同一把密钥。原文不回显——回显没有任何操作价值，只有泄露面；配错了重设即可。</div>
        </div>
        <div class="bd-uform__f">
          <label>新的预共享密钥<i class="req">*</i></label>
          <a-input-password v-model="pskValue" placeholder="至少 20 字符，建议直接用右侧随机生成" allow-clear />
          <div class="bd-pskacts">
            <button class="bd-btn bd-btn--ghost" @click="genPsk"><icon-refresh />生成随机 PSK</button>
            <span class="bd-sub3">32 字节密码学随机数（crypto.getRandomValues）</span>
          </div>
        </div>
        <!-- IKEv2 的 PSK 认证在弱口令下可被离线字典攻击：AUTH 载荷就是 PSK 的 PRF 输出，
             抓一次握手就能在本地慢慢猜。所以这里只推随机串，不接受「好记的口令」。 -->
        <div class="bd-uform__note">
          提交后原文<b>立刻从界面消失且无法再读取</b>，请在关闭前同步配置到对端设备。
          两端 PSK 不一致的症状是 <span class="bd-mono">AUTHENTICATION_FAILED</span>，会显示在「实际状态」列。
        </div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="pskOpen = false">取消</button>
          <button class="bd-btn" :disabled="pskSaving" @click="savePsk">写入并下发</button>
        </div>
      </div>
    </a-modal>

    <!-- ============ 新建 / 编辑 站点 ============ -->
    <a-modal v-model:visible="formOpen" :title="editing ? '编辑站点隧道' : '新建站点隧道'" :width="560" :footer="false" unmount-on-close>
      <div class="bd-uform">
        <!-- 装载期会被拒绝的参数在这里提前说清楚。留成「可选但不工作」的下场是：
             管理员保存成功、启用成功、隧道永远起不来，而界面上看不出为什么。 -->
        <div v-if="formUnsupported.length" class="bd-formwarn">
          <icon-exclamation-circle-fill />
          <div>当前配置含本实现<b>不支持</b>的参数：{{ formUnsupported.join('、') }}。保存可以，但网关在装载期会直接拒绝并把站点置为「协商失败」。</div>
        </div>

        <div class="bd-uform__group">基本</div>
        <div class="bd-uform__row">
          <div class="bd-uform__f"><label>站点名称<i class="req">*</i></label>
            <a-input v-model="form.name" placeholder="如 上海分支" />
          </div>
          <div class="bd-uform__f"><label>对端网关地址<i class="req">*</i></label>
            <a-input v-model="form.peer" placeholder="如 203.0.113.20" />
          </div>
        </div>
        <div class="bd-uform__row">
          <div class="bd-uform__f"><label>承载网关 ID<i class="req">*</i></label>
            <a-input v-model="form.gatewayId" placeholder="如 ipsec-gw-1（须与组网网关 mTLS 证书 CN 逐字符一致）" />
            <div class="bd-uform__refhint">留空则没有任何网关会拉到这条站点：界面上表现为永远「未回报」，且全程不会有任何报错。</div>
          </div>
          <div class="bd-uform__f"><label>协议版本</label>
            <a-input model-value="IKEv2" disabled />
            <div class="bd-uform__refhint">固定 IKEv2，提交时自动带上（不实现 IKEv1）。</div>
          </div>
        </div>
        <div class="bd-uform__row">
          <div class="bd-uform__f"><label>本端网段</label>
            <a-select
              :model-value="form.localRef"
              class="bd-uform__objpick"
              placeholder="从对象库选择（可选）"
              allow-clear
              :disabled="!subnetObjs.length"
              @change="(v) => pickLocalObj(v as string | undefined)"
            >
              <a-option v-for="o in subnetObjs" :key="o.id" :value="o.id">{{ objLabel(o) }}</a-option>
            </a-select>
            <a-input v-model="form.localSubnet" placeholder="如 10.10.0.0/16" @input="onLocalSubnetInput" />
            <div v-if="form.localRef" class="bd-uform__refhint">引用地址对象：{{ refName(form.localRef) }}</div>
          </div>
          <div class="bd-uform__f"><label>对端网段</label>
            <a-select
              :model-value="form.remoteRef"
              class="bd-uform__objpick"
              placeholder="从对象库选择（可选）"
              allow-clear
              :disabled="!subnetObjs.length"
              @change="(v) => pickRemoteObj(v as string | undefined)"
            >
              <a-option v-for="o in subnetObjs" :key="o.id" :value="o.id">{{ objLabel(o) }}</a-option>
            </a-select>
            <a-input v-model="form.remoteSubnet" placeholder="如 10.20.0.0/16" @input="onRemoteSubnetInput" />
            <div v-if="form.remoteRef" class="bd-uform__refhint">引用地址对象：{{ refName(form.remoteRef) }}</div>
          </div>
        </div>

        <div class="bd-uform__group">认证 · 套件</div>
        <div class="bd-uform__row">
          <div class="bd-uform__f"><label>认证方式</label>
            <a-select v-model="form.auth">
              <a-option value="psk">预共享密钥（PSK）</a-option>
              <a-option value="cert" disabled>证书 · 本轮未实现</a-option>
              <a-option value="sm2cert" disabled>SM2 证书 · 本轮未实现</a-option>
            </a-select>
            <div class="bd-uform__refhint">证书认证需要 RFC 7427 数字签名 AUTH 与 CERT/CERTREQ 载荷，本轮不做，故置灰而不是留成可选。</div>
          </div>
          <div class="bd-uform__f"><label>密码套件</label>
            <a-radio-group v-model="form.suite" type="button" @change="onSuiteChange">
              <a-radio value="standard">标准</a-radio>
              <a-radio value="gm">国密</a-radio>
            </a-radio-group>
            <div v-if="form.suite === 'gm'" class="bd-uform__refhint bd-warn">
              国密 = SM4-GCM/HMAC-SM3/sm2p256v1，走 IANA 私有使用段码点（1024+）：仅白帝↔白帝互通，与第三方设备一律不通，且与 GM/T 0022 无关。
            </div>
          </div>
        </div>
        <div class="bd-uform__row">
          <div class="bd-uform__f bd-uform__sw"><label>PFS 完美前向保密</label><a-switch v-model="form.pfs" /></div>
          <div class="bd-uform__f bd-uform__sw">
            <label>后量子 ML-KEM 混合<span class="bd-sub3">字段保留，本版本未实现</span></label>
            <a-switch v-model="form.pqHybrid" disabled />
          </div>
        </div>

        <div class="bd-uform__group">相一参数（IKE SA）</div>
        <div class="bd-uform__row3">
          <div class="bd-uform__f"><label>加密</label>
            <a-select v-model="form.phase1.enc"><a-option v-for="e in ENC_OPTS" :key="e.v" :value="e.v" :disabled="!algUsable(e)">{{ algLabel(e) }}</a-option></a-select>
          </div>
          <div class="bd-uform__f"><label>哈希</label>
            <a-select v-model="form.phase1.hash"><a-option v-for="h in HASH_OPTS" :key="h.v" :value="h.v" :disabled="!algUsable(h)">{{ algLabel(h) }}</a-option></a-select>
          </div>
          <div class="bd-uform__f"><label>DH 群</label>
            <a-select v-model="form.phase1.dh"><a-option v-for="d in DH_OPTS" :key="d.v" :value="d.v" :disabled="!algUsable(d)">{{ algLabel(d) }}</a-option></a-select>
          </div>
        </div>

        <div class="bd-uform__group">相二参数（IPSec SA）</div>
        <div class="bd-uform__row3">
          <div class="bd-uform__f"><label>加密</label>
            <a-select v-model="form.phase2.enc"><a-option v-for="e in ENC_OPTS" :key="e.v" :value="e.v" :disabled="!algUsable(e)">{{ algLabel(e) }}</a-option></a-select>
          </div>
          <div class="bd-uform__f"><label>哈希</label>
            <a-select v-model="form.phase2.hash"><a-option v-for="h in HASH_OPTS" :key="h.v" :value="h.v" :disabled="!algUsable(h)">{{ algLabel(h) }}</a-option></a-select>
          </div>
          <div class="bd-uform__f"><label>DH 群</label>
            <a-select v-model="form.phase2.dh"><a-option v-for="d in DH_OPTS" :key="d.v" :value="d.v" :disabled="!algUsable(d)">{{ algLabel(d) }}</a-option></a-select>
          </div>
        </div>

        <div class="bd-uform__note">
          保存只写配置与管理意图，<b>不会立刻建隧道</b>：网关下一跳（≤{{ HEARTBEAT_SEC }}s）拉到配置后才开始 IKE 协商，结果在「实际状态」列。
        </div>

        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="formOpen = false">取消</button>
          <button class="bd-btn" :disabled="saving" @click="save">{{ editing ? '保存' : '创建' }}并落库</button>
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import {
  api,
  type IpsecSite, type IpsecSA, type IpsecState, type IpsecPhase, type IpsecResp, type IpsecPskResp,
  type AddrObject, type ObjectBundle, failReason, failStatus } from '@/lib/api';

const tab = ref<'topo' | 'list'>('topo');
const live = ref(false);
const saving = ref(false);

/* ── 节拍常量 ──
 * 网关经 mTLS 心跳回报运行态，15s 一跳。这个数字决定了两件事：
 *  ① 流量/状态最多滞后 15s，界面必须把这句话说出来（否则用户会拿它当秒级监控用）；
 *  ② 点了「启用」到看见结果，最坏要等两跳（一跳拉配置、一跳回报结果）。
 * 轮询节拍取 4s 只是为了让回报一到就能被看见，不是把心跳变快——真实数据新鲜度仍由心跳决定。 */
const HEARTBEAT_SEC = 15;
const POLL_SEC = 4;
const STALE_SEC = 45;       // 连续三跳没回报就不能再把数字当实时值展示
const PENDING_MAX_SEC = 90; // 下发后等待首个新回报的上限，超过就转为「疑似网关离线」

/* ── 算法可选项 ──
 * ok=false 的项在下拉里置灰：网关在装载期会**直接拒绝**这些参数（见 ike/const.go 的
 * Transform ID 表，本实现只有 AES/SM4 的 GCM|CBC、HMAC-SHA256|SM3、MODP2048/ECP256/sm2p256v1）。
 * ★留成「可选但不工作」的症状最坑：保存成功、启用成功、隧道永远起不来，界面上还看不出为什么。 */
interface AlgOpt { v: string; ok: boolean }
const ENC_OPTS: AlgOpt[] = [
  { v: 'AES256-GCM', ok: true },
  { v: 'AES128-GCM', ok: true },
  { v: 'AES256-CBC', ok: true },
  { v: 'SM4-GCM', ok: true },
  { v: 'SM4-CBC', ok: true }
];
const HASH_OPTS: AlgOpt[] = [
  { v: 'SHA256', ok: true },
  { v: 'SHA384', ok: false },
  { v: 'SM3', ok: true }
];
const DH_OPTS: AlgOpt[] = [
  { v: 'group14', ok: true },  // MODP-2048
  { v: 'group19', ok: true },  // ECP-256
  { v: 'sm2p256', ok: true },  // sm2p256v1（私有码点 1024）
  { v: 'group21', ok: false },
  { v: 'group24', ok: false }
];
/** 走 IANA 私有码点的算法：只有「国密」套件放行（与后端 ipsecPrivateAlgs、
 *  数据面 ike 的 private 标记一致）。 */
const PRIVATE_ALGS = new Set(['SM4-GCM', 'SM4-CBC', 'SM3', 'sm2p256']);
/** 某算法在当前套件下能否选：本实现支持 且（非私有码点 或 已选国密套件）。
 *  ★不做反向限制——SM4-GCM 配 SHA256 在国密套件下完全可用，数据面明说拒绝它
 *  没有安全收益（ike/suite.go），入口比实现更严会造成反向假拒绝。 */
function algUsable(o: AlgOpt): boolean {
  if (!o.ok) return false;
  return form.suite === 'gm' || !PRIVATE_ALGS.has(o.v);
}
function algLabel(o: AlgOpt) {
  if (!o.ok) return `${o.v} · 本实现不支持`;
  if (PRIVATE_ALGS.has(o.v) && form.suite !== 'gm') return `${o.v} · 需切到「国密」套件`;
  return o.v;
}
function algBad(list: AlgOpt[], v: string) { const o = list.find((x) => x.v === v); return !o || !o.ok; }

/* ── 五态展示元数据 ──
 * ★down 用灰不用红：「管理员没启用」是意图不是故障，画成红色会让运维在满屏红里
 * 找不到真正 failed 的那一条。pending/unreported 是纯 UI 概念，见 decorate()。 */
type ViewState = IpsecState | 'pending' | 'unreported';
const STATE_META: Record<ViewState, { t: string; c: string }> = {
  up: { t: '已建立', c: '#00B42A' },
  rekeying: { t: '重协商中', c: '#165DFF' }, // 旧 SA 仍在承载流量，不是故障
  connecting: { t: '协商中…', c: '#FF7D00' },
  failed: { t: '协商失败', c: '#F53F3F' },
  down: { t: '未启用', c: '#C9CDD4' },
  pending: { t: '下发中…', c: '#FF7D00' },
  unreported: { t: '未回报', c: '#86909C' }
};
function stateColor(v: ViewState) { return STATE_META[v].c; }
function stateText(v: ViewState) { return STATE_META[v].t; }
const LEGEND: { v: ViewState; t: string }[] = [
  { v: 'up', t: '已建立' },
  { v: 'rekeying', t: '重协商中' },
  { v: 'connecting', t: '协商中' },
  { v: 'failed', t: '协商失败' },
  { v: 'down', t: '未启用' }
];

/* ── 降级演示数据 ──
 * 时间戳按「相对现在」现算，所以倒计时会真的走、新鲜度也不会一进页面就过期。
 * 五条覆盖全部五态，其中 site-bj 刻意造成「配了 AES256 实际谈成 AES128」的降级，
 * 用来验证套件对比那一格确实会亮红——这一格如果永远显示 ✓ 就等于没做。 */
function mockSites(): IpsecSite[] {
  const t = nowFn();
  return [
    {
      id: 'site-sh', name: '上海分支', peer: '203.0.113.20', localSubnet: '10.10.0.0/16', remoteSubnet: '10.20.0.0/16',
      ikeVersion: 'IKEv2', auth: 'psk', suite: 'gm', gatewayId: 'ipsec-gw-1', enabled: true,
      phase1: { enc: 'SM4-GCM', hash: 'SM3', dh: 'sm2p256' },
      phase2: { enc: 'SM4-GCM', hash: 'SM3', dh: 'sm2p256' },
      pfs: true, pqHybrid: false, hasPsk: true, pskFingerprint: 'a3f9c2e1', pskVersion: 3,
      sa: {
        siteId: 'site-sh', gatewayId: 'ipsec-gw-1', state: 'up',
        ikeSpiI: '8f2c41a09b7de315', ikeSpiR: '1d77e0b3c4a95f28', childSpiIn: 0xc0a80042, childSpiOut: 0x3f9e11b7,
        rxBytes: 41_238_912, txBytes: 18_774_016, packetsIn: 39_120, packetsOut: 27_845,
        negotiatedProposal: 'SM4-GCM16/PRF-HMAC-SM3/SM2P256',
        establishedAt: t - 1180, rekeyAt: t + 2420, expiresAt: t + 3600, reportedAt: t - 4,
        lastError: '', lastErrorAt: 0
      }
    },
    {
      id: 'site-bj', name: '北京总部备线', peer: '198.51.100.7', localSubnet: '10.10.0.0/16', remoteSubnet: '10.30.0.0/16',
      ikeVersion: 'IKEv2', auth: 'psk', suite: 'standard', gatewayId: 'ipsec-gw-1', enabled: true,
      phase1: { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' },
      phase2: { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' },
      pfs: true, pqHybrid: false, hasPsk: true, pskFingerprint: '7b10d4c6', pskVersion: 1,
      sa: {
        siteId: 'site-bj', gatewayId: 'ipsec-gw-1', state: 'rekeying',
        ikeSpiI: '55ab90ff2e1c7d64', ikeSpiR: 'e2019c73aa4b8016', childSpiIn: 0x9d43f001, childSpiOut: 0x2b6c77aa,
        rxBytes: 9_126_805, txBytes: 5_242_880, packetsIn: 8_431, packetsOut: 6_902,
        negotiatedProposal: 'AES128-GCM16/PRF-HMAC-SHA256/ECP256', // 刻意降级：配的是 AES256
        establishedAt: t - 3400, rekeyAt: t + 160, expiresAt: t + 400, reportedAt: t - 9,
        lastError: '', lastErrorAt: 0
      }
    },
    {
      id: 'site-gz', name: '广州办事处', peer: '192.0.2.55', localSubnet: '10.10.0.0/16', remoteSubnet: '10.40.0.0/24',
      ikeVersion: 'IKEv2', auth: 'psk', suite: 'standard', gatewayId: 'ipsec-gw-1', enabled: true,
      phase1: { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group14' },
      phase2: { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group14' },
      pfs: false, pqHybrid: false, hasPsk: true, pskFingerprint: 'd0c81b44', pskVersion: 2,
      sa: {
        siteId: 'site-gz', gatewayId: 'ipsec-gw-1', state: 'failed',
        ikeSpiI: '3c81aa07d5e94b12', ikeSpiR: '', childSpiIn: 0, childSpiOut: 0,
        rxBytes: 0, txBytes: 2_048, packetsIn: 0, packetsOut: 6,
        negotiatedProposal: '',
        establishedAt: 0, rekeyAt: 0, expiresAt: 0, reportedAt: t - 6,
        lastErrorCode: 'AUTHENTICATION_FAILED',
        lastError: '对端 192.0.2.55:500 拒绝认证：AUTH 载荷校验不通过，通常是两端 PSK 不一致（本端指纹 d0c81b44）',
        lastErrorAt: t - 6
      }
    },
    {
      id: 'site-cd', name: '成都灾备', peer: '203.0.113.99', localSubnet: '10.10.0.0/16', remoteSubnet: '10.50.0.0/16',
      ikeVersion: 'IKEv2', auth: 'psk', suite: 'standard', gatewayId: 'gw-2', enabled: false,
      phase1: { enc: 'AES256-CBC', hash: 'SHA256', dh: 'group14' },
      phase2: { enc: 'AES256-CBC', hash: 'SHA256', dh: 'group14' },
      pfs: true, pqHybrid: true, hasPsk: false,
      sa: {
        siteId: 'site-cd', gatewayId: 'gw-2', state: 'down',
        ikeSpiI: '', ikeSpiR: '', childSpiIn: 0, childSpiOut: 0,
        rxBytes: 0, txBytes: 0, packetsIn: 0, packetsOut: 0,
        negotiatedProposal: '',
        establishedAt: 0, rekeyAt: 0, expiresAt: 0, reportedAt: t - 11,
        lastError: '', lastErrorAt: 0
      }
    },
    {
      // 已启用却从未被回报：多半是 gatewayId 指错或该网关的 baidi-ipsec 没起。
      // 旧界面下这条会显示成「未建立」，与「本来就没开」长得一模一样。
      id: 'site-wh', name: '武汉测试点', peer: '198.51.100.42', localSubnet: '10.10.0.0/16', remoteSubnet: '10.60.0.0/24',
      ikeVersion: 'IKEv2', auth: 'psk', suite: 'standard', gatewayId: 'gw-3', enabled: true,
      phase1: { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' },
      phase2: { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' },
      pfs: true, pqHybrid: false, hasPsk: true, pskFingerprint: '5e2af730', pskVersion: 1
    }
  ];
}

const sites = ref<IpsecSite[]>([]);

/* ── 对象库地址对象（供本端/对端网段引用，仅子网类：cidr/ip/range，排除 domain）── */
const subnetObjs = ref<AddrObject[]>([]);
function objLabel(o: AddrObject) { return `${o.name} · ${o.value}`; }
function refName(id?: string) { return subnetObjs.value.find((o) => o.id === id)?.name || ''; }

/* ── 时间与格式 ── */
function nowFn() { return Math.floor(Date.now() / 1000); }
const nowSec = ref(nowFn());
function fmtTs(ts: number) { return ts > 0 ? new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }) : '—'; }
function ageText(sec: number) {
  const s = Math.max(0, sec);
  if (s < 60) return `${s} 秒`;
  if (s < 3600) return `${Math.floor(s / 60)} 分`;
  return `${Math.floor(s / 3600)} 小时`;
}
function remainText(sec: number) {
  const s = Math.max(0, sec);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60;
  if (h > 0) return `${h}h${String(m).padStart(2, '0')}m`;
  if (m > 0) return `${m}m${String(ss).padStart(2, '0')}s`;
  return `${ss}s`;
}
function formatBytes(n: number): string {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}
function spiHex(n?: number) { return n ? '0x' + n.toString(16).padStart(8, '0') : '—'; }
function phText(p: IpsecPhase) { return `${p.enc} / ${p.hash} / ${p.dh}`; }
function tagStyle(color: string) { return { color, background: color + '14' }; }

/* ── 认证方式 ──
 * 本轮只有 PSK 是通的。cert/sm2cert 存量数据仍可能是这两个值，所以文案要明说
 * 「本轮未实现」，而不是渲染成一个看起来正常的标签。 */
function authText(auth: string) {
  return auth === 'psk' ? '预共享密钥' : auth === 'cert' ? '证书 · 未实现' : 'SM2 证书 · 未实现';
}
function authColor(auth: string) { return auth === 'psk' ? '#86909C' : '#FF7D00'; }
function authHint(auth: string) {
  return auth === 'psk' ? 'IKEv2 PSK 认证（RFC 7296 AUTH 方法 2）' : '本轮未实现证书认证，网关会在装载期拒绝这条站点并置为协商失败';
}

/* ── 配置期望 vs 实际协商结果 ──
 * ★这一格存在的唯一理由是抓「以为走了国密、实际降级成 AES」。因此宁可显示「无法比对」
 * 也绝不能给一个乐观的 ✓——假 ✓ 比不做还糟，它会把要抓的东西盖住。
 *
 * 判定方式不是整串相等（两边书写口径本就不同：配置写 group19、协商结果写 ECP256），
 * 而是「配置项的关键字必须集中出现在协商串的**同一个分段**里」。分段匹配是关键：
 * 若拿整串做包含判断，配置 AES256-GCM 会被 "AES128-GCM16/PRF-HMAC-SHA256/ECP256"
 * 里的那个 256（其实来自 SHA256）骗过去，正好放过要抓的降级。 */
const NEGO_KEYS: Record<string, string[]> = {
  'AES256-GCM': ['AES', '256', 'GCM'],
  'AES128-GCM': ['AES', '128', 'GCM'],
  'AES256-CBC': ['AES', '256', 'CBC'],
  'SM4-GCM': ['SM4', 'GCM'],
  'SM4-CBC': ['SM4', 'CBC'],
  SHA256: ['SHA', '256'],
  SM3: ['SM3'],
  group14: ['MODP', '2048'],
  group19: ['ECP', '256'],
  sm2p256: ['SM2']
};
type CmpVerdict = 'pending' | 'unknown' | 'match' | 'mismatch';
const CMP_ICON: Record<CmpVerdict, string> = { pending: '', unknown: '（无法比对）', match: '✓', mismatch: '⚠ 与配置不符' };
function comparePhase1(s: IpsecSite): { v: CmpVerdict; miss: string[] } {
  const nego = s.sa?.negotiatedProposal || '';
  if (!nego) return { v: 'pending', miss: [] };
  const slots = nego.split('/').map((x) => x.toUpperCase().replace(/[^A-Z0-9]/g, '')).filter(Boolean);
  const items = [s.phase1.enc, s.phase1.hash, s.phase1.dh];
  // 配置里有本表覆盖不到的写法（比如 group21）就直说无法比对，不猜
  if (items.some((x) => !NEGO_KEYS[x])) return { v: 'unknown', miss: items.filter((x) => !NEGO_KEYS[x]) };
  const miss = items.filter((x) => !slots.some((sl) => NEGO_KEYS[x].every((k) => sl.includes(k))));
  // 三项全对不上，更可能是网关的文案口径变了而不是三项全降级——这种情况报「无法比对」，
  // 免得每条站点都挂一个假警报，最后所有人都学会无视这一格
  if (miss.length === items.length) return { v: 'unknown', miss };
  return miss.length ? { v: 'mismatch', miss } : { v: 'match', miss: [] };
}

/* ── 装载期会被拒绝的配置 ── */
function unsupportedOf(s: { auth: string; pqHybrid: boolean; phase1: IpsecPhase; phase2: IpsecPhase }): string[] {
  const out: string[] = [];
  if (s.auth !== 'psk') out.push(`认证方式 ${s.auth}`);
  if (s.pqHybrid) out.push('后量子 ML-KEM 混合');
  const phases: [string, IpsecPhase][] = [['相一', s.phase1], ['相二', s.phase2]];
  for (const [tag, p] of phases) {
    if (algBad(ENC_OPTS, p.enc)) out.push(`${tag}加密 ${p.enc}`);
    if (algBad(HASH_OPTS, p.hash)) out.push(`${tag}哈希 ${p.hash}`);
    if (algBad(DH_OPTS, p.dh)) out.push(`${tag}DH ${p.dh}`);
  }
  return out;
}

/* ── 在途窗口（异步 toggle 的核心）──
 * busy[siteId] = 点击时刻。真协商不可能瞬时完成，点一下就翻状态是旧实现最直接的「假」。
 *
 * ★判定「还在途中」不能只看 sa.state === 'connecting'：心跳 15s 一跳，刚点完启用时
 * 拿到的 sa 还是**上一跳的旧快照**（多半是 down）。只看 state 的症状是：点了启用、
 * 界面立刻弹回「未建立」，运维以为功能坏了，其实只是还没到下一跳。
 * 所以要拿回报时刻和点击时刻比——只有比点击更新的回报才算数。 */
const busy = ref<Record<string, number>>({});
function markBusy(id: string) { busy.value = { ...busy.value, [id]: nowSec.value }; }
function clearBusy(id: string) { const m = { ...busy.value }; delete m[id]; busy.value = m; }

interface Row {
  s: IpsecSite;
  vs: ViewState;
  stale: boolean;     // 心跳断了：数字还在但已经不是当前值
  timedOut: boolean;  // 下发很久了还没等到新回报：多半网关没起
  cmp: { v: CmpVerdict; miss: string[] };
  unsupported: string[];
}
function decorate(s: IpsecSite): Row {
  const since = busy.value[s.id] ?? 0;
  const rep = s.sa?.reportedAt ?? 0;
  const waiting = since > 0 && rep <= since;              // 下发后还没等到新回报
  const timedOut = waiting && nowSec.value - since > PENDING_MAX_SEC;
  const vs: ViewState = waiting && !timedOut ? 'pending' : !s.sa ? 'unreported' : s.sa.state;
  // 降级演示没有网关心跳，新鲜度判定没有意义（横幅已标明是演示数据）
  const stale = live.value && !!s.sa && rep > 0 && nowSec.value - rep > STALE_SEC;
  return { s, vs, stale, timedOut, cmp: comparePhase1(s), unsupported: unsupportedOf(s) };
}
const decorated = computed<Row[]>(() => sites.value.map(decorate));

/* ── 站点清单关键词检索（拓扑总览不受影响，始终展示全部）── */
const kw = ref('');
const shownRows = computed(() => {
  const k = kw.value.trim().toLowerCase();
  if (!k) return decorated.value;
  return decorated.value.filter((r) =>
    [r.s.name, r.s.peer, r.s.localSubnet, r.s.remoteSubnet, r.s.gatewayId].some((f) => (f || '').toLowerCase().includes(k))
  );
});

/* ── 聚合统计：期望与实测分开数，两个数字不等本身就是信息 ── */
const enabledCount = computed(() => sites.value.filter((s) => s.enabled).length);
const upCount = computed(() => sites.value.filter((s) => s.sa?.state === 'up' || s.sa?.state === 'rekeying').length);
const failedCount = computed(() => sites.value.filter((s) => s.sa?.state === 'failed').length);
const silentCount = computed(() => decorated.value.filter((r) => r.s.enabled && (r.vs === 'unreported' || r.stale)).length);

/* ── SVG 椭圆布局 ──
 * 用椭圆而不是正圆：节点框宽 172、中心框宽 184，正圆半径 170 时左右两侧的节点会压到
 * 中心框上（站点一多就糊成一团）。横向拉开、纵向压扁既避开重叠，也不至于顶到底部图例。 */
const hubCx = 480;
const hubCy = 240;
const radiusX = 250;
const radiusY = 145;
function nodePos(i: number) {
  const n = sites.value.length || 1;
  const angle = (i / n) * Math.PI * 2 - Math.PI / 2;
  return { x: hubCx + radiusX * Math.cos(angle), y: hubCy + radiusY * Math.sin(angle) };
}

/* ── 剩余寿命 ── */
function lifePct(sa: IpsecSA): number {
  const total = sa.rekeyAt - sa.establishedAt;
  if (total <= 0) return 0;
  return Math.max(0, Math.min(1, (sa.rekeyAt - nowSec.value) / total));
}

/* ── 数据新鲜度 ──
 * 心跳 15s 一跳，界面必须把「这不是秒级实时」说出来；断跳后更要明说数字已经过期，
 * 否则一个停更的计数器和一个永不变化的种子常量在观感上没有任何区别。 */
function freshText(s: IpsecSite): string {
  if (!live.value) return '降级演示数据 · 非实测';
  const rep = s.sa?.reportedAt ?? 0;
  if (!rep) return '从未回报';
  const age = nowSec.value - rep;
  if (age > STALE_SEC) return `已 ${ageText(age)}未回报 · 数字已过期`;
  return `数据延迟 ≤${HEARTBEAT_SEC}s · ${ageText(age)}前更新`;
}

/* ── 表单 ── */
const formOpen = ref(false);
const editing = ref(false);
const form = reactive<IpsecSite>({
  id: '', name: '', peer: '', localSubnet: '', remoteSubnet: '',
  ikeVersion: 'IKEv2', auth: 'psk', suite: 'standard', gatewayId: '',
  phase1: { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' },
  phase2: { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' },
  pfs: true, pqHybrid: false, enabled: false
});
const formUnsupported = computed(() => unsupportedOf(form));

function applyDefaults(suite: 'standard' | 'gm') {
  if (suite === 'gm') {
    // 国密默认落在**本实现真的支持**的三件套上（SM4-GCM/SM3/sm2p256v1）。
    // 老默认值 group24 本实现不支持，配上去等于建一条永远红的站点。
    form.phase1 = { enc: 'SM4-GCM', hash: 'SM3', dh: 'sm2p256' };
    form.phase2 = { enc: 'SM4-GCM', hash: 'SM3', dh: 'sm2p256' };
  } else {
    form.phase1 = { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' };
    form.phase2 = { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' };
  }
}
function onSuiteChange(v: string | number | boolean) {
  applyDefaults(v === 'gm' ? 'gm' : 'standard');
}

function openCreate() {
  editing.value = false;
  form.id = ''; form.name = ''; form.peer = ''; form.localSubnet = ''; form.remoteSubnet = '';
  form.localRef = undefined; form.remoteRef = undefined; form.gatewayId = '';
  form.ikeVersion = 'IKEv2'; form.auth = 'psk'; form.suite = 'standard';
  form.pfs = true; form.pqHybrid = false;
  // 新建默认不启用：PSK 还没配就开始对外发 IKE，只会在对端日志里刷一串认证失败
  form.enabled = false;
  form.hasPsk = false; form.pskFingerprint = undefined; form.pskVersion = undefined;
  applyDefaults('standard');
  formOpen.value = true;
}
function openEdit(s: IpsecSite) {
  editing.value = true;
  form.id = s.id; form.name = s.name; form.peer = s.peer;
  form.localSubnet = s.localSubnet; form.remoteSubnet = s.remoteSubnet;
  form.localRef = s.localRef; form.remoteRef = s.remoteRef;
  form.ikeVersion = s.ikeVersion || 'IKEv2'; form.auth = s.auth; form.suite = s.suite;
  form.gatewayId = s.gatewayId || '';
  form.phase1 = { ...s.phase1 }; form.phase2 = { ...s.phase2 };
  form.pfs = s.pfs; form.pqHybrid = s.pqHybrid;
  form.enabled = s.enabled;
  form.hasPsk = s.hasPsk; form.pskFingerprint = s.pskFingerprint; form.pskVersion = s.pskVersion;
  formOpen.value = true;
}

/* ── 网段 ↔ 对象库引用联动 ── */
function pickLocalObj(id: string | undefined) {
  form.localRef = id || undefined;
  const o = subnetObjs.value.find((x) => x.id === id);
  if (o) form.localSubnet = o.value;
}
function pickRemoteObj(id: string | undefined) {
  form.remoteRef = id || undefined;
  const o = subnetObjs.value.find((x) => x.id === id);
  if (o) form.remoteSubnet = o.value;
}
// 手动编辑网段输入即视为脱离对象库引用
function onLocalSubnetInput() { form.localRef = undefined; }
function onRemoteSubnetInput() { form.remoteRef = undefined; }

async function save() {
  if (!live.value) { Message.warning('当前为降级演示，未连接后端，无法写入'); return; }
  if (!form.name || !form.peer) { Message.warning('站点名称与对端网关地址必填'); return; }
  saving.value = true;
  // 运行态字段一律不提交：sa 是网关权威，前端往回写就等于又给「控制面自说自话改状态」开了口子
  const payload = {
    id: form.id, name: form.name, peer: form.peer,
    localSubnet: form.localSubnet, remoteSubnet: form.remoteSubnet,
    ikeVersion: 'IKEv2', auth: form.auth, suite: form.suite,
    gatewayId: form.gatewayId || '',
    phase1: { ...form.phase1 }, phase2: { ...form.phase2 },
    pfs: form.pfs, pqHybrid: form.pqHybrid, enabled: form.enabled,
    localRef: form.localRef || undefined, remoteRef: form.remoteRef || undefined
  };
  try {
    await api('/ipsec', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    Message.success(`站点「${form.name}」已落库，网关下一跳（≤${HEARTBEAT_SEC}s）生效`);
    formOpen.value = false;
    await load();
  } catch (e) {
    // ★后端对站点 peer 的拒绝是**说得出原因**的（"peer 不能填域名，IKEv2 守护进程
    //   刻意不解析 DNS…"）。整句丢掉换成"请检查权限"，管理员会反复换写法去试，
    //   而那条站点会安静地永远 down——wave8 行动 17 专门为此改过后端文案。
    Message.error(`站点保存失败：${failReason(e)}`);
  } finally { saving.value = false; }
}

async function del(s: IpsecSite) {
  if (!live.value) { Message.warning('当前为降级演示，未连接后端，无法写入'); return; }
  try {
    await api(`/ipsec/${s.id}`, { method: 'DELETE' });
    clearBusy(s.id);
    Message.success(`站点「${s.name}」已删除`);
    await load();
  } catch (e) { Message.error(`站点删除失败：${failReason(e)}`); }
}

/* ── 启停：异步语义 ──
 * 点击只写「管理意图」，随后进入在途窗口并开始轮询，直到网关回报出结果为止。
 * ★绝不能再像旧实现那样点完就宣布「已建立 IPSec 隧道」——控制面根本没有能力知道
 * 隧道建没建起来，那句提示（连同同款审计记录）是在谎报一个从未发生的事实。 */
async function toggle(r: Row) {
  const s = r.s;
  if (!live.value) { Message.warning('当前为降级演示，未连接后端，无法写入'); return; }
  if (r.vs === 'pending') { Message.info('上一次下发还在途中，等网关回报后再操作'); return; }
  const next = !s.enabled;
  if (next && s.auth === 'psk' && !s.hasPsk) {
    Message.warning('该站点还没有 PSK：空密钥会被网关在装载期拒绝，请先设置');
    openPsk(s);
    return;
  }
  if (next && r.unsupported.length) {
    Message.warning(`站点「${s.name}」含本实现不支持的参数（${r.unsupported.join('、')}），启用后必然协商失败，请先在「编辑」里改掉`);
    return;
  }
  markBusy(s.id);
  try {
    // 带上目标值而不是靠服务端翻转：连点两次时两条请求的意图是明确的，不会互相抵消
    await api(`/ipsec/${s.id}/toggle`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: next })
    });
    Message.info(next
      ? `已下发启用意图，网关下一跳（≤${HEARTBEAT_SEC}s）开始 IKE 协商，结果看「实际状态」列`
      : '已下发停用意图，网关将拆除该站点的 SA');
    await load();
  } catch (e) {
    clearBusy(s.id);
    Message.error(`启停失败：${failReason(e)}`);
  }
}

/* ── PSK 设置（只写不读）── */
const pskOpen = ref(false);
const pskSite = ref<IpsecSite | null>(null);
const pskValue = ref('');
const pskSaving = ref(false);
function openPsk(s: IpsecSite) {
  pskSite.value = s;
  pskValue.value = '';
  pskOpen.value = true;
}
function genPsk() {
  // ★必须用 crypto.getRandomValues，不能用 Math.random：IKEv2 的 PSK 认证在弱口令下
  // 可被离线字典攻击（AUTH 载荷就是 PSK 的 PRF 输出，抓一次握手即可离线穷举）。
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  pskValue.value = btoa(Array.from(b, (x) => String.fromCharCode(x)).join('')).replace(/=+$/, '');
}
async function savePsk() {
  const s = pskSite.value;
  if (!s) return;
  if (!live.value) { Message.warning('当前为降级演示，未连接后端，无法写入'); return; }
  const v = pskValue.value.trim();
  if (v.length < 20) { Message.warning('PSK 至少 20 字符（建议直接用随机生成），过短的口令可被离线字典攻击'); return; }
  pskSaving.value = true;
  try {
    const r = await api<IpsecPskResp>(`/ipsec/${s.id}/psk`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ psk: v })
    });
    Message.success(`站点「${s.name}」PSK 已写入${r?.version ? ` · v${r.version}` : ''}${r?.fingerprint ? ` · 指纹 ${r.fingerprint}` : ''}，请把同一把密钥配到对端`);
    pskValue.value = ''; // 原文只在这个输入框里存在过，提交后立即抹掉
    pskOpen.value = false;
    await load();
  } catch (e) {
    if (failStatus(e) === 404) Message.error('控制面没有 PSK 端点：该版本 baidi-control 尚未支持 IPSec 密钥下发');
    else if (failStatus(e) === 403) Message.error(failReason(e));
    else Message.error('写入失败，请检查后端连接');
  } finally { pskSaving.value = false; }
}

/* ── 运行态抽屉：按 id 取行，轮询刷新时抽屉里的数字会跟着走 ── */
const detailId = ref('');
const detailRow = computed(() => decorated.value.find((r) => r.s.id === detailId.value) ?? null);
const detailOpen = computed({
  get: () => !!detailRow.value,
  set: (v: boolean) => { if (!v) detailId.value = ''; }
});

/* ── 加载与轮询 ──
 * 只在「有站点在途」时以 POLL_SEC 节拍轮询，收敛后自动停：常开轮询白白给控制面加压，
 * 而旧写法（toggle 完立刻 load 一次就收工）则永远只能看到那一跳的旧快照。 */
const polling = computed(() => decorated.value.some((r) => r.vs === 'pending' || r.vs === 'connecting' || r.vs === 'rekeying'));
let ticker: number | undefined;
let lastPoll = 0;

// 演示数据只生成一次并缓存：每次重试都重算一遍的话，里面的 rekeyAt 会跟着「现在」一起往后跑，
// 倒计时就永远倒不下去——那恰好复刻了这次要消灭的东西（一个不会变化的假数字）。
let demoCache: IpsecSite[] | null = null;
function demoSites(): IpsecSite[] {
  if (!demoCache) demoCache = mockSites();
  return demoCache;
}

async function load() {
  try {
    const r = await api<IpsecResp>('/ipsec');
    sites.value = r.sites ?? [];
    live.value = true;
    // 已经等到「比点击更新」的回报的站点，脱离在途窗口
    for (const s of sites.value) {
      const since = busy.value[s.id];
      if (since && (s.sa?.reportedAt ?? 0) > since) clearBusy(s.id);
    }
  } catch {
    sites.value = demoSites();
    live.value = false;
    busy.value = {};
  }
}

async function loadObjects() {
  try {
    const b = await api<ObjectBundle>('/objects');
    // 仅保留可作网段的地址对象（cidr/ip/range），排除 domain
    subnetObjs.value = (b.addrs || []).filter((o) => o.kind === 'cidr' || o.kind === 'ip' || o.kind === 'range');
  } catch { subnetObjs.value = []; }
}

function onTick() {
  nowSec.value = nowFn();
  // 已连后端：只在有站点在途时快节拍轮询，收敛后自动停，不给控制面白加压。
  // 降级演示（后端不通）：按心跳节拍慢速重试，后端恢复后界面能自己回到实时态，不用手动刷新。
  if (live.value && !polling.value) return;
  const gap = live.value ? POLL_SEC : HEARTBEAT_SEC;
  if (nowSec.value - lastPoll >= gap) { lastPoll = nowSec.value; load(); }
}

onMounted(() => {
  lastPoll = nowFn(); // 否则首个 tick 会紧跟着首次 load 再打一次，白白多一发请求
  load();
  loadObjects();
  // 1s 心跳只驱动倒计时与「N 秒前」，真正的拉取由 onTick 里的节拍闸控制
  ticker = window.setInterval(onTick, 1000);
});
onUnmounted(() => { if (ticker) window.clearInterval(ticker); });
</script>

<style scoped>
/* 诚实边界提示条 */
.bd-note { display: flex; gap: 10px; align-items: flex-start; background: var(--bd-primary-1); border: 1px solid #BEDAFF; border-radius: var(--bd-radius); padding: 11px 14px; margin-bottom: 16px; font-size: 12.5px; line-height: 1.7; color: var(--bd-t2); }
.bd-note__ic { color: var(--bd-primary); font-size: 15px; flex: none; margin-top: 3px; }
.bd-note b { color: var(--bd-t1); font-weight: 600; }

/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab em { font-style: normal; color: var(--bd-t3); margin-left: 4px; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }

/* 聚合统计 */
.bd-stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-bottom: 16px; }
.bd-stat { padding: 16px 18px; }
.bd-stat__n { font-size: 28px; font-weight: 700; color: var(--bd-t1); line-height: 1.1; }
.bd-stat__c { margin-top: 6px; font-size: 12.5px; color: var(--bd-t3); }

/* 拓扑卡 */
.bd-topo { padding: 16px 18px; }
.bd-topo svg { display: block; }

/* 搜索框输入 */
.bd-searchbox__in { border: none; outline: none; background: transparent; flex: 1; min-width: 0; font-size: 13px; color: var(--bd-t1); }
.bd-searchbox__in::placeholder { color: var(--bd-t3); }
.bd-polling { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; color: var(--bd-primary); }

/* 降级演示下禁用写入按钮 */
.bd-btn:disabled { opacity: .5; cursor: not-allowed; }

/* 行内辅助文字 */
.bd-sub2 { margin-top: 5px; display: flex; flex-wrap: wrap; gap: 4px; }
.bd-sub3 { font-size: 11px; color: var(--bd-t3); line-height: 1.6; margin-top: 2px; }
.bd-sub3.warn, .bd-warn { color: var(--bd-warning, #FF7D00); font-size: 11px; line-height: 1.6; margin-top: 2px; }
.bd-err { color: var(--bd-danger, #F53F3F); font-size: 11px; line-height: 1.6; margin-top: 2px; }
.bd-dim { color: var(--bd-t3); }
.bd-dash { color: var(--bd-t3); }
.bd-flow { font-size: 11.5px; line-height: 1.7; }

/* 操作列：链接多，窄列里靠 margin 排会散成一竖条，用 flex 收成两行 */
.bd-ops { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 4px 12px; min-width: 108px; }

/* 期望态 pill */
.bd-pill { display: inline-block; font-size: 11.5px; padding: 2px 9px; border-radius: 10px; font-weight: 500; }
.bd-pill.on { color: #165DFF; background: #E8F3FF; }
.bd-pill.off { color: #86909C; background: var(--bd-fill-2); }

/* 失败原因（一级视图） */
.bd-fail { margin-top: 4px; }
.bd-fail__msg { font-size: 11.5px; color: var(--bd-danger, #F53F3F); line-height: 1.6; margin-top: 3px; max-width: 260px; display: -webkit-box; -webkit-line-clamp: 2; line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }

/* 套件对比 */
.bd-cmp { font-size: 11px; line-height: 1.7; color: var(--bd-t3); }
.bd-cmp .v-match { color: #00B42A; }
.bd-cmp .v-mismatch { color: var(--bd-danger, #F53F3F); font-weight: 600; }
.bd-cmp .v-unknown { color: var(--bd-t3); }
.bd-cmp .v-pending { color: var(--bd-t3); }
.v-match { color: #00B42A; }
.v-mismatch { color: var(--bd-danger, #F53F3F); font-weight: 600; }

/* SA 剩余寿命 */
.bd-life { font-family: ui-monospace, monospace; font-size: 13px; font-weight: 600; color: var(--bd-t1); margin-bottom: 4px; }
.bd-life.soon { color: var(--bd-warning, #FF7D00); }

/* 抽屉 */
.bd-dsec { font-size: 12.5px; font-weight: 600; color: var(--bd-t1); margin: 18px 0 8px; padding-bottom: 6px; border-bottom: 1px solid var(--bd-fill-2); }
.bd-dsec:first-child { margin-top: 0; }
.bd-kv { display: flex; justify-content: space-between; gap: 12px; font-size: 12.5px; padding: 5px 0; }
.bd-kv span { color: var(--bd-t3); flex: none; }
.bd-kv b { color: var(--bd-t1); font-weight: 500; text-align: right; word-break: break-all; }
.bd-dhint { font-size: 11.5px; color: var(--bd-t3); line-height: 1.7; margin-top: 6px; }

/* PSK */
.bd-pskcur { background: var(--bd-fill-1); border-radius: 6px; padding: 10px 12px; margin-bottom: 14px; font-size: 12.5px; color: var(--bd-t2); }
.bd-pskacts { display: flex; align-items: center; gap: 10px; margin-top: 8px; }

/* 表单 */
.bd-formwarn { display: flex; gap: 8px; align-items: flex-start; background: #FFF7E8; border: 1px solid #FFCF8B; border-radius: 6px; padding: 10px 12px; margin-bottom: 14px; font-size: 12.5px; color: #7A4B00; line-height: 1.7; }
.bd-uform__group { font-size: 13px; font-weight: 600; color: var(--bd-t1); margin: 16px 0 10px; padding-bottom: 6px; border-bottom: 1px solid var(--bd-fill-2); }
.bd-uform__group:first-child { margin-top: 0; }
.bd-uform__row { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.bd-uform__row3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; }
.bd-uform__f { margin-bottom: 12px; }
.bd-uform__f label { display: block; font-size: 12.5px; color: var(--bd-t2); margin-bottom: 6px; }
.bd-uform__f .req { color: var(--bd-danger); margin-left: 2px; font-style: normal; }
.bd-uform__sw { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.bd-uform__sw label { margin-bottom: 0; }
.bd-uform__sw label .bd-sub3 { display: block; margin-top: 2px; } /* 说明另起一行，别和标题挤成一句 */
.bd-uform__note { font-size: 12px; color: var(--bd-t3); margin: -2px 0 6px; line-height: 1.7; }
.bd-uform__objpick { margin-bottom: 6px; }
.bd-uform__refhint { font-size: 11.5px; color: var(--bd-t3); margin-top: 4px; line-height: 1.6; }
.bd-empty { text-align: center; color: var(--bd-t3); padding: 28px 0; }
</style>
