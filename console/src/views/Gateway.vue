<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">网关与隐身</div>
        <div class="bd-page__sub">已注册数据面网关 · SPA 服务隐身：先认证后连接（隐身是否真的生效见逐台实测回执）</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '后端未连接' }}</a-tag>
        <!-- ★「最后心跳 N 秒前」是相对时间，此前定格在渲染那一刻：页面开着不动，
             一台刚掉线的网关会一直显示「12 秒前」。现在每 15s 自动重拉（与网关心跳同频），
             并把数据时间写出来——不写的话，自动刷新与卡死在页面上仍然分不出来。 -->
        <span v-if="fetchedAt" class="bd-gwts">数据时间 {{ fetchedAt }} · 每 15s 自动刷新</span>
        <a-button @click="load"><template #icon><icon-refresh /></template>刷新</a-button>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'topo' }" @click="tab = 'topo'">拓扑总览</span>
      <span class="bd-tab" :class="{ on: tab === 'spa' }" @click="tab = 'spa'">SPA 服务隐身</span>
      <span class="bd-tab" :class="{ on: tab === 'node' }" @click="tab = 'node'">网关节点</span>
      <span class="bd-tab" :class="{ on: tab === 'cert' }" @click="tab = 'cert'; loadCerts()">机器身份 · mTLS 证书</span>
    </div>

    <!-- 空态：一台网关都没注册。整页不画任何拓扑——
         此前这里会渲染「华东/华南出口」四台编造节点，运维对着不存在的拓扑排查不了任何问题。
         ★证书页不受这道空态影响：**先签证书、后起网关**，没有网关恰恰是最需要签证书的时候。 -->
    <div v-if="!nodes.length && tab !== 'cert'" class="bd-card bd-empty">
      <icon-exclamation-circle-fill class="bd-empty__ic" />
      <div class="bd-empty__t">尚无数据面网关经 mTLS 注册</div>
      <div class="bd-empty__d">
        本页只展示注册心跳上报的真实网关。以 <code>-control</code> 指向本控制面、并带上
        <code>-mtls-cert/-mtls-key/-mtls-ca</code> 启动 <code>baidi-gateway</code>，注册后此处才有事实可报。
      </div>
      <div class="bd-empty__d">
        控制面自身可独立运行；没有网关不代表控制面异常，但也意味着<b>此刻没有任何隧道接入能力</b>。
      </div>
    </div>

    <template v-if="nodes.length">
      <!-- ============ 拓扑总览 ============ -->
      <div v-show="tab === 'topo'">
        <div class="bd-card bd-topo">
          <svg :viewBox="`0 0 960 ${svgH}`" width="100%" preserveAspectRatio="xMidYMid meet"
               font-family="-apple-system, 'PingFang SC', 'Segoe UI', sans-serif">
            <!-- 控制中心 -->
            <g>
              <rect x="360" y="14" width="240" height="52" rx="10" fill="#F2F7FF" stroke="#BEDAFF" />
              <circle cx="392" cy="40" r="9" fill="#165DFF" />
              <text x="412" y="36" font-size="14" font-weight="600" fill="#1D2129">控制中心 · 策略大脑</text>
              <text x="412" y="53" font-size="12" fill="#86909C">认证决策 / 策略下发 / 敲门令牌签发</text>
            </g>

            <!-- 访问者 -->
            <g>
              <rect x="24" y="184" width="156" height="92" rx="12" fill="#F7F8FA" stroke="#E5E6EB" />
              <text x="102" y="214" font-size="14" font-weight="600" fill="#1D2129" text-anchor="middle">访问者 / 客户端</text>
              <text x="102" y="240" font-size="22" font-weight="700" fill="#165DFF" text-anchor="middle">{{ bundle.sessions }}</text>
              <text x="102" y="261" font-size="12" fill="#86909C" text-anchor="middle">在线网关上报的会话</text>
            </g>

            <!-- 受保护业务 -->
            <g>
              <rect x="800" y="176" width="136" height="108" rx="12" fill="#F7F8FA" stroke="#E5E6EB" />
              <text x="868" y="206" font-size="14" font-weight="600" fill="#1D2129" text-anchor="middle">受保护业务</text>
              <text x="868" y="238" font-size="24" font-weight="700" fill="#1D2129" text-anchor="middle">{{ bundle.total ? totalTunnels : 0 }}</text>
              <text x="868" y="258" font-size="12" fill="#86909C" text-anchor="middle">活跃隧道连接</text>
            </g>

            <!-- 网关节点 -->
            <g v-for="(n, i) in nodes" :key="n.id">
              <path :d="`M180 230 C 280 230, 280 ${nodeY(i) + nodeH / 2}, 340 ${nodeY(i) + nodeH / 2}`"
                    fill="none" :stroke="statusColor(n.online)" stroke-width="2" />
              <path :d="`M480 66 C 480 110, 480 ${nodeY(i) - 14}, 480 ${nodeY(i)}`"
                    fill="none" stroke="#BEDAFF" stroke-width="1.5" stroke-dasharray="4 4" />
              <path :d="`M620 ${nodeY(i) + nodeH / 2} C 720 ${nodeY(i) + nodeH / 2}, 720 230, 800 230`"
                    fill="none" :stroke="statusColor(n.online)" stroke-width="2" />

              <rect x="340" :y="nodeY(i)" width="280" :height="nodeH" rx="10" fill="#FFFFFF"
                    :stroke="statusColor(n.online)" stroke-width="1.5" />
              <circle cx="358" :cy="nodeY(i) + 22" r="5" :fill="statusColor(n.online)" />
              <text x="372" :y="nodeY(i) + 26" font-size="14" font-weight="600" fill="#1D2129">{{ n.id }}</text>
              <text x="608" :y="nodeY(i) + 26" font-size="11" :fill="statusColor(n.online)" text-anchor="end"
                    font-weight="600">{{ n.online ? '在线' : '心跳超时' }}</text>
              <text x="372" :y="nodeY(i) + 48" font-size="11" fill="#86909C" font-family="ui-monospace, monospace">
                敲门口 {{ n.spa || '—' }} · 隧道口 {{ n.proxy || '—' }}
              </text>
              <text x="372" :y="nodeY(i) + 66" font-size="11" fill="#86909C">
                会话 {{ n.sessions }} · 隧道 {{ n.tunnels }} · 放行源 {{ n.clients }}
              </text>
              <text x="608" :y="nodeY(i) + 66" font-size="11" fill="#86909C" text-anchor="end">{{ n.version || '版本未上报' }}</text>
            </g>

            <text x="500" y="100" font-size="11" fill="#86909C">策略下发（控制面）</text>

            <g :transform="`translate(24, ${svgH - 30})`">
              <text x="0" y="12" font-size="12" font-weight="600" fill="#4E5969">图例</text>
              <line x1="56" y1="8" x2="84" y2="8" stroke="#86909C" stroke-width="2" />
              <text x="92" y="12" font-size="12" fill="#86909C">数据面（实线）</text>
              <line x1="220" y1="8" x2="248" y2="8" stroke="#BEDAFF" stroke-width="1.5" stroke-dasharray="4 4" />
              <text x="256" y="12" font-size="12" fill="#86909C">控制面（虚线）</text>
              <circle cx="392" cy="8" r="5" fill="#00B42A" /><text x="404" y="12" font-size="12" fill="#86909C">在线</text>
              <circle cx="462" cy="8" r="5" fill="#F53F3F" /><text x="474" y="12" font-size="12" fill="#86909C">心跳超时</text>
            </g>
          </svg>
        </div>
      </div>

      <!-- ============ SPA 服务隐身 ============ -->
      <div v-show="tab === 'spa'">
        <div class="bd-spa">
          <div class="bd-card bd-spacard">
            <div class="bd-section-title">服务隐身状态</div>
            <div class="bd-spa__meta">
              <div class="bd-kv"><span>认证模式</span><b>先认证后连接：SPA 敲门 + mTLS 机器身份 + 证书指纹钉扎</b></div>
              <div class="bd-kv"><span>敲门令牌</span>
                <b>控制面签发的一次性短时效令牌 · 有效期 {{ bundle.knockTokenTtlSec }} 秒</b>
              </div>
              <div class="bd-kv"><span>在线网关</span>
                <b>{{ bundle.online }} / {{ bundle.total }} 台（判据：{{ bundle.onlineWindowSec }} 秒内有心跳）</b>
              </div>
            </div>

            <div class="bd-spa__ports">
              <div class="bd-spa__portshead">
                各网关上报的监听口（未敲门时会不会被内核丢弃，见下方逐台回执）
              </div>
              <div class="bd-spa__portslist">
                <span v-for="n in nodes" :key="n.id" class="bd-tg bd-port">
                  {{ n.id }} · 敲门 {{ n.spa || '—' }} · 隧道 {{ n.proxy || '—' }}
                </span>
              </div>
              <!-- ★这段注记不是免责声明，是口径说明：控制面只转述网关上报的事实，
                   "端口在公网上到底可不可见"要从外部实测，白帝没有做这件事。
                   原实现里那个恒为 true 的「已隐身」开关就是在替一台可能压根没配
                   防火墙规则的网关打包票。 -->
              <div class="bd-spa__note">
                控制面不从外部实测端口可见性：以上为网关自报的监听地址。
                <b>但「内核规则集装没装、保护的是哪个端口」网关自己知道</b>，已随心跳上报，见下方逐台回执。
                最终确认仍请从外网侧扫描（未敲门时应表现为超时/filtered 而非拒绝或握手成功）。
              </div>
            </div>
          </div>

          <!-- 隐身实测回执（wave8 行动 7）。文案全部由后端下发：这是安全结论，
               前端自己编就会与后端实际判定脱节（与 Nat.vue 的 warnings 同纪律）。 -->
          <div class="bd-section-title" style="margin-top: 22px">
            内核态隐身 · 逐台实测回执
            <span class="bd-stealth__count">{{ bundle.stealthArmed }} / {{ bundle.stealth.length }} 台生效</span>
          </div>
          <div v-for="(w, i) in bundle.stealthWarnings" :key="'sw' + i" class="bd-stealthwarn">
            <icon-exclamation-circle-fill /><span>{{ w }}</span>
          </div>
          <div v-if="!bundle.stealth.length" class="bd-spa__note">无在线网关，隐身状态无从判定。</div>
          <div v-for="rc in bundle.stealth" :key="rc.gatewayId" class="bd-card bd-stealth">
            <div class="bd-stealth__h">
              <b>{{ rc.gatewayId }}</b>
              <span class="bd-tg" :class="stealthTagClass(rc.status)">{{ stealthLabel(rc.status) }}</span>
              <!-- 管理意图与实测态分列：一列同时表达"想开"和"真的开着"正是被批判的形态。 -->
              <span class="bd-stealth__intent">-pf {{ triText(rc.wanted, '已开启', '未开启') }}</span>
            </div>
            <div class="bd-stealth__sum">{{ rc.summary }}</div>
            <div class="bd-stealth__scan"><b>攻击者视角：</b>{{ rc.scannerView }}</div>
            <div class="bd-stealth__meta">
              后端 {{ rc.backend || '—' }} · {{ triText(rc.root, 'root', '非 root') }} ·
              隧道口 {{ rc.proxyAddr || '—' }} ·
              规则集保护端口 {{ rc.guardedPort ?? '不可判定' }}
            </div>
          </div>

          <div class="bd-section-title" style="margin-top: 22px">隐身效果 · 未装专属客户端 vs 已装客户端</div>
          <div class="bd-cmp">
            <div class="bd-card bd-cmp__c bd-cmp__c--bad">
              <div class="bd-cmp__h"><icon-close-circle-fill class="bd-cmp__ic bad" />未装专属客户端</div>
              <!-- ★这四条此前是写死的断言。它们只有在**内核态隐身实测生效**时才成立；
                   参考部署默认不开 -pf，那时未敲门的连接会先完成 TCP 三次握手再被
                   用户态断开（proxy.go 的 accept-then-close），nmap 判 open——
                   「握手后被断开」与「等同于不存在」是两种安全等级，不能用同一段文案。 -->
              <ul v-if="allArmed" class="bd-cmp__list">
                <li><icon-info-circle />端口扫描全程超时，<b>无任何端口可探测</b></li>
                <li><icon-info-circle />未通过 SPA 敲门，网关在<b>内核态丢弃</b>所有报文</li>
                <li><icon-info-circle />无法建立 TCP 连接，<b>无法接入</b>任何业务</li>
                <li><icon-info-circle />在攻击者视角下，网关与业务<b>等同于不存在</b></li>
              </ul>
              <ul v-else class="bd-cmp__list">
                <!-- 敞着 L7 口时，「隐身没生效」与「隐身生效了但另有一个口是敞的」
                     是两种不同的处境，处置也不同（前者去查 nft 规则，后者是取舍问题）。 -->
                <li v-if="webExposed > 0">
                  <icon-info-circle />有 <b>{{ webExposed }}</b> 台网关开着<b>七层 Web 代理</b>，该端口<b>不受 SPA 隐身保护</b>
                  <span class="bd-cmp__ep">{{ (bundle.webEndpoints ?? []).join('、') }}</span>
                </li>
                <li v-else><icon-info-circle />当前<b>未确认内核态隐身生效</b>（{{ bundle.stealthArmed }} / {{ bundle.stealth.length }} 台）</li>
                <li><icon-info-circle />未敲门的 TCP 连接会<b>先完成三次握手</b>，再由用户态立即断开</li>
                <li><icon-info-circle />端口对扫描器表现为 <b>open</b> 而非 filtered：能确认这里有服务在监听</li>
                <li><icon-info-circle />业务仍<b>接入不了</b>（无 SPA 授权即断连），但网关本身并未隐身</li>
              </ul>
              <div class="bd-cmp__foot bad">
                {{ allArmed
                  ? '攻击面 = 0 · 先认证后连接'
                  : (webExposed > 0
                    ? '七层入口可见 · 隧道口按实测态 —— B/S 免客户端与端口隐身是一组取舍，不能同时成立'
                    : '端口可见 · 业务不可达 —— 先认证后连接成立，隐身尚未成立') }}
              </div>
            </div>

            <div class="bd-card bd-cmp__c bd-cmp__c--good">
              <div class="bd-cmp__h"><icon-check-circle-fill class="bd-cmp__ic good" />已装专属客户端</div>
              <ul class="bd-cmp__list">
                <li><icon-check-circle-fill class="li-ok" />客户端先向控制面换取<b>一次性敲门令牌</b>（受账号状态/终端合规闸约束）</li>
                <li><icon-check-circle-fill class="li-ok" />网关校验通过后<b>按需短暂放行</b>该源地址</li>
                <li><icon-check-circle-fill class="li-ok" />仅放行<b>本人已授权资源</b>，其余仍不可见</li>
                <li><icon-check-circle-fill class="li-ok" />放行窗口到期<b>立即重新隐身</b></li>
              </ul>
              <div class="bd-cmp__foot good">认证通过 · 最小化按需暴露</div>
            </div>
          </div>
        </div>
      </div>

      <!-- ============ 网关节点 ============ -->
      <div v-show="tab === 'node'">
        <div class="bd-card">
          <table class="bd-table">
            <thead>
              <tr>
                <!-- ★「对外接入地址」与「敲门口/隧道口」是两回事：后者是网关自报的**监听**地址
                     （默认 ':18201' 不带 host），前者才是客户端真正会去拨的地址。
                     没登记时剖面只能拿全局兜底去猜，症状是「显示在线却连不上」。 -->
                <th>网关</th><th>对外接入地址</th><th>敲门口</th><th>隧道口</th><th>状态</th>
                <th>会话</th><th>隧道</th><th>放行源</th><th>版本</th><th>时钟偏差</th><th>运行时长</th><th>最后心跳</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="n in nodes" :key="n.id">
                <td><b style="color: var(--bd-t1); font-weight: 500">{{ n.id }}</b></td>
                <td>
                  <template v-if="n.accessConfigured">
                    <div v-if="n.lanHost" class="bd-mono bd-acc"><i>内网</i>{{ n.lanHost }}</div>
                    <div v-if="n.wanHost" class="bd-mono bd-acc"><i>互联网</i>{{ n.wanHost }}</div>
                  </template>
                  <span v-else class="bd-acc__none" title="未登记时客户端拿到的是全局兜底地址（多为 127.0.0.1），会拨号超时——而这一页仍显示在线">
                    <icon-exclamation-circle-fill />未登记
                  </span>
                  <button type="button" class="bd-link bd-acc__edit" @click="openAccess(n)">编辑</button>
                </td>
                <td><span class="bd-mono">{{ n.spa || '—' }}</span></td>
                <td><span class="bd-mono">{{ n.proxy || '—' }}</span></td>
                <td>
                  <span class="bd-st">
                    <span class="d" :style="{ background: statusColor(n.online) }" />{{ n.online ? '在线' : '心跳超时' }}
                  </span>
                </td>
                <td>{{ n.sessions }}</td>
                <td>{{ n.tunnels }}</td>
                <td>{{ n.clients }}</td>
                <!-- 旧网关不上报版本：显示 — 而不是猜一个 -->
                <td><span class="bd-mono">{{ n.version || '—' }}</span></td>
                <!-- 时钟偏差三态：null=未上报（不可判定，绝不显示 0）；超 10s 标黄提醒。
                     敲门令牌是控制面签、网关验的，这一列漂过令牌有效期时敲门全灭且无报错。 -->
                <td>
                  <span v-if="n.skewSec === null || n.skewSec === undefined" style="color: var(--bd-t3)">未上报</span>
                  <span v-else :style="{ color: Math.abs(n.skewSec) > 10 ? 'var(--bd-warning, #FF7D00)' : 'var(--bd-t2)' }" class="bd-mono">
                    {{ n.skewSec > 0 ? '+' : '' }}{{ n.skewSec }}s
                  </span>
                </td>
                <td>{{ humanUptime(n.uptime) }}</td>
                <td>{{ sinceText(n.lastSeen) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <!-- ============ 机器身份 · mTLS 证书 ============
         ★后端三个端点（签发 / 清单 / 吊销）一直都在，控制台此前**一个入口都没有**：
         网关的机器身份只能用 curl 管，而"吊销"是一台网关失陷时唯一的即刻处置手段
         （指纹白名单是执行点，且吊销会把它从下发给终端的落点清单里一并摘掉）。 -->
    <div v-show="tab === 'cert'">
      <div class="bd-card bd-certnote">
        <icon-info-circle class="bd-certnote__ic" />
        <div>
          网关的机器身份<b>只有这一条路径</b>：控制面内部 CA 签发的 mTLS 客户端证书。
          网关带 <code>-mtls-cert/-mtls-key/-mtls-ca</code> 启动后才能调控制面拉策略；
          配了 <code>-control</code> 却没配证书会<b>直接拒绝启动</b>。
          <br>
          吊销<b>即刻生效</b>（指纹白名单就是执行点），并会把该网关从下发给终端的落点清单里摘掉——
          客户端下一次拉剖面即故障转移到其它落点。
        </div>
      </div>

      <div v-if="certs.caEnabled === false" class="bd-card bd-certwarn">
        <icon-exclamation-circle-fill />
        <span>控制面未启用内部 CA（未配置 <code>BAIDI_PKI_DIR</code>）：签发端点会返回 503。请先配置后重启控制面。</span>
      </div>

      <div class="bd-tablecard">
        <div class="bd-toolbar">
          <div class="bd-searchbox" style="width: 260px">
            <icon-search />
            <input v-model="certKw" class="bd-searchbox__in" placeholder="按网关 id / 指纹搜索" />
          </div>
          <div style="flex: 1" />
          <span class="bd-toolbar__c">共 {{ certs.certs.length }} 张 · 有效 {{ validCertCount }}</span>
          <a-button size="small" @click="loadCerts"><template #icon><icon-refresh /></template>刷新</a-button>
          <a-button type="primary" size="small" :disabled="certs.caEnabled === false" @click="openIssue">
            <template #icon><icon-plus /></template>签发证书
          </a-button>
        </div>

        <table class="bd-table">
          <thead>
            <tr>
              <th>网关 id（证书 CN）</th>
              <th style="width: 230px">指纹（SHA-256）</th>
              <th style="width: 150px">签发时间</th>
              <th style="width: 150px">有效期至</th>
              <th style="width: 150px">状态</th>
              <th class="r" style="width: 90px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in shownCerts" :key="c.fingerprint" :class="{ 'bd-row--off': c.revoked }">
              <td>
                <b>{{ c.gatewayId }}</b>
                <!-- ipsec- 前缀是组网网关的分权判据，标出来免得被当成普通隧道网关 -->
                <div v-if="c.gatewayId.startsWith('ipsec-')" class="bd-cellsub">站点组网网关（ipsec- 前缀）</div>
              </td>
              <td>
                <span class="bd-mono bd-fp" :title="c.fingerprint">{{ c.fingerprint.slice(0, 24) }}…</span>
                <span class="bd-link" style="margin-left: 8px" @click="copyText(c.fingerprint, '指纹')">复制</span>
              </td>
              <td class="bd-mono">{{ c.issuedAt || '—' }}</td>
              <td class="bd-mono">{{ c.notAfter || '—' }}</td>
              <td>
                <span class="bd-tg" :style="tagStyle(certStateColor(c))">{{ certStateText(c) }}</span>
                <div v-if="c.revoked && c.revokeReason" class="bd-cellsub">{{ c.revokeReason }}</div>
              </td>
              <td class="r">
                <span v-if="!c.revoked" class="bd-link bd-link--danger" @click="askRevoke(c)">吊销</span>
                <span v-else class="bd-anyt">已吊销</span>
              </td>
            </tr>
            <tr v-if="!shownCerts.length">
              <td colspan="6" class="bd-empty">
                <template v-if="certs.certs.length">没有匹配「{{ certKw.trim() }}」的证书（共 {{ certs.certs.length }} 张）</template>
                <template v-else-if="certErr">证书清单读取失败：{{ certErr }}</template>
                <template v-else>尚未签发任何网关证书。点右上「签发证书」为第一台网关建立机器身份。</template>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 签发弹窗 -->
    <a-modal v-model:visible="issue.open" title="签发网关 mTLS 客户端证书" :width="issue.result ? 640 : 480"
             :footer="false" @close="closeIssue">
      <template v-if="!issue.result">
        <div class="bd-accnote">
          证书的 <b>CN 就是网关 id</b>：网关启动时用它注册，控制面按 CN 识别这台机器。
          填一个已存在的 id = 为同一台网关换证（旧证需另行吊销，不会自动失效）。
        </div>
        <div class="bd-accfld">
          <label>网关 id</label>
          <a-input v-model="issue.id" placeholder="如 gw-hq-1；站点组网网关须以 ipsec- 开头"
                   allow-clear @press-enter="doIssue" />
          <span class="bd-accfld__d">
            <code>standby-</code> 开头会被后端拒绝：那是温备节点的保留命名空间，
            凭它能拉走整套信任材料，只能在主机上离线签发。
          </span>
        </div>
        <div v-if="issue.err" class="bd-accerr"><icon-close-circle-fill />{{ issue.err }}</div>
        <div class="bd-wfoot">
          <a-button @click="issue.open = false">取消</a-button>
          <div style="flex: 1" />
          <a-button type="primary" :loading="issue.busy" @click="doIssue">签发</a-button>
        </div>
      </template>

      <template v-else>
        <!-- ★私钥只在这一次应答里出现，控制面不留副本。这句话必须排在最前面，
             而不是塞在页脚：关掉弹窗之后只能重签一张。 -->
        <div class="bd-certonce">
          <icon-exclamation-circle-fill />
          <div>
            <b>私钥只显示这一次。</b>控制面不保存它——关掉本窗口后无法再取回，只能重新签发一张新证书。
            请现在就把三个文件保存到网关机器上。
          </div>
        </div>
        <div class="bd-accnote">
          网关 <b>{{ issue.result.gatewayId }}</b> · 指纹
          <span class="bd-mono">{{ issue.result.fingerprint.slice(0, 24) }}…</span> ·
          有效期至 <span class="bd-mono">{{ issue.result.notAfter }}</span>
        </div>
        <div v-for="f in issuedFiles" :key="f.name" class="bd-pemrow">
          <div class="bd-pemrow__h">
            <b>{{ f.name }}</b><span>{{ f.desc }}</span>
            <div style="flex: 1" />
            <span class="bd-link" @click="copyText(f.body, f.name)">复制</span>
            <span class="bd-link" @click="downloadText(f.name, f.body)">下载</span>
          </div>
          <pre class="bd-pem">{{ f.body.slice(0, 88) }}…</pre>
        </div>
        <div class="bd-accnote">
          启动命令：<code class="bd-mono">baidi-gateway -control &lt;控制面地址&gt; -mtls-cert gateway.crt.pem -mtls-key gateway.key.pem -mtls-ca ca.pem</code>
        </div>
        <div class="bd-wfoot">
          <div style="flex: 1" />
          <a-button type="primary" @click="closeIssue">我已保存，关闭</a-button>
        </div>
      </template>
    </a-modal>

    <!-- 吊销确认 -->
    <a-modal v-model:visible="rev.open" title="吊销网关证书" :width="480"
             :ok-loading="rev.busy" ok-text="确认吊销" cancel-text="取消"
             :ok-button-props="{ status: 'danger' }" @ok="doRevoke">
      <div class="bd-certonce bd-certonce--warn">
        <icon-exclamation-circle-fill />
        <div>
          将吊销网关 <b>{{ rev.gatewayId }}</b> 的机器身份。<b>即刻生效</b>：
          该网关下一次调控制面即被拒（拉不到策略、心跳注册失败），
          并会从下发给终端的<b>落点清单</b>里摘掉——已连的客户端在下一次拉剖面时故障转移到其它落点。
          此操作不可撤销，恢复需要重新签发一张新证书并改网关启动参数。
        </div>
      </div>
      <div class="bd-accfld">
        <label>吊销原因</label>
        <a-textarea v-model="rev.reason" placeholder="会写进审计与证书台账，例如：机器下线 / 疑似失陷 / 换证"
                    :max-length="200" allow-clear :auto-size="{ minRows: 2, maxRows: 4 }" />
      </div>
      <div v-if="rev.err" class="bd-accerr"><icon-close-circle-fill />{{ rev.err }}</div>
    </a-modal>
  </div>
    <!-- 对外接入地址（PRD FR-SCEN-08/17）。★两栏都可留空，都空即撤销登记。
         端口刻意不收：它的权威来源是网关自报的监听地址，收第二份就会有两个真相，
         而不一致时症状是「敲门发到 A 口、隧道拨到 B 口」，两边日志都正常。 -->
    <a-modal v-model:visible="acc.open" :title="`网关「${acc.id}」的对外接入地址`" :width="520"
      :ok-loading="acc.busy" ok-text="保存" cancel-text="取消" @ok="saveAccess">
      <div class="bd-accnote">
        客户端会照这两个地址拨号。它与网关自报的<b>监听地址</b>是两回事——网关默认监听
        <code>:18201</code>，无从知道自己在 NAT / 负载均衡后面对外是什么地址。
        两栏都填时，客户端按<b>内网优先</b>的顺序依次尝试（拨不通自动切下一个）。
      </div>
      <div class="bd-accfld">
        <label>局域网访问地址</label>
        <a-input v-model="acc.lan" placeholder="如 10.0.0.9 或 gw-lan.corp.internal" allow-clear />
        <span class="bd-accfld__d">内网终端用的地址。只填主机名或 IP，不要带端口和协议。</span>
      </div>
      <div class="bd-accfld">
        <label>互联网访问地址</label>
        <a-input v-model="acc.wan" placeholder="如 gw.example.com 或 203.0.113.9" allow-clear />
        <span class="bd-accfld__d">公网终端用的地址。内外网想用同一个域名（分区 DNS）时，两栏填一样即可。</span>
      </div>
      <div v-if="acc.err" class="bd-accerr"><icon-close-circle-fill />{{ acc.err }}</div>
    </a-modal>
</template>

<script setup lang="ts">
/**
 * 网关与隐身页。
 *
 * ★整页数据来自 GET /api/v1/gateway，而该端点读的是 mTLS 注册心跳的在线登记
 * （与 GET /api/v1/gateways、诊断页的「数据面网关在线 / SPA 服务隐身」同一份）。
 *
 * 此前这里有一份 MOCK_ZONES：三个区域、六台带主备角色与负载百分比的节点，
 * 全是编的，而且后端种子也是编的——两边都假，看起来严丝合缝。现在页面**没有
 * 任何内置演示数据**：拉不到就说拉不到，没网关就是空态。
 *
 * 去掉的维度与理由：
 *  - 区域：白帝没有区域概念（apps.node 里那列区域名没有任何消费方），
 *    做成网关自报字段既不可验证也不参与任何判定，那是又一个 config-only；
 *  - 主/备角色：没有选主机制；
 *  - 负载百分比：不采集网关负载（宿主机指标另有「设备状态」页，走 metrics 时序）。
 */
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, failReason, type GatewayBundle, type GwNode, type GatewayCert, type GatewayCertsResp, type GatewayCertIssued } from '@/lib/api';

const tab = ref<'topo' | 'spa' | 'node' | 'cert'>('topo');
/* ── 机器身份 · mTLS 证书 ───────────────────────────────────────────────
 *
 * 三个端点后端一直都有（POST/GET /pki/gateway-certs、POST …/{fp}/revoke），
 * 控制台此前一个入口都没有。补上时有两条不能含糊的地方：
 *
 *  ① **私钥只回一次**。签发应答里的 keyPem 不落控制面的库，弹窗一关就没了。
 *     这句话必须排在结果的最前面，而不是页脚的一行小字——不然管理员点掉窗口，
 *     手里只剩一张查得到指纹、却装不上任何机器的证书。
 *  ② **吊销的影响面要说全**。它不只切断"网关→控制面"，还会把这台网关从
 *     下发给终端的落点清单里摘掉（后端 handleRevokeGatewayCert 专门做了这件事）。
 *     只说"吊销证书"的话，管理员不会预期到客户端会跟着故障转移。
 */
const certs = ref<GatewayCertsResp>({ certs: [], caEnabled: true });
const certErr = ref('');
const certKw = ref('');

const shownCerts = computed(() => {
  const k = certKw.value.trim().toLowerCase();
  if (!k) return certs.value.certs;
  return certs.value.certs.filter((c) => `${c.gatewayId} ${c.fingerprint}`.toLowerCase().includes(k));
});
/** 有效 = 未吊销且未过期。★过期与吊销要分开显示：两者的补救动作不同
 *  （过期是换证，吊销是这台机器被主动踢出信任域）。 */
const validCertCount = computed(() => certs.value.certs.filter((c) => certState(c) === 'valid').length);

function certState(c: GatewayCert): 'revoked' | 'expired' | 'valid' {
  if (c.revoked) return 'revoked';
  const t = Date.parse(c.notAfter.replace(' ', 'T'));
  if (!Number.isNaN(t) && t < Date.now()) return 'expired';
  return 'valid';
}
function certStateText(c: GatewayCert) {
  return { revoked: '已吊销', expired: '已过期', valid: '有效' }[certState(c)];
}
/** 与其它页同款的浅色 tag 样式（Resources.vue 同名函数）。 */
function tagStyle(color: string) { return { color, background: color + '14' }; }
function certStateColor(c: GatewayCert) {
  return { revoked: '#F53F3F', expired: '#FF7D00', valid: '#00B42A' }[certState(c)];
}

async function loadCerts() {
  try {
    certs.value = await api<GatewayCertsResp>('/pki/gateway-certs');
    certErr.value = '';
  } catch (e) {
    // 不编空清单：读不到就说读不到（空表与"一张都没签过"在页面上完全同形）。
    certErr.value = failReason(e);
  }
}

const issue = reactive<{ open: boolean; busy: boolean; id: string; err: string; result: GatewayCertIssued | null }>(
  { open: false, busy: false, id: '', err: '', result: null });

function openIssue() { issue.id = ''; issue.err = ''; issue.result = null; issue.open = true; }
function closeIssue() { issue.open = false; issue.result = null; issue.id = ''; issue.err = ''; }

/** 三个待保存的文件。名字与 baidi-gateway 启动参数里的文件名对齐，免得改名后对不上。 */
const issuedFiles = computed(() => {
  const r = issue.result;
  if (!r) return [];
  return [
    { name: 'gateway.crt.pem', desc: '客户端证书（-mtls-cert）', body: r.certPem },
    { name: 'gateway.key.pem', desc: '私钥（-mtls-key）· 只此一次', body: r.keyPem },
    { name: 'ca.pem', desc: '控制面 CA 根证书（-mtls-ca）', body: r.caPem }
  ];
});

async function doIssue() {
  const id = issue.id.trim();
  if (!id) { issue.err = '请填写网关 id'; return; }
  issue.busy = true; issue.err = '';
  try {
    issue.result = await api<GatewayCertIssued>('/pki/gateway-certs', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ gatewayId: id })
    });
    await loadCerts();
  } catch (e) {
    // 后端在这条路上说得很具体（standby- 前缀被拒并给出正路、License 席位不足、未配 CA），
    // 每一条都指明了下一步动作。
    issue.err = failReason(e);
  } finally { issue.busy = false; }
}

const rev = reactive({ open: false, busy: false, fingerprint: '', gatewayId: '', reason: '', err: '' });
function askRevoke(c: GatewayCert) {
  rev.fingerprint = c.fingerprint; rev.gatewayId = c.gatewayId;
  rev.reason = ''; rev.err = ''; rev.open = true;
}
async function doRevoke() {
  rev.busy = true; rev.err = '';
  try {
    await api(`/pki/gateway-certs/${encodeURIComponent(rev.fingerprint)}/revoke`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: rev.reason.trim() || '管理员在控制台吊销（未填原因）' })
    });
    Message.success(`网关「${rev.gatewayId}」的证书已吊销，即刻生效`);
    rev.open = false;
    await loadCerts();
    await load(); // 落点清单会跟着变，顺带刷新网关列表
  } catch (e) {
    rev.err = failReason(e);
  } finally { rev.busy = false; }
}

/** 复制到剪贴板。★失败要说出来：静默失败会让人以为复制成功，然后粘出上一次的内容。 */
async function copyText(text: string, what: string) {
  try {
    await navigator.clipboard.writeText(text);
    Message.success(`${what} 已复制`);
  } catch {
    Message.error(`${what} 复制失败（浏览器拒绝了剪贴板权限），请手动选中复制`);
  }
}

/** 存成本地文件。私钥不经任何网络出口——就地由 Blob 生成。 */
function downloadText(name: string, body: string) {
  const url = URL.createObjectURL(new Blob([body], { type: 'application/x-pem-file' }));
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

const live = ref(false);

const EMPTY: GatewayBundle = {
  nodes: [], total: 0, online: 0, sessions: 0, onlineWindowSec: 0, knockTokenTtlSec: 0,
  stealth: [], stealthArmed: 0, stealthWarnings: []
};
const bundle = ref<GatewayBundle>(EMPTY);
const nodes = computed<GwNode[]>(() => bundle.value.nodes ?? []);
const totalTunnels = computed(() => nodes.value.filter((n) => n.online).reduce((s, n) => s + n.tunnels, 0));

/* ── 内核态隐身回执（wave8 行动 7）── */

/* allArmed 是否**全部**在线网关都实测生效。
 * ★零台在线时为 false：那时没有任何事实支撑「攻击面 = 0」，
 * 空集恒真会让一台网关都没有的部署把最强的那段断言画出来。 */
const allArmed = computed(() => {
  const rs = bundle.value.stealth ?? [];
  if (rs.length === 0 || !rs.every((r) => r.status === 'armed')) return false;
  // ★第二个前提：**没有敞着的七层 Web 代理口**。
  //   L7 监听不受 SPA 隐身保护（CLAUDE.md 端口表逐字写着；发布向导与网关启动日志
  //   都告警过）——内核态隐身只护住敲门口与隧道口，L7 是一个对全世界敞着的 TCP 端口。
  //   少了这一条，一台开着 `-web` 且 nft 规则装好的网关会让这一页同时显示
  //   「端口扫描全程超时，无任何端口可探测」与「攻击面 = 0」，而 nmap 对着
  //   18444 一扫一个准。这是整页唯一一句**正向安全断言**，它必须把已知敞着的口算进去。
  return (bundle.value.webExposed ?? 0) === 0;
});

/** 七层 Web 代理敞口台数（旧后端不下发 → undefined，按"不可判定"处理：不改变断言，
 *  但下面那条说明照样出——不知道有没有敞口时，同样不该说"攻击面 = 0"）。 */
const webExposed = computed(() => bundle.value.webExposed ?? 0);

/* 后端 stealth.go 的**七态**必须在这里全部有名字。漏一个的后果不是报错，
   是那一态在页面上显示成生英文 key + 走兜底的灰色样式——而灰色在本项目里
   专表「我们不知道」。orphan-ruleset 就漏过一次：它在后端是 fail（全员连不上），
   在页面上却与「不可判定」同色同形。 */
const STEALTH_ZH: Record<string, string> = {
  armed: '内核态生效',
  off: '未启用（端口可见）',
  'no-ruleset': '已开启但规则集缺失',
  'no-drop-rule': '规则集缺默认丢弃规则',
  'orphan-ruleset': '规则集在但未启用（全员连不上）',
  'port-mismatch': '规则集保护了别的端口',
  unknown: '不可判定',
  unreported: '网关未上报'
};
function stealthLabel(st: string) { return STEALTH_ZH[st] ?? st; }

/* 只有 armed 是绿的。不可判定与未上报走**灰**而不是暖色——
 * 它们不是"轻微问题"，是"我们不知道"（与在线用户页的 unknown 同一条纪律）。 */
const STEALTH_BAD = ['no-ruleset', 'no-drop-rule', 'orphan-ruleset', 'port-mismatch'];
function stealthTagClass(st: string) {
  if (st === 'armed') return 'bd-tg--ok';
  /* 与后端 checkStealth 的 fail 分桶**同一份名单**：两处分头维护就会出现
     「后端判 fail、页面画成中性灰」。 */
  if (STEALTH_BAD.includes(st)) return 'bd-tg--bad';
  if (st === 'off') return 'bd-tg--warn';
  return 'bd-tg--muted';
}

/* triText 三态布尔渲染：undefined = 网关没说过这件事，显示「不可判定」。
   ★用三元式 `rc.wanted ? 'A' : 'B'` 会把「没上报」渲染成确定结论 B——
   同一张卡片上标签写着「网关未上报」，meta 行却并排给出「-pf 未开启 · 非 root」。 */
function triText(v: boolean | undefined, yes: string, no: string) {
  return v === undefined || v === null ? '不可判定' : v ? yes : no;
}

/* ── SVG 布局 ── */
const nodeH = 86;
const nodeGap = 20;
const nodeTop = 96;
function nodeY(i: number) { return nodeTop + i * (nodeH + nodeGap); }
const svgH = computed(() => Math.max(460, nodeTop + nodes.value.length * (nodeH + nodeGap) + 60));

function statusColor(online: boolean) { return online ? '#00B42A' : '#F53F3F'; }

function humanUptime(sec: number): string {
  if (!sec) return '—';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d) return `${d} 天 ${h} 小时`;
  if (h) return `${h} 小时 ${m} 分`;
  return `${m} 分`;
}

function sinceText(ts: number): string {
  if (!ts) return '—';
  const sec = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (sec < 60) return `${sec} 秒前`;
  if (sec < 3600) return `${Math.floor(sec / 60)} 分钟前`;
  return `${Math.floor(sec / 3600)} 小时前`;
}

/** 本页数据的取回时刻。相对时间列（"最后心跳 N 秒前"）的口径就是它。 */
const fetchedAt = ref('');

async function load(): Promise<void> {
  try {
    bundle.value = await api<GatewayBundle>('/gateway');
    live.value = true;
    fetchedAt.value = new Date().toLocaleTimeString('zh-CN', { hour12: false });
  } catch {
    // 拉不到就是拉不到：清空而不是回落到演示拓扑。
    bundle.value = EMPTY;
    live.value = false;
    fetchedAt.value = '';
  }
}

/* ── 对外接入地址（wave8 行动 4）── */
const acc = reactive({ open: false, busy: false, id: '', lan: '', wan: '', err: '' });
function openAccess(n: GwNode) {
  Object.assign(acc, { open: true, busy: false, id: n.id, lan: n.lanHost ?? '', wan: n.wanHost ?? '', err: '' });
}
async function saveAccess() {
  acc.busy = true; acc.err = '';
  try {
    await api(`/gateway/${encodeURIComponent(acc.id)}/access`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lanHost: acc.lan.trim(), wanHost: acc.wan.trim() })
    });
    acc.open = false;
    Message.success('接入地址已保存，客户端下次拉取剖面即生效');
    await load();
  } catch (e) {
    // 后端的校验文案要原样透出：它说清了为什么这个地址必然连不通（回环 / 带端口 / 带协议）
    acc.err = (e as Error).message || '保存失败';
  } finally { acc.busy = false; }
}

// 自动刷新与网关心跳同频（15s）。★定时器必须在卸载时清掉：留着会在换页之后
// 继续打接口，登出后还会触发 401 跳转，表现为"随机被踢回登录页"。
let gwTimer: number | undefined;
onMounted(() => {
  void load();
  void loadCerts();
  gwTimer = window.setInterval(() => void load(), 15_000);
});
onUnmounted(() => { if (gwTimer) window.clearInterval(gwTimer); });
</script>

<style scoped>
.bd-cmp__ep { display: block; font-size: 11px; color: var(--bd-t3); margin-top: 3px; padding-left: 22px; }

.bd-gwts { font-size: 12px; color: var(--bd-t3); }

/* 机器身份 · mTLS 证书 */
.bd-certnote { display: flex; gap: 10px; padding: 13px 16px; margin-bottom: 12px; font-size: 12.5px; color: var(--bd-t2); line-height: 1.85; }
.bd-certnote__ic { color: var(--bd-primary); font-size: 16px; flex: none; margin-top: 2px; }
.bd-certwarn { display: flex; gap: 9px; align-items: center; padding: 11px 16px; margin-bottom: 12px; font-size: 12.5px; color: var(--bd-warning); }
.bd-searchbox { display: flex; align-items: center; gap: 8px; height: 32px; padding: 0 11px; background: var(--bd-fill-2); border-radius: 6px; color: var(--bd-t3); }
.bd-searchbox__in { border: none; outline: none; background: transparent; flex: 1; min-width: 0; font-size: 13px; color: var(--bd-t1); }
.bd-searchbox__in::placeholder { color: var(--bd-t3); }
.bd-fp { font-size: 11.5px; color: var(--bd-t2); }
.bd-cellsub { font-size: 11px; color: var(--bd-t3); margin-top: 2px; }
.bd-anyt { font-size: 12px; color: var(--bd-t4); }
.bd-row--off { opacity: .55; }
.bd-certonce {
  display: flex; gap: 10px; align-items: flex-start; padding: 12px 14px; margin-bottom: 14px;
  background: var(--bd-tag-red-bg); border: 1px solid #FFCDC7; border-radius: 8px;
  font-size: 12.5px; color: var(--bd-t1); line-height: 1.8;
}
.bd-certonce > :first-child { color: var(--bd-danger); font-size: 16px; flex: none; margin-top: 2px; }
.bd-certonce--warn { background: var(--bd-tag-gold-bg); border-color: #FFCF8B; }
.bd-certonce--warn > :first-child { color: var(--bd-warning); }
.bd-pemrow { margin-bottom: 12px; }
.bd-pemrow__h { display: flex; align-items: center; gap: 9px; font-size: 12.5px; margin-bottom: 5px; }
.bd-pemrow__h span { color: var(--bd-t3); font-size: 11.5px; }
.bd-pem {
  margin: 0; padding: 8px 11px; background: var(--bd-fill-1); border-radius: 6px;
  font-size: 11px; color: var(--bd-t2); overflow-x: auto; white-space: pre-wrap; word-break: break-all;
}
.bd-wfoot { display: flex; align-items: center; gap: 10px; margin-top: 20px; padding-top: 15px; border-top: 1px solid var(--bd-fill-2); }

/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }

/* 空态 */
.bd-empty { padding: 40px 24px; text-align: center; }
.bd-empty__ic { font-size: 30px; color: var(--bd-warning); }
.bd-empty__t { margin-top: 12px; font-size: 15px; font-weight: 600; color: var(--bd-t1); }
.bd-empty__d { margin-top: 8px; font-size: 13px; color: var(--bd-t3); line-height: 1.8; }
.bd-empty__d code { font-family: ui-monospace, monospace; background: var(--bd-fill-2); padding: 1px 6px; border-radius: 4px; }

/* 拓扑卡 */
.bd-topo { padding: 16px 18px; }
.bd-topo svg { display: block; }

/* SPA */
.bd-spa { max-width: 1080px; }
.bd-spacard { padding: 18px 20px 20px; }
.bd-section-title { font-size: 15px; font-weight: 600; color: var(--bd-t1); margin-bottom: 14px; }
.bd-spa__meta { display: flex; flex-direction: column; }
.bd-kv { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding: 10px 0; border-bottom: 1px solid var(--bd-fill-1); font-size: 13px; }
.bd-kv:last-child { border-bottom: none; }
.bd-kv span { color: var(--bd-t3); flex: none; }
.bd-kv b { font-weight: 500; color: var(--bd-t1); text-align: right; }

.bd-spa__ports { margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--bd-fill-2); }
.bd-spa__portshead { font-size: 12.5px; color: var(--bd-t3); margin-bottom: 12px; }
.bd-spa__portslist { display: flex; flex-wrap: wrap; gap: 10px; }
.bd-port { font-size: 12.5px; padding: 5px 12px; border-radius: 14px; background: var(--bd-fill-2); color: var(--bd-t2); font-family: ui-monospace, monospace; }
.bd-spa__note { margin-top: 12px; font-size: 12.5px; color: var(--bd-t3); line-height: 1.7; }

/* 对比卡 */
.bd-cmp { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.bd-cmp__c { padding: 18px 20px; }
.bd-cmp__c--bad { border-color: var(--bd-tag-red-bg); background: linear-gradient(180deg, #FFF8F7 0%, #fff 60%); }
.bd-cmp__c--good { border-color: var(--bd-tag-green-bg); background: linear-gradient(180deg, #F6FFF8 0%, #fff 60%); }
.bd-cmp__h { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: var(--bd-t1); margin-bottom: 14px; }
.bd-cmp__ic { font-size: 18px; }
.bd-cmp__ic.bad { color: var(--bd-danger); }
.bd-cmp__ic.good { color: var(--bd-success); }
.bd-cmp__list { list-style: none; margin: 0; padding: 0; }
.bd-cmp__list li { display: flex; align-items: flex-start; gap: 8px; font-size: 13px; color: var(--bd-t2); line-height: 1.7; padding: 5px 0; }
.bd-cmp__list li :deep(svg) { flex: none; margin-top: 4px; color: var(--bd-t4); font-size: 13px; }
.bd-cmp__list li :deep(svg.li-ok) { color: var(--bd-success); }
.bd-cmp__list b { color: var(--bd-t1); font-weight: 600; }
.bd-cmp__foot { margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--bd-fill-2); font-size: 12.5px; font-weight: 600; }
.bd-cmp__foot.bad { color: var(--bd-danger); }
.bd-cmp__foot.good { color: #0B8235; }
/* 对外接入地址列 */
.bd-acc { font-size: 12px; line-height: 1.7; white-space: nowrap; }
.bd-acc i { display: inline-block; min-width: 42px; margin-right: 6px; font-style: normal; color: var(--bd-t3); font-size: 11px; }
.bd-acc__none { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; color: var(--bd-warning, #FF7D00); }
.bd-acc__edit { margin-left: 10px; font-size: 12px; }
.bd-accnote { font-size: 12.5px; line-height: 1.8; color: var(--bd-t2); background: var(--bd-fill-1);
  padding: 10px 12px; border-radius: 8px; margin-bottom: 14px; }
.bd-accnote code { font-family: var(--bd-mono, monospace); background: var(--bd-fill-2, #f2f3f5); padding: 0 4px; border-radius: 3px; }
.bd-accfld { margin-bottom: 14px; }
.bd-accfld label { display: block; font-size: 13px; font-weight: 500; color: var(--bd-t1); margin-bottom: 6px; }
.bd-accfld__d { display: block; margin-top: 5px; font-size: 12px; color: var(--bd-t3); line-height: 1.6; }
.bd-accerr { display: flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--bd-danger);
  background: var(--bd-tag-red-bg, #FFECE8); padding: 8px 12px; border-radius: 6px; }

/* ── 内核态隐身回执 ── */
.bd-stealth__count { margin-left: 10px; font-size: 12px; font-weight: 400; color: var(--bd-t3); }
.bd-stealthwarn {
  display: flex; align-items: flex-start; gap: 8px; margin-bottom: 10px; padding: 10px 12px;
  border-radius: 8px; font-size: 12.5px; line-height: 1.6;
  color: #A8620E; background: #FFF7E8; border: 1px solid #FFD08A;
}
.bd-stealthwarn > :first-child { flex: none; margin-top: 2px; font-size: 14px; }
.bd-stealth { padding: 14px 16px; margin-bottom: 10px; }
.bd-stealth__h { display: flex; align-items: center; gap: 10px; font-size: 13.5px; margin-bottom: 8px; }
.bd-stealth__intent { margin-left: auto; font-size: 12px; color: var(--bd-t3); }
.bd-stealth__sum { font-size: 13px; color: var(--bd-t1); line-height: 1.6; }
.bd-stealth__scan { margin-top: 6px; font-size: 12.5px; color: var(--bd-t2); line-height: 1.7; }
.bd-stealth__meta { margin-top: 8px; font-size: 12px; color: var(--bd-t3); }
/* 只有 armed 是绿的；不可判定/未上报走灰——它们不是"轻微问题"，是"我们不知道"。 */
.bd-tg--ok { color: var(--bd-success); background: var(--bd-tag-green-bg); }
.bd-tg--bad { color: var(--bd-danger); background: var(--bd-tag-red-bg); }
.bd-tg--warn { color: #A8620E; background: #FFF7E8; }
.bd-tg--muted { color: var(--bd-t3); background: var(--bd-fill2); }
</style>
