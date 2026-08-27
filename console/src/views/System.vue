<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">系统管理</div>
        <div class="bd-page__sub">三权分立 · 分级分权 · 消息通道 · 集群</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '未连控制中心' }}</a-tag>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'admin' }" @click="tab = 'admin'">管理员与三权分立</span>
      <span class="bd-tab" :class="{ on: tab === 'notify' }" @click="tab = 'notify'">消息通道</span>
      <span class="bd-tab" :class="{ on: tab === 'forward' }" @click="tab = 'forward'">日志外送</span>
      <span class="bd-tab" :class="{ on: tab === 'cluster' }" @click="tab = 'cluster'">集群</span>
      <span class="bd-tab" :class="{ on: tab === 'license' }" @click="tab = 'license'">License</span>
    </div>

    <!-- ============ 管理员与三权分立 ============ -->
    <div v-show="tab === 'admin'">
      <!-- ① 角色卡片行 -->
      <div class="bd-section-title">管理员角色 · 三权分立</div>
      <div class="bd-sep__note">
        <icon-safe />
        <span>
          <b>系统 / 安全 / 审计</b> 三组互不越权，权限由后端 <i class="bd-mono">requirePerm</i> 逐端点执行：
          审计管理员只读全量日志（改不了用户与策略）、安全管理员定策略但读不到审计、系统管理员管配置。
          卡片上的权限键就是判定用的那份，不是文案。
        </span>
      </div>
      <div v-if="err" class="bd-warn"><icon-exclamation-circle-fill />{{ err }}</div>
      <div class="bd-groups">
        <div
          v-for="g in roles"
          :key="g.key"
          class="bd-card bd-gcard"
          :style="{ '--pc': powerColor(g.power) }"
        >
          <span class="bd-gcard__bar" />
          <div class="bd-gcard__top">
            <span class="bd-gcard__dot" />
            <span class="bd-gcard__name">{{ g.name }}</span>
            <a-tag v-if="g.builtin" size="small" :style="tagStyle(powerColor(g.power))">内置</a-tag>
            <a-tag v-else size="small" :style="tagStyle('#86909C')">自定义</a-tag>
          </div>
          <div class="bd-gcard__meta">
            <span class="bd-gcard__power" :style="{ color: powerColor(g.power) }">{{ powerText(g.power) }}</span>
            <span class="bd-gcard__members"><b>{{ g.members }}</b> 人</span>
          </div>
          <div class="bd-gcard__perms">
            <span v-for="p in g.perms" :key="p" class="bd-perm bd-mono">{{ p }}</span>
          </div>
          <div class="bd-gcard__scope">{{ g.scope }}</div>
          <div v-if="!g.builtin" class="bd-gcard__ops">
            <span class="bd-link bd-link--danger" @click="removeRole(g)">删除角色</span>
          </div>
        </div>
      </div>
      <div class="bd-rolebar">
        <button class="bd-btn bd-btn--ghost" @click="openRole"><icon-plus />新建自定义角色</button>
        <span class="bd-hint">自定义角色只能在 system / security / audit 三权内收缩，不能自造超管。</span>
      </div>

      <!-- ② 管理员账号表 -->
      <div class="bd-section-title" style="margin-top: 26px">管理员账号</div>
      <div class="bd-tablecard">
        <div class="bd-toolbar">
          <div class="bd-searchbox" style="flex: 1; max-width: 280px">
            <icon-search />
            <input v-model="kw" placeholder="搜索账号 / 姓名" />
          </div>
          <div style="margin-left: auto; display: flex; gap: 10px">
            <button class="bd-btn bd-btn--ghost" @click="reload"><icon-refresh />刷新</button>
            <button class="bd-btn" @click="openAdmin"><icon-plus />新建管理员</button>
          </div>
        </div>
        <table class="bd-table">
          <thead>
            <tr>
              <th>账号</th>
              <th>角色</th>
              <th>认证方式</th>
              <th>二次认证</th>
              <th>状态</th>
              <th>最后登录</th>
              <th class="r">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in filteredAdmins" :key="a.account">
              <td>
                <div class="bd-cellname">
                  <span class="bd-avatar" :style="{ background: avatarBg(a.name) }">{{ a.name.slice(0, 1) }}</span>
                  <span>
                    <b>{{ a.name }}</b>
                    <i class="bd-mono">{{ a.account }}</i>
                  </span>
                </div>
              </td>
              <td>
                <span class="bd-st">
                  <span class="d" :style="{ background: powerColor(a.power) }" />{{ a.roleName }}
                </span>
              </td>
              <td>{{ a.auth }}</td>
              <td>
                <span v-if="a.twoFa" class="bd-tg" :style="tagStyle('#00B42A')">已注册 passkey</span>
                <span v-else class="bd-tg" :style="tagStyle('#86909C')">未注册</span>
              </td>
              <td>{{ statusText(a.status) }}</td>
              <td class="bd-mono">{{ a.lastLogin || '—' }}</td>
              <td class="r">
                <span class="bd-link" @click="openRoleChange(a)">改派角色</span>
                <span class="bd-link bd-link--danger" style="margin-left: 14px" @click="removeAdmin(a)">撤销管理员</span>
              </td>
            </tr>
            <tr v-if="!filteredAdmins.length">
              <td colspan="7" class="bd-empty">{{ kw ? '无匹配管理员' : '暂无管理员账号' }}</td>
            </tr>
          </tbody>
        </table>
        <div class="bd-pager">
          共 {{ filteredAdmins.length }} 名管理员 · 系统至少保留一名超级管理员（最后一名不可降权/撤销/禁用）
        </div>
      </div>
    </div>

    <!-- ============ 消息通道（PRD ch15.2）============ -->
    <div v-show="tab === 'notify'">
      <div class="bd-section-title">消息通道</div>
      <div class="bd-sep__note">
        <icon-notification />
        <span>
          安全事件（<b>账号被爆破锁定</b>、<b>终端被判不合规</b>）会向下面每一条<b>已启用</b>的通道各发一份。
          发送成功与失败都会落审计，并写进「上次发送」列——那一列显示的是<b>真正发出去那一次</b>的结果，
          保存配置不会把它刷成绿色。
        </span>
      </div>
      <div v-if="smsNote" class="bd-warn">
        <icon-exclamation-circle-fill />{{ smsNote }}
      </div>
      <!-- 哪些事件真的会发通知。★不列的话，「没收到」与「这类事件根本没接线」
           在页面上完全同形——管理员配好通道后无从知道自己会收到什么。
           与告警规则页展示 alertKindSpecs.Signal 同款做法：逐条写出触发源。 -->
      <div v-if="notifyEvents.length" class="bd-nev">
        <div class="bd-nev__h">会触发通知的安全事件</div>
        <div v-for="e in notifyEvents" :key="e.event" class="bd-nev__i" :class="{ off: !e.wired }">
          <span class="bd-nev__n">
            <icon-check-circle-fill v-if="e.wired" class="bd-nev__ok" />
            <icon-minus-circle v-else class="bd-nev__no" />
            {{ e.name }}
          </span>
          <span class="bd-nev__s">{{ e.wired ? e.signal : (e.reason || '本版本未接线') }}</span>
        </div>
      </div>
      <div v-if="notifyErr" class="bd-warn"><icon-exclamation-circle-fill />{{ notifyErr }}</div>
      <div v-if="dropped > 0" class="bd-warn">
        <icon-exclamation-circle-fill />
        通知队列已累计丢弃 <b>{{ dropped }}</b> 条（队列满时丢新保旧）。安全处置本身不受影响，但这段时间的告警确实没发出去。
      </div>

      <div class="bd-tablecard">
        <div class="bd-toolbar">
          <span class="bd-hint">凭据（SMTP 口令 / 请求头 token）加密独立存放，<b>只写不读</b>——界面只能看到指纹前 8 位。</span>
          <div style="margin-left: auto; display: flex; gap: 10px">
            <button class="bd-btn bd-btn--ghost" @click="reloadNotify"><icon-refresh />刷新</button>
            <button class="bd-btn" @click="openChannel()"><icon-plus />新建通道</button>
          </div>
        </div>
        <table class="bd-table">
          <thead>
            <tr>
              <th>名称</th>
              <th>类型</th>
              <th>目标</th>
              <th>状态</th>
              <th>凭据</th>
              <th>上次发送</th>
              <th class="r">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in channels" :key="c.id">
              <td><b>{{ c.name }}</b><i class="bd-mono" style="display: block">{{ c.id }}</i></td>
              <td>
                <span class="bd-tg" :style="tagStyle(kindColor(c.kind))">{{ kindText(c.kind) }}</span>
              </td>
              <td class="bd-mono bd-target">{{ channelTarget(c) }}</td>
              <td>
                <span v-if="c.enabled" class="bd-tg" :style="tagStyle('#00B42A')">已启用</span>
                <span v-else class="bd-tg" :style="tagStyle('#86909C')">已停用</span>
              </td>
              <td>
                <span v-if="c.hasSecret" class="bd-mono">已配置 · {{ c.secretFingerprint }}</span>
                <span v-else class="bd-hint">未配置</span>
              </td>
              <td>
                <span v-if="!c.lastStatus" class="bd-hint">从未发送</span>
                <span v-else>
                  <span class="bd-tg" :style="tagStyle(c.lastStatus === 'ok' ? '#00B42A' : '#F53F3F')">
                    {{ c.lastStatus === 'ok' ? '成功' : '失败' }}
                  </span>
                  <i class="bd-mono" style="display: block">{{ lastAtText(c.lastAt) }} · {{ c.lastEvent }}</i>
                  <i class="bd-lastdetail">{{ c.lastDetail }}</i>
                </span>
              </td>
              <td class="r">
                <span class="bd-link" @click="testChannel(c)">测试</span>
                <span class="bd-link" style="margin-left: 12px" @click="openChannel(c)">编辑</span>
                <span class="bd-link" style="margin-left: 12px" @click="openSecret(c)">设凭据</span>
                <span class="bd-link bd-link--danger" style="margin-left: 12px" @click="removeChannel(c)">删除</span>
              </td>
            </tr>
            <tr v-if="!channels.length">
              <td colspan="7" class="bd-empty">
                还没有任何消息通道——安全事件目前只落审计，不会主动通知任何人。
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 新建 / 编辑消息通道 -->
    <a-modal v-model:visible="chanOpen" :title="chanForm.id ? '编辑消息通道' : '新建消息通道'"
      :confirm-loading="saving" @ok="submitChannel" @cancel="chanOpen = false">
      <a-form :model="chanForm" layout="vertical">
        <a-form-item label="名称"><a-input v-model="chanForm.name" placeholder="如 SOC 邮件组" /></a-form-item>
        <a-form-item label="类型">
          <a-select v-model="chanForm.kind" :disabled="!!chanForm.id">
            <a-option v-for="k in supportedKinds" :key="k" :value="k">{{ kindText(k) }}</a-option>
          </a-select>
        </a-form-item>
        <a-form-item>
          <a-checkbox v-model="chanForm.enabled">启用（安全事件会向它发送）</a-checkbox>
        </a-form-item>

        <template v-if="chanForm.kind === 'smtp'">
          <a-form-item label="服务器">
            <a-input v-model="chanForm.host" placeholder="smtp.corp.example" style="flex: 2" />
            <a-input-number v-model="chanForm.port" placeholder="端口" :min="1" :max="65535" style="margin-left: 8px; width: 120px" />
          </a-form-item>
          <a-form-item label="传输加密" help="STARTTLS 协商失败绝不降级明文——后端会直接报错，不会偷偷用明文把口令发出去">
            <a-select v-model="chanForm.tlsMode">
              <a-option value="starttls">STARTTLS（587/25，推荐）</a-option>
              <a-option value="implicit">隐式 TLS（465）</a-option>
              <a-option value="plaintext">明文（仅限本机中继；此模式下不允许配置认证）</a-option>
            </a-select>
          </a-form-item>
          <a-form-item label="认证方式">
            <a-select v-model="chanForm.authMode">
              <a-option value="none">匿名（内网按 IP 放行的中继）</a-option>
              <a-option value="plain">AUTH PLAIN</a-option>
              <a-option value="login">AUTH LOGIN（Exchange / 部分国产网关只认它）</a-option>
            </a-select>
          </a-form-item>
          <a-form-item v-if="chanForm.authMode !== 'none'" label="账号" help="口令走「设凭据」单独提交，只写不读">
            <a-input v-model="chanForm.username" placeholder="alarm@corp.example" />
          </a-form-item>
          <a-form-item label="发件人"><a-input v-model="chanForm.from" placeholder="baidi@corp.example" /></a-form-item>
          <a-form-item label="收件人" help="多个用逗号分隔；为空时发送会直接报错，不会静默丢弃">
            <a-input v-model="chanForm.recipients" placeholder="soc@corp.example, ops@corp.example" />
          </a-form-item>
          <a-form-item label="服务端证书名（可选）" help="用 IP 连接但证书签的是主机名时填这里，比跳过证书校验正确得多">
            <a-input v-model="chanForm.serverName" placeholder="mail.corp.example" />
          </a-form-item>
          <a-form-item label="自定义 CA（可选，PEM）" help="填了就只信这一把——内网 MTA 多是私有 CA 签的，'系统池 ∪ 私有 CA' 反而更宽">
            <a-textarea v-model="chanForm.caCert" :auto-size="{ minRows: 2, maxRows: 5 }"
              placeholder="-----BEGIN CERTIFICATE-----" />
          </a-form-item>
        </template>

        <template v-else>
          <a-form-item label="URL"><a-input v-model="chanForm.url" placeholder="https://hook.corp.example/baidi" /></a-form-item>
          <a-form-item label="凭据头名（可选）" help="填了就必须再用「设凭据」提交头值；头值加密存放，只写不读">
            <a-input v-model="chanForm.secretHeader" placeholder="Authorization" />
          </a-form-item>
          <a-form-item :label="chanForm.kind === 'sms' ? '手机号' : '收件人（进载荷 to 字段，可空）'"
            :help="chanForm.kind === 'sms' ? '多个用逗号分隔；为空时发送直接报错' : '多个用逗号分隔'">
            <a-input v-model="chanForm.recipients" :placeholder="chanForm.kind === 'sms' ? '13800000000' : 'soc@corp.example'" />
          </a-form-item>
          <div v-if="chanForm.kind === 'sms'" class="bd-hint" style="margin-bottom: 12px; line-height: 1.7">
            短信通道<b>就是一次 webhook 调用</b>：白帝把 <i class="bd-mono">{{ '{ mobiles, text }' }}</i> POST 给这个 URL，
            由你自己搭的一跳转成运营商 / 云厂商的请求。白帝<b>不实现</b>任何短信网关协议。
          </div>
        </template>
      </a-form>
    </a-modal>

    <!-- 设置通道凭据 -->
    <a-modal v-model:visible="secretOpen" title="设置通道凭据" :confirm-loading="saving"
      @ok="submitSecret" @cancel="secretOpen = false">
      <a-form :model="secretForm" layout="vertical">
        <a-form-item label="通道"><a-input v-model="secretForm.name" disabled /></a-form-item>
        <a-form-item label="凭据"
          help="SMTP 通道填口令；webhook / 短信通道填凭据头的取值（如 Bearer xxx）。提交后无法回显，只能覆盖。">
          <a-input-password v-model="secretForm.secret" placeholder="提交后只写不读" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- ============ 日志外送（PRD ch16 + ch21.6）============ -->
    <div v-show="tab === 'forward'">
      <div class="bd-section-title">审计日志外送 · Syslog / SIEM</div>
      <div class="bd-sep__note">
        <icon-export />
        <span>
          每条审计落库时会同步入一个<b>持久化队列</b>，后台按批投递到下面每一条<b>已启用</b>的出口：
          <b>发送成功才出队</b>，失败留在队列里退避重试（<b>一条都不丢</b>），队列满了才丢弃并计数。
          外送的字段与审计列表、CSV 导出<b>同源</b>，且带防篡改链的 <i class="bd-mono">seq</i> 与
          <i class="bd-mono">mac</i>——这是 SIEM 侧能<b>独立验真</b>的依据，也是这个功能真正的价值。
        </span>
      </div>
      <div v-if="fwdNote" class="bd-sep__note">
        <icon-info-circle /><span>{{ fwdNote }}</span>
      </div>
      <div v-if="fwdErr" class="bd-warn"><icon-exclamation-circle-fill />{{ fwdErr }}</div>
      <div v-for="t in droppingTargets" :key="'drop-' + t.id" class="bd-warn">
        <icon-exclamation-circle-fill />
        出口「<b>{{ t.name }}</b>」队列已溢出，累计丢弃 <b>{{ t.dropped }}</b> 条待外送记录（上界 {{ fwdQueueMax }}）。
        这些审计已落库，但<b>不会</b>送达 SIEM——请先修复对端再考虑补导 CSV。
      </div>

      <div class="bd-tablecard">
        <div class="bd-toolbar">
          <span class="bd-hint">
            凭据（HTTP 出口的请求头 token）加密独立存放，<b>只写不读</b>；syslog 出口<b>没有</b>可设的凭据。
          </span>
          <div style="margin-left: auto; display: flex; gap: 10px">
            <button class="bd-btn bd-btn--ghost" @click="reloadForward"><icon-refresh />刷新</button>
            <button class="bd-btn" @click="openForward()"><icon-plus />新建出口</button>
          </div>
        </div>
        <table class="bd-table">
          <thead>
            <tr>
              <th>名称</th>
              <th>类型</th>
              <th>目标</th>
              <th>状态</th>
              <th>队列</th>
              <th>上次投递</th>
              <th class="r">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="t in fwdTargets" :key="t.id">
              <td>
                <b>{{ t.name }}</b>
                <i class="bd-mono" style="display: block">{{ t.id }}</i>
                <i class="bd-hint" style="display: block">自审计 #{{ t.startAuditId }} 起外送（更早的历史不补发）</i>
              </td>
              <td><span class="bd-tg" :style="tagStyle(fwdKindColor(t.kind))">{{ fwdKindText(t.kind) }}</span></td>
              <td class="bd-mono bd-target">{{ fwdTarget(t) }}</td>
              <td>
                <span v-if="t.enabled" class="bd-tg" :style="tagStyle('#00B42A')">已启用</span>
                <span v-else class="bd-tg" :style="tagStyle('#86909C')">已停用</span>
              </td>
              <td>
                <span :style="{ color: t.queued > 0 ? '#FF7D00' : 'var(--bd-t2)' }">
                  积压 <b>{{ t.queued }}</b> / {{ fwdQueueMax }}
                </span>
                <i v-if="t.dropped > 0" class="bd-mono" style="display: block; color: #F53F3F">
                  已丢弃 {{ t.dropped }} 条
                </i>
              </td>
              <td>
                <span v-if="!t.lastStatus" class="bd-hint">从未投递</span>
                <span v-else>
                  <span class="bd-tg" :style="tagStyle(t.lastStatus === 'ok' ? '#00B42A' : '#F53F3F')">
                    {{ t.lastStatus === 'ok' ? '成功' : '失败' }}
                  </span>
                  <i class="bd-mono" style="display: block">{{ lastAtText(t.lastAt) }}</i>
                  <!-- 上次**成功**单列一行：外送断了之后 lastAt 会一直被失败刷新，
                       只看它会误以为"刚刚还通着" -->
                  <i class="bd-mono" style="display: block">上次成功：{{ lastAtText(t.lastOkAt) }}</i>
                  <i class="bd-lastdetail">{{ t.lastDetail }}</i>
                </span>
              </td>
              <td class="r">
                <span class="bd-link" @click="testForward(t)">测试</span>
                <span class="bd-link" style="margin-left: 12px" @click="flushForward(t)">立即投递</span>
                <span class="bd-link" style="margin-left: 12px" @click="openForward(t)">编辑</span>
                <span v-if="t.kind === 'http'" class="bd-link" style="margin-left: 12px" @click="openFwdSecret(t)">设凭据</span>
                <span class="bd-link bd-link--danger" style="margin-left: 12px" @click="removeForward(t)">删除</span>
              </td>
            </tr>
            <tr v-if="!fwdTargets.length">
              <td colspan="7" class="bd-empty">
                还没有任何外送出口——审计目前只留在本机库里，外部 SIEM 拿不到、也无法独立验真。
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 新建 / 编辑外送出口 -->
    <a-modal v-model:visible="fwdOpen" :title="fwdForm.id ? '编辑外送出口' : '新建外送出口'"
      :confirm-loading="saving" @ok="submitForward" @cancel="fwdOpen = false">
      <a-form :model="fwdForm" layout="vertical">
        <a-form-item label="名称"><a-input v-model="fwdForm.name" placeholder="如 SOC Syslog" /></a-form-item>
        <a-form-item label="类型">
          <a-select v-model="fwdForm.kind" :disabled="!!fwdForm.id">
            <a-option v-for="k in fwdKinds" :key="k" :value="k">{{ fwdKindText(k) }}</a-option>
          </a-select>
        </a-form-item>
        <a-form-item>
          <a-checkbox v-model="fwdForm.enabled">启用（新产生的审计会入队并投递）</a-checkbox>
        </a-form-item>

        <template v-if="fwdForm.kind === 'syslog'">
          <a-form-item label="服务器" help="只走 TCP。刻意不做 UDP——审计日志用 UDP 会静默丢包，而丢了这件事两端都看不见">
            <a-input v-model="fwdForm.host" placeholder="siem.corp.example" style="flex: 2" />
            <!-- 0 = 交给后端按是否 TLS 取默认。写死 6514 的话，取消勾选 TLS 之后端口
                 还停在 6514，界面看起来完全正常、实际拨到了一个多半没人听的端口。 -->
            <a-input-number v-model="fwdForm.port" placeholder="0=默认" :min="0" :max="65535"
              style="margin-left: 8px; width: 120px" />
          </a-form-item>
          <a-form-item help="没有「跳过证书校验」这一项：外送内容是全量审计，那种开关一旦存在就会被永久打开。证书对不上请填下面两项">
            <a-checkbox v-model="fwdForm.tls">启用 TLS（RFC 5425，默认端口 6514；不勾则明文 TCP，默认 514）</a-checkbox>
          </a-form-item>
          <a-form-item v-if="fwdForm.tls" label="服务端证书名（可选）" help="用 IP 连接但证书签的是主机名时填这里">
            <a-input v-model="fwdForm.serverName" placeholder="siem.corp.example" />
          </a-form-item>
          <a-form-item v-if="fwdForm.tls" label="自定义 CA（可选，PEM）" help="填了就只信这一把——内网 SIEM 多是私有 CA 签的">
            <a-textarea v-model="fwdForm.caCert" :auto-size="{ minRows: 2, maxRows: 5 }"
              placeholder="-----BEGIN CERTIFICATE-----" />
          </a-form-item>
          <a-form-item label="帧方式" help="收集端切错帧会导致整段日志解析不出来。rsyslog imtcp 默认是 LF，RFC 6587 推荐八位组计数">
            <a-select v-model="fwdForm.framing">
              <a-option value="octet">八位组计数（RFC 6587 §3.4.1，推荐）</a-option>
              <a-option value="lf">换行分隔（rsyslog imtcp 默认）</a-option>
            </a-select>
          </a-form-item>
          <a-form-item label="企业号（可选）"
            help="RFC 5424 要求自定义 SD-ID 形如 name@企业号。白帝没有 IANA 企业号，默认用 RFC 5612 保留给文档的 32473；有自己号段的填这里">
            <a-input v-model="fwdForm.enterpriseId" placeholder="32473" />
          </a-form-item>
        </template>

        <template v-else>
          <a-form-item label="URL"><a-input v-model="fwdForm.url" placeholder="https://siem.corp.example/ingest/baidi" /></a-form-item>
          <a-form-item label="凭据头名（可选）" help="填了就必须再用「设凭据」提交头值；头值加密存放，只写不读">
            <a-input v-model="fwdForm.secretHeader" placeholder="Authorization" />
          </a-form-item>
          <a-form-item label="自定义 CA（可选，PEM）" help="https 且是私有 CA 签发时填；填了就只信这一把">
            <a-textarea v-model="fwdForm.caCert" :auto-size="{ minRows: 2, maxRows: 5 }"
              placeholder="-----BEGIN CERTIFICATE-----" />
          </a-form-item>
          <div class="bd-hint" style="margin-bottom: 12px; line-height: 1.7">
            载荷是一批记录：<i class="bd-mono">{{ '{ source, kind, sentAt, count, chain, records[] }' }}</i>，
            其中每条 record 的字段与 <i class="bd-mono">GET /api/v1/audit</i> 返回的条目<b>完全一致</b>（含 seq / mac）。
          </div>
        </template>
      </a-form>
    </a-modal>

    <!-- 设置外送凭据 -->
    <a-modal v-model:visible="fwdSecretOpen" title="设置外送凭据" :confirm-loading="saving"
      @ok="submitFwdSecret" @cancel="fwdSecretOpen = false">
      <a-form :model="fwdSecretForm" layout="vertical">
        <a-form-item label="出口"><a-input v-model="fwdSecretForm.name" disabled /></a-form-item>
        <a-form-item label="凭据" help="凭据头的取值（如 Bearer xxx）。提交后无法回显，只能覆盖。">
          <a-input-password v-model="fwdSecretForm.secret" placeholder="提交后只写不读" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- ============ 集群（控制面温备，PRD 15.5）============
         三态全部来自 GET /api/v1/system 的 cluster 块（standby_nodes 真实台账），
         与 /diag 的 checkCluster 同一个后端函数——这一页刻意**没有**降级演示数据：
         编一台"同步正常"的备机，与真的备机在页面上无法区分，而这一页的存在意义
         正是"切换那天手上到底有没有一份能用的备份"。 -->
    <div v-show="tab === 'license'">
      <div class="bd-section-title">License · 容量与有效期</div>

      <!-- 状态行：demo 是正常形态（研究/演示项目），不当成缺陷渲染 -->
      <div class="bd-card" style="padding: 16px 18px; margin-bottom: 12px">
        <div style="display: flex; align-items: center; gap: 10px">
          <a-tag :color="licModeColor" bordered>{{ licModeLabel }}</a-tag>
          <span v-if="lic?.manifest" style="color: var(--bd-t2)">
            {{ lic.manifest.licensee }} · 到期 <b>{{ lic.manifest.expiresAt }}</b>
          </span>
          <span v-if="lic?.reason" style="color: var(--bd-danger); font-size: 13px">{{ lic.reason }}</span>
        </div>
        <!-- 席位：-1 = 读不出（显示 —，绝不显示 0）；超限亮红 -->
        <div v-if="lic" class="lic-usage">
          <div class="lic-usage__item">
            <span>用户席位</span>
            <b :style="lic.usage.overUsers ? 'color: var(--bd-danger)' : ''">
              {{ seat(lic.usage.users) }} / {{ cap(lic.usage.maxUsers) }}
              <template v-if="lic.usage.overUsers">（已超限）</template>
            </b>
          </div>
          <div class="lic-usage__item">
            <span>网关席位（未吊销证书的去重网关数）</span>
            <b :style="lic.usage.overGateways ? 'color: var(--bd-danger)' : ''">
              {{ seat(lic.usage.gateways) }} / {{ cap(lic.usage.maxGateways) }}
              <template v-if="lic.usage.overGateways">（已超限）</template>
            </b>
          </div>
        </div>
      </div>

      <!-- 导入（PermSystem；无发行公钥时如实说明为什么导不了，而不是让人贴完才 400） -->
      <div class="bd-card" style="padding: 16px 18px; margin-bottom: 12px">
        <div class="bd-card__title" style="margin-bottom: 8px">导入 / 替换 License</div>
        <div v-if="lic && !lic.keysConfigured" class="bd-hint" style="color: var(--bd-warning)">
          控制面未配置发行公钥（BAIDI_LICENSE_PUBKEY）：任何 license 都无法验证，导入会被拒绝。
          公钥由发行方 <i class="bd-mono">baidi-license -genkey</i> 产出，经部署期配置分发。
        </div>
        <template v-else>
          <a-textarea v-model="licPaste" :auto-size="{ minRows: 3, maxRows: 8 }"
            placeholder='粘贴 license 文件内容（{"manifest":…,"signature":…}）' />
          <div style="margin-top: 10px">
            <a-button type="primary" :loading="saving" :disabled="!licPaste.trim()" @click="importLicense">
              验证并导入
            </a-button>
            <span class="bd-hint" style="margin-left: 10px">导入后立刻生效（判定现算不缓存）；没有"删除回演示模式"的入口。</span>
          </div>
        </template>
      </div>

      <div class="bd-card" style="padding: 16px 18px">
        <div class="bd-card__title" style="margin-bottom: 8px">边界（照实说）</div>
        <ul class="lic-bounds">
          <li v-for="(b, i) in lic?.boundaries ?? []" :key="i">{{ b }}</li>
        </ul>
      </div>
    </div>

    <div v-show="tab === 'cluster'">
      <!-- ① 未配置备机（单机形态）-->
      <div v-if="!cluster.deployed" class="bd-card bd-empty bd-empty--lg">
        <icon-storage />
        <div class="bd-empty__t">{{ cluster.summary || '未配置备机（当前为单机形态）' }}</div>
        <div class="bd-empty__d">{{ cluster.note }}</div>
        <div class="bd-empty__d">
          运维体检（/diag）里这一项同样记为
          <i class="bd-mono">{{ cluster.status || 'skip' }}</i>——未部署的能力不参与健康分。
        </div>
      </div>

      <!-- ② / ③ 已配备机：新鲜 or 落后 -->
      <template v-else>
        <div class="bd-section-title">控制面温备 · 备机同步状态</div>
        <div class="bd-cl__head" :class="cluster.status === 'pass' ? 'ok' : 'bad'">
          <icon-check-circle-fill v-if="cluster.status === 'pass'" />
          <icon-exclamation-circle-fill v-else />
          <div>
            <div class="bd-cl__sum">{{ cluster.summary }}</div>
            <div class="bd-cl__note">{{ cluster.note }}</div>
          </div>
        </div>
        <div class="bd-sep__note">
          <icon-clock-circle />
          <span><b>{{ cluster.rpo }}</b>　落后阈值：逐台取 max(全局 {{ Math.round(cluster.staleAfterSec / 60) }} 分钟, 3×该备机自报间隔)。</span>
        </div>

        <table class="bd-table">
          <thead>
            <tr>
              <th>备机</th>
              <th>状态</th>
              <th>落后</th>
              <th>同步间隔（RPO）</th>
              <th>盘上那份备份</th>
              <th>最近一轮</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="n in cluster.nodes" :key="n.nodeId">
              <td>
                <b>{{ n.nodeId }}</b>
                <i class="bd-mono" style="display: block">{{ n.addr || '落点未报' }}</i>
              </td>
              <td><span class="bd-tg" :style="tagStyle(stateColor(n.state))">{{ stateText(n.state) }}</span></td>
              <td>
                <!-- lagSeconds < 0 = 不可判定（从未成功同步过）。绝不显示成"0 秒"——
                     那是"刚刚同步过"的意思，与事实恰好相反。 -->
                <span :style="{ color: n.state === 'fresh' ? 'var(--bd-t2)' : '#F53F3F' }">{{ n.lagText }}</span>
                <i class="bd-hint" style="display: block">阈值 {{ Math.round(n.thresholdSec / 60) }} 分钟</i>
              </td>
              <td>
                <span v-if="n.intervalSec > 0">{{ Math.round(n.intervalSec / 60) }} 分钟</span>
                <span v-else class="bd-hint">尚未回报</span>
              </td>
              <td>
                <span v-if="n.lastSyncAt">
                  <i class="bd-mono" style="display: block">{{ n.lastSyncAt }} 落盘</i>
                  <i class="bd-mono" style="display: block">版本 {{ n.backupVersion || '未知' }} · 生成于 {{ n.backupCreatedAt || '未知' }}</i>
                  <i class="bd-mono bd-lastdetail">sha256 {{ (n.backupSha256 || '').slice(0, 16) || '—' }}…</i>
                </span>
                <span v-else class="bd-hint">
                  从未成功同步——现在提升它只会得到一套空系统
                  <i v-if="n.lastPullAt" class="bd-mono" style="display: block">但来拉过：{{ n.lastPullAt }}</i>
                </span>
              </td>
              <td>
                <span v-if="!n.lastStatus" class="bd-hint">从未回报</span>
                <span v-else>
                  <span class="bd-tg" :style="tagStyle(n.lastStatus === 'ok' ? '#00B42A' : '#F53F3F')">
                    {{ n.lastStatus === 'ok' ? '成功' : '失败' }}
                  </span>
                  <i v-if="n.lastDetail" class="bd-lastdetail">{{ n.lastDetail }}</i>
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </template>

      <!-- 诚实边界 + 切换命令：两块都由后端下发，页面照抄不自己编 -->
      <div class="bd-card bd-cl__box">
        <div class="bd-cl__boxt">这套温备做到哪、没做哪</div>
        <ul class="bd-cl__list">
          <li v-for="(b, i) in cluster.boundaries" :key="i">{{ b }}</li>
        </ul>
        <div class="bd-cl__boxt" style="margin-top: 14px">切换（提升备机为主机）</div>
        <div class="bd-hint" style="line-height: 1.8">
          在<b>备机</b>上执行下面这条；它会先校验备份完整性再动手，<i class="bd-mono">--dry-run</i>
          只校验与打印覆盖清单、不碰任何现网文件。切换前务必确认<b>老主机确已停机</b>——
          两台同时跑等于两个控制面同时签发令牌、下发相反的策略，而现场没有任何一处会显示这件事。
        </div>
        <pre class="bd-cl__cmd">{{ cluster.promoteCmd }}</pre>
      </div>
    </div>

    <!-- 新建 / 提升管理员 -->
    <a-modal v-model:visible="adminOpen" title="新建管理员" :confirm-loading="saving" @ok="submitAdmin" @cancel="adminOpen = false">
      <a-form :model="adminForm" layout="vertical">
        <a-form-item label="账号" help="账号已存在时只改其角色，不会重置口令">
          <a-input v-model="adminForm.account" placeholder="如 sec.zhang" />
        </a-form-item>
        <a-form-item label="姓名">
          <a-input v-model="adminForm.name" placeholder="新建账号时的显示名" />
        </a-form-item>
        <a-form-item label="角色">
          <a-select v-model="adminForm.roleKey" placeholder="选择管理员角色">
            <a-option v-for="g in roles" :key="g.key" :value="g.key">{{ g.name }}（{{ g.perms.join('/') }}）</a-option>
          </a-select>
        </a-form-item>
        <a-form-item label="初始口令" help="留空用演示默认口令；新账号一律置首登强制改密">
          <a-input-password v-model="adminForm.password" placeholder="至少 6 位" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 改派角色 -->
    <a-modal v-model:visible="roleChangeOpen" title="改派管理员角色" :confirm-loading="saving" @ok="submitRoleChange" @cancel="roleChangeOpen = false">
      <a-form :model="roleChangeForm" layout="vertical">
        <a-form-item label="账号"><a-input v-model="roleChangeForm.account" disabled /></a-form-item>
        <a-form-item label="新角色">
          <a-select v-model="roleChangeForm.roleKey">
            <a-option v-for="g in roles" :key="g.key" :value="g.key">{{ g.name }}（{{ g.perms.join('/') }}）</a-option>
          </a-select>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 新建自定义角色 -->
    <a-modal v-model:visible="roleOpen" title="新建自定义角色" :confirm-loading="saving" @ok="submitRole" @cancel="roleOpen = false">
      <a-form :model="roleForm" layout="vertical">
        <a-form-item label="角色标识" help="小写字母/数字/短横，落库后不可改">
          <a-input v-model="roleForm.key" placeholder="如 east-op" />
        </a-form-item>
        <a-form-item label="角色名称"><a-input v-model="roleForm.name" placeholder="如 华东运维组" /></a-form-item>
        <a-form-item label="权限键" help="只能在三权内收缩；* 与 admins 不可选（那等于自造超管）">
          <a-checkbox-group v-model="roleForm.perms">
            <a-checkbox value="system">system · 系统配置</a-checkbox>
            <a-checkbox value="security">security · 安全策略</a-checkbox>
            <a-checkbox value="audit">audit · 审计只读</a-checkbox>
          </a-checkbox-group>
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { Message, Modal } from '@arco-design/web-vue';
import {
  getToken,
  api, type SystemBundle, type AdminRole, type AdminAccount, type ClusterInfo,
  type NotifyChannel, type NotifyChannelsResp, type NotifyEventSpec, type NotifyTestResp, type SaveNotifyChannelResp,
  type SmtpChannelConfig, type WebhookChannelConfig,
  type AuditForwardTarget, type AuditForwardResp, type SaveAuditForwardResp,
  type AuditForwardTestResp, type AuditForwardFlushResp,
  type SyslogTargetConfig, type HttpTargetConfig,
  type LicenseInfo
} from '@/lib/api';

// 支持从审计中心深链过来（/system/manage?tab=forward）：那一页的「日志外送」
// 入口指到这里，而不是在审计页上另放一份假的开关。
const route = useRoute();
const initialTab = (['admin', 'notify', 'forward', 'cluster', 'license'] as const)
  .find((k) => k === route.query.tab) ?? 'admin';
const tab = ref<'admin' | 'notify' | 'forward' | 'cluster' | 'license'>(initialTab);
const live = ref(false);
const err = ref('');
const kw = ref('');
const saving = ref(false);

/* 全部数据来自 GET /api/v1/system（admin_roles 表 + users 表）。
 * 此前这里有 MOCK_GROUPS / MOCK_ADMINS / MOCK_CLUSTER 三份编造数据，
 * 后端不可达时页面照样显示"五个管理组八个管理员三个集群节点"——那是全项目
 * 最容易被误读成"已实现"的地方。现在拉不到就空着并显式报错。 */
const roles = ref<AdminRole[]>([]);
const admins = ref<AdminAccount[]>([]);
/* 集群 = 控制面温备（PRD 15.5）。初值刻意是「不可判定」而不是「未配置备机」：
 * 后端还没答话时，说"没配备机"是在替它下结论——而这两件事下一步动作完全不同。 */
const cluster = ref<ClusterInfo>({
  mode: 'single', deployed: false, status: 'skip',
  summary: '', note: '正在读取备机同步状态…', rpo: '—',
  staleAfterSec: 900, nodes: [], boundaries: [], promoteCmd: '',
});

const filteredAdmins = computed(() => {
  const q = kw.value.trim().toLowerCase();
  if (!q) return admins.value;
  return admins.value.filter((a) => a.name.toLowerCase().includes(q) || a.account.toLowerCase().includes(q));
});

/* ── 颜色 / 文案 ── */
function powerColor(power: string) {
  switch (power) {
    case 'root': return '#F53F3F';
    case 'system': return '#165DFF';
    case 'security': return '#FF7D00';
    case 'audit': return '#00B42A';
    default: return '#722ED1'; // custom / 未分配
  }
}
function powerText(power: string) {
  switch (power) {
    case 'root': return '超级权限（含角色分配）';
    case 'system': return '系统配置权';
    case 'security': return '安全策略权';
    case 'audit': return '审计只读权';
    default: return '自定义收缩权';
  }
}
function statusText(status: string) {
  switch (status) {
    case 'active': return '启用';
    case 'disabled': return '禁用';
    case 'locked': return '锁定';
    case 'idle': return '挂起';
    default: return status || '—';
  }
}
/* 备机三态的配色与文案。fresh 之外一律红——「落后」与「从未同步」在切换那天
 * 的后果是同一个：手上没有一份足够新的备份。 */
function stateColor(state: string) {
  return state === 'fresh' ? '#00B42A' : '#F53F3F';
}
function stateText(state: string) {
  switch (state) {
    case 'fresh': return '同步新鲜';
    case 'stale': return '落后';
    case 'never': return '从未成功同步';
    default: return state || '—';
  }
}
function tagStyle(color: string) { return { color, background: color + '14', border: 'none' }; }
function avatarBg(name: string) {
  const palette = ['#165DFF', '#722ED1', '#00B42A', '#FF7D00', '#F53F3F'];
  let h = 0;
  for (const ch of name) h = (h + ch.charCodeAt(0)) % palette.length;
  return palette[h];
}

/* ── 读取 ── */
async function load(toast = false) {
  try {
    const b = await api<SystemBundle>('/system');
    roles.value = b.roles ?? [];
    admins.value = b.admins ?? [];
    cluster.value = b.cluster ?? cluster.value;
    live.value = true;
    err.value = '';
    if (toast) Message.success('已刷新');
  } catch (e) {
    live.value = false;
    roles.value = [];
    admins.value = [];
    err.value = '未连控制中心，管理员与角色数据不可用：' + (e instanceof Error ? e.message : String(e));
    if (toast) Message.error('刷新失败');
  }
}
function reload() { void load(true); }
onMounted(() => { void load(); void loadNotify(); void loadForward(); void loadLicense(); });

/* ── License（GET/POST /api/v1/license）── */
const lic = ref<LicenseInfo | null>(null);
const licPaste = ref('');
const licModeLabel = computed(() =>
  ({ demo: '演示模式 · 未导入 License（容量不限）', licensed: '已授权', expired: '已过期', invalid: '无效' }[lic.value?.mode ?? 'demo']));
const licModeColor = computed(() =>
  ({ demo: 'gray', licensed: 'green', expired: 'red', invalid: 'red' }[lic.value?.mode ?? 'demo']));
/** -1 = 读不出（不可判定）：显示 —，绝不显示 0（0 的含义是"空着"）。 */
function seat(n: number) { return n < 0 ? '—' : String(n); }
function cap(n: number) { return n > 0 ? String(n) : '不限'; }

async function loadLicense() {
  try { lic.value = await api<LicenseInfo>('/license'); } catch { lic.value = null; }
}

async function importLicense() {
  saving.value = true;
  try {
    // 原文直发：license 验签对象是文件原始字节，任何"重新序列化"都可能改变空白。
    const res = await fetch('/api/v1/license', {
      method: 'POST',
      headers: { Authorization: `Bearer ${getToken()}` },
      body: licPaste.value
    });
    const out = await res.json();
    if (!res.ok) throw new Error(out?.error ?? `${res.status}`);
    Message.success(`已导入：${out.manifest?.licensee ?? ''}（到期 ${out.manifest?.expiresAt ?? '—'}）`);
    licPaste.value = '';
    void loadLicense();
  } catch (e) {
    Message.error(`导入失败：${e instanceof Error ? e.message : e}`);
  } finally {
    saving.value = false;
  }
}

/* ── 消息通道（PRD ch15.2）────────────────────────────────────────────
 * 全部来自 GET /api/v1/notify/channels（notify_channels 表）。这一页刻意**没有**
 * 内置演示数据：编一条假的 SMTP 配置，比空着更容易让人以为告警已经能发出去。
 */
const channels = ref<NotifyChannel[]>([]);
const supportedKinds = ref<string[]>(['smtp', 'webhook', 'sms']);
const smsNote = ref('');
const notifyEvents = ref<NotifyEventSpec[]>([]);
const dropped = ref(0);
const notifyErr = ref('');

async function loadNotify(toast = false) {
  try {
    const b = await api<NotifyChannelsResp>('/notify/channels');
    notifyEvents.value = b.events ?? [];
    channels.value = b.channels ?? [];
    supportedKinds.value = b.supportedKinds?.length ? b.supportedKinds : supportedKinds.value;
    smsNote.value = b.smsNote ?? '';
    dropped.value = b.droppedNotices ?? 0;
    notifyErr.value = '';
    if (toast) Message.success('已刷新');
  } catch (e) {
    channels.value = [];
    const msg = e instanceof Error ? e.message : String(e);
    notifyErr.value = msg.includes('403')
      ? '当前角色无权查看消息通道（该页归系统管理员一权）'
      : '未连控制中心，消息通道不可用：' + msg;
    if (toast) Message.error('刷新失败');
  }
}
function reloadNotify() { void loadNotify(true); }

function kindText(k: string) {
  switch (k) {
    case 'smtp': return '邮件 SMTP';
    case 'webhook': return 'Webhook';
    // ★如实标注：这条通道不是短信协议实现，只是把消息 POST 给用户自己的对接服务。
    case 'sms': return '短信（webhook 适配）';
    default: return k;
  }
}
function kindColor(k: string) {
  return k === 'smtp' ? '#165DFF' : k === 'sms' ? '#722ED1' : '#00B42A';
}
function parseCfg<T>(raw: string): Partial<T> {
  try { return JSON.parse(raw || '{}') as Partial<T>; } catch { return {}; }
}
/** 目标列显示的是配置里真实要拨过去的那个地址，不是通道名。 */
function channelTarget(c: NotifyChannel) {
  if (c.kind === 'smtp') {
    const cfg = parseCfg<SmtpChannelConfig>(c.config);
    return cfg.host ? `${cfg.host}:${cfg.port || (cfg.tlsMode === 'implicit' ? 465 : 587)}` : '—';
  }
  return parseCfg<WebhookChannelConfig>(c.config).url || '—';
}
function lastAtText(ts?: number) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false });
}
function splitList(s: string) {
  return s.split(/[,，\s]+/).map((x) => x.trim()).filter(Boolean);
}

const chanOpen = ref(false);
const chanForm = reactive({
  id: '', name: '', kind: 'smtp', enabled: true,
  // smtp
  host: '', port: 587, tlsMode: 'starttls', authMode: 'none', username: '',
  from: '', serverName: '', caCert: '',
  // webhook / sms
  url: '', secretHeader: '',
  // 两类共用
  recipients: ''
});

function openChannel(c?: NotifyChannel) {
  Object.assign(chanForm, {
    id: '', name: '', kind: supportedKinds.value[0] ?? 'smtp', enabled: true,
    host: '', port: 587, tlsMode: 'starttls', authMode: 'none', username: '',
    from: '', serverName: '', caCert: '', url: '', secretHeader: '', recipients: ''
  });
  if (c) {
    chanForm.id = c.id; chanForm.name = c.name; chanForm.kind = c.kind; chanForm.enabled = c.enabled;
    if (c.kind === 'smtp') {
      const cfg = parseCfg<SmtpChannelConfig>(c.config);
      chanForm.host = cfg.host ?? ''; chanForm.port = cfg.port ?? 587;
      chanForm.tlsMode = cfg.tlsMode ?? 'starttls'; chanForm.authMode = cfg.authMode ?? 'none';
      chanForm.username = cfg.username ?? ''; chanForm.from = cfg.from ?? '';
      chanForm.serverName = cfg.serverName ?? '';
      chanForm.caCert = cfg.caCert ?? '';
      chanForm.recipients = (cfg.recipients ?? []).join(', ');
    } else {
      const cfg = parseCfg<WebhookChannelConfig>(c.config);
      chanForm.url = cfg.url ?? ''; chanForm.secretHeader = cfg.secretHeader ?? '';
      chanForm.recipients = (cfg.recipients ?? []).join(', ');
    }
  }
  chanOpen.value = true;
}

async function submitChannel() {
  if (!chanForm.name.trim()) { Message.warning('名称不能为空'); return; }
  const config: SmtpChannelConfig | WebhookChannelConfig = chanForm.kind === 'smtp'
    ? {
        host: chanForm.host.trim(), port: Number(chanForm.port) || 0,
        tlsMode: chanForm.tlsMode as SmtpChannelConfig['tlsMode'],
        serverName: chanForm.serverName.trim() || undefined,
        caCert: chanForm.caCert.trim() || undefined,
        authMode: chanForm.authMode as SmtpChannelConfig['authMode'],
        username: chanForm.username.trim() || undefined,
        from: chanForm.from.trim(),
        recipients: splitList(chanForm.recipients)
      }
    : {
        url: chanForm.url.trim(),
        secretHeader: chanForm.secretHeader.trim() || undefined,
        recipients: splitList(chanForm.recipients)
      };
  saving.value = true;
  try {
    const r = await api<SaveNotifyChannelResp>('/notify/channels', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: chanForm.id, name: chanForm.name.trim(), kind: chanForm.kind,
        enabled: chanForm.enabled, config
      })
    });
    // 后端「保存即校验」：配置存下了但当前不可用时要把原因原样显示，
    // 不能只报一句"已保存"——那正是"配置齐全却发不出去"的温床。
    if (r.warning) Message.warning(r.warning);
    else Message.success('消息通道已落库');
    chanOpen.value = false;
    await loadNotify();
  } catch (e) { opError(e, '保存失败'); } finally { saving.value = false; }
}

const secretOpen = ref(false);
const secretForm = reactive({ id: '', name: '', secret: '' });
function openSecret(c: NotifyChannel) {
  secretForm.id = c.id; secretForm.name = `${c.name}（${kindText(c.kind)}）`; secretForm.secret = '';
  secretOpen.value = true;
}
async function submitSecret() {
  if (!secretForm.secret) { Message.warning('凭据不能为空'); return; }
  saving.value = true;
  try {
    await api(`/notify/channels/${encodeURIComponent(secretForm.id)}/secret`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: secretForm.secret })
    });
    Message.success('凭据已更新（只写不读，界面只保留指纹）');
    secretOpen.value = false;
    await loadNotify();
  } catch (e) { opError(e, '保存失败'); } finally { saving.value = false; }
}

/** 测试连接：后端真发一条消息，成功与失败都是真实结果（不存在"假成功"）。 */
async function testChannel(c: NotifyChannel) {
  try {
    const r = await api<NotifyTestResp>(`/notify/channels/${encodeURIComponent(c.id)}/test`, { method: 'POST' });
    if (r.ok) Message.success(`「${c.name}」发送成功：${r.detail}`);
    else Message.error(`「${c.name}」发送失败：${r.detail}`);
  } catch (e) { opError(e, '测试失败'); } finally { await loadNotify(); }
}

function removeChannel(c: NotifyChannel) {
  Modal.warning({
    title: '删除消息通道',
    content: `删除「${c.name}」及其凭据。删掉最后一条通道后，账号被爆破锁定、终端被判不合规都不会再通知任何人（仍会落审计）。`,
    hideCancel: false,
    onOk: async () => {
      try {
        await api(`/notify/channels/${encodeURIComponent(c.id)}`, { method: 'DELETE' });
        Message.success('通道已删除');
        await loadNotify();
      } catch (e) { opError(e, '删除失败'); }
    }
  });
}

/* ── 写操作 ── */
function opError(e: unknown, fallback: string) {
  const msg = e instanceof Error ? e.message : String(e);
  if (msg.includes('409')) { Message.warning('操作被拒：系统必须保留至少一名超级管理员，或该角色仍有成员'); return; }
  if (msg.includes('403')) { Message.warning('当前角色无权执行该操作（分配管理员权限仅超级管理员持有）'); return; }
  Message.error(fallback);
}

/* ── 审计日志外送（PRD ch16 + ch21.6）────────────────────────────────
 * 全部来自 GET /api/v1/audit/forward（audit_forward_targets 表 + 现算的队列积压）。
 * 与消息通道一页同款：**没有**内置演示数据——编一条假的 SIEM 地址，
 * 比空着更容易让人以为审计已经在往外送了。
 */
const fwdTargets = ref<AuditForwardTarget[]>([]);
const fwdKinds = ref<string[]>(['syslog', 'http']);
const fwdQueueMax = ref(0);
const fwdNote = ref('');
const fwdErr = ref('');
/** 有过丢弃的出口：顶部单独拉一条红条，光靠表格里的小字没人会注意到。 */
const droppingTargets = computed(() => fwdTargets.value.filter((t) => t.dropped > 0));

async function loadForward(toast = false) {
  try {
    const b = await api<AuditForwardResp>('/audit/forward');
    fwdTargets.value = b.targets ?? [];
    fwdKinds.value = b.supportedKinds?.length ? b.supportedKinds : fwdKinds.value;
    fwdQueueMax.value = b.queueMax ?? 0;
    fwdNote.value = b.note ?? '';
    fwdErr.value = '';
    if (toast) Message.success('已刷新');
  } catch (e) {
    fwdTargets.value = [];
    const msg = e instanceof Error ? e.message : String(e);
    fwdErr.value = msg.includes('403')
      ? '当前角色无权查看审计外送配置（该页归系统管理员一权）'
      : '未连控制中心，审计外送配置不可用：' + msg;
    if (toast) Message.error('刷新失败');
  }
}
function reloadForward() { void loadForward(true); }

function fwdKindText(k: string) {
  return k === 'syslog' ? 'Syslog（RFC 5424 / TCP）' : k === 'http' ? 'HTTP JSON' : k;
}
function fwdKindColor(k: string) { return k === 'syslog' ? '#165DFF' : '#00B42A'; }
/** 目标列显示的是配置里真实要拨过去的那个地址，不是出口名。 */
function fwdTarget(t: AuditForwardTarget) {
  if (t.kind === 'syslog') {
    const cfg = parseCfg<SyslogTargetConfig>(t.config);
    if (!cfg.host) return '—';
    return `${cfg.tls ? 'tls' : 'tcp'}://${cfg.host}:${cfg.port || (cfg.tls ? 6514 : 514)}`;
  }
  return parseCfg<HttpTargetConfig>(t.config).url || '—';
}

const fwdOpen = ref(false);
const fwdForm = reactive({
  id: '', name: '', kind: 'syslog', enabled: true,
  // syslog
  host: '', port: 6514, tls: true, serverName: '', framing: 'octet', enterpriseId: '',
  // http
  url: '', secretHeader: '',
  // 两类共用
  caCert: ''
});

function openForward(t?: AuditForwardTarget) {
  Object.assign(fwdForm, {
    id: '', name: '', kind: fwdKinds.value[0] ?? 'syslog', enabled: true,
    host: '', port: 0, tls: true, serverName: '', framing: 'octet', enterpriseId: '',
    url: '', secretHeader: '', caCert: ''
  });
  if (t) {
    fwdForm.id = t.id; fwdForm.name = t.name; fwdForm.kind = t.kind; fwdForm.enabled = t.enabled;
    if (t.kind === 'syslog') {
      const cfg = parseCfg<SyslogTargetConfig>(t.config);
      fwdForm.host = cfg.host ?? '';
      fwdForm.tls = cfg.tls ?? false;
      fwdForm.port = cfg.port ?? 0;
      fwdForm.serverName = cfg.serverName ?? '';
      fwdForm.framing = cfg.framing ?? 'octet';
      fwdForm.enterpriseId = cfg.enterpriseId ?? '';
      fwdForm.caCert = cfg.caCert ?? '';
    } else {
      const cfg = parseCfg<HttpTargetConfig>(t.config);
      fwdForm.url = cfg.url ?? '';
      fwdForm.secretHeader = cfg.secretHeader ?? '';
      fwdForm.caCert = cfg.caCert ?? '';
    }
  }
  fwdOpen.value = true;
}

async function submitForward() {
  if (!fwdForm.name.trim()) { Message.warning('名称不能为空'); return; }
  const config: SyslogTargetConfig | HttpTargetConfig = fwdForm.kind === 'syslog'
    ? {
        host: fwdForm.host.trim(), port: Number(fwdForm.port) || 0, tls: fwdForm.tls,
        serverName: fwdForm.serverName.trim() || undefined,
        caCert: fwdForm.caCert.trim() || undefined,
        framing: fwdForm.framing as SyslogTargetConfig['framing'],
        enterpriseId: fwdForm.enterpriseId.trim() || undefined
      }
    : {
        url: fwdForm.url.trim(),
        secretHeader: fwdForm.secretHeader.trim() || undefined,
        caCert: fwdForm.caCert.trim() || undefined
      };
  saving.value = true;
  try {
    const r = await api<SaveAuditForwardResp>('/audit/forward', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: fwdForm.id, name: fwdForm.name.trim(), kind: fwdForm.kind,
        enabled: fwdForm.enabled, config
      })
    });
    // 后端「保存即校验」：存下了但当前不可用时把原因原样显示，不能只说"已保存"。
    if (r.warning) Message.warning(r.warning);
    else Message.success('外送出口已落库（只外送此后新产生的审计，历史不补发）');
    fwdOpen.value = false;
    await loadForward();
  } catch (e) { opError(e, '保存失败'); } finally { saving.value = false; }
}

const fwdSecretOpen = ref(false);
const fwdSecretForm = reactive({ id: '', name: '', secret: '' });
function openFwdSecret(t: AuditForwardTarget) {
  fwdSecretForm.id = t.id; fwdSecretForm.name = `${t.name}（${fwdKindText(t.kind)}）`; fwdSecretForm.secret = '';
  fwdSecretOpen.value = true;
}
async function submitFwdSecret() {
  if (!fwdSecretForm.secret) { Message.warning('凭据不能为空'); return; }
  saving.value = true;
  try {
    await api(`/audit/forward/${encodeURIComponent(fwdSecretForm.id)}/secret`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: fwdSecretForm.secret })
    });
    Message.success('凭据已更新（只写不读，界面只保留指纹）');
    fwdSecretOpen.value = false;
    await loadForward();
  } catch (e) { opError(e, '保存失败'); } finally { saving.value = false; }
}

/** 测试：后端真发一条标注为「连通性测试」的记录（seq=0，不冒充链上记录）。 */
async function testForward(t: AuditForwardTarget) {
  try {
    const r = await api<AuditForwardTestResp>(`/audit/forward/${encodeURIComponent(t.id)}/test`, { method: 'POST' });
    if (r.ok) Message.success(`「${t.name}」投递成功：${r.detail}`);
    else Message.error(`「${t.name}」投递失败：${r.detail}`);
  } catch (e) { opError(e, '测试失败'); } finally { await loadForward(); }
}

/** 立即投递：清零退避并当场跑一轮（SIEM 修好之后不必干等最长 15 分钟的退避）。 */
async function flushForward(t: AuditForwardTarget) {
  try {
    const r = await api<AuditForwardFlushResp>(`/audit/forward/${encodeURIComponent(t.id)}/flush`, { method: 'POST' });
    Message.success(`已触发投递（清零 ${r.reset} 条退避），当前积压 ${r.target?.queued ?? '—'}`);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes('409')) { Message.warning('该出口已停用，启用后才会投递'); return; }
    opError(e, '投递失败');
  } finally { await loadForward(); }
}

function removeForward(t: AuditForwardTarget) {
  Modal.warning({
    title: '删除外送出口',
    content: `删除「${t.name}」及其凭据，并丢弃队列里尚未送出的 ${t.queued} 条记录。`
      + '删除后新产生的审计不再送往该目标（审计本身仍照常落库）。',
    hideCancel: false,
    onOk: async () => {
      try {
        await api(`/audit/forward/${encodeURIComponent(t.id)}`, { method: 'DELETE' });
        Message.success('外送出口已删除');
        await loadForward();
      } catch (e) { opError(e, '删除失败'); }
    }
  });
}

const adminOpen = ref(false);
const adminForm = reactive({ account: '', name: '', roleKey: '', password: '' });
function openAdmin() {
  adminForm.account = ''; adminForm.name = ''; adminForm.password = '';
  adminForm.roleKey = roles.value[0]?.key ?? '';
  adminOpen.value = true;
}
async function submitAdmin() {
  if (!adminForm.account.trim() || !adminForm.roleKey) { Message.warning('账号与角色不能为空'); return; }
  saving.value = true;
  try {
    await api('/admins', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        account: adminForm.account.trim(), name: adminForm.name.trim(),
        roleKey: adminForm.roleKey, password: adminForm.password
      })
    });
    Message.success(`管理员「${adminForm.account.trim()}」已落库`);
    adminOpen.value = false;
    await load();
  } catch (e) { opError(e, '保存失败'); } finally { saving.value = false; }
}

const roleChangeOpen = ref(false);
const roleChangeForm = reactive({ account: '', roleKey: '' });
function openRoleChange(a: AdminAccount) {
  roleChangeForm.account = a.account;
  roleChangeForm.roleKey = a.roleKey || (roles.value[0]?.key ?? '');
  roleChangeOpen.value = true;
}
async function submitRoleChange() {
  saving.value = true;
  try {
    await api(`/admins/${encodeURIComponent(roleChangeForm.account)}/role`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ roleKey: roleChangeForm.roleKey })
    });
    Message.success('角色已改派');
    roleChangeOpen.value = false;
    await load();
  } catch (e) { opError(e, '改派失败'); } finally { saving.value = false; }
}

function removeAdmin(a: AdminAccount) {
  Modal.warning({
    title: '撤销管理员身份',
    content: `将「${a.name}（${a.account}）」降为普通用户并清空角色。账号本身保留（删号会让审计里的历史行为人对不上）。`,
    hideCancel: false,
    onOk: async () => {
      try {
        await api(`/admins/${encodeURIComponent(a.account)}`, { method: 'DELETE' });
        Message.success('已撤销管理员身份');
        await load();
      } catch (e) { opError(e, '撤销失败'); }
    }
  });
}

const roleOpen = ref(false);
const roleForm = reactive<{ key: string; name: string; perms: string[] }>({ key: '', name: '', perms: [] });
function openRole() {
  roleForm.key = ''; roleForm.name = ''; roleForm.perms = [];
  roleOpen.value = true;
}
async function submitRole() {
  if (!roleForm.key.trim() || !roleForm.name.trim() || !roleForm.perms.length) {
    Message.warning('标识、名称与至少一个权限键都必填');
    return;
  }
  saving.value = true;
  try {
    await api('/admin-roles', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: roleForm.key.trim(), name: roleForm.name.trim(), perms: roleForm.perms })
    });
    Message.success('自定义角色已落库');
    roleOpen.value = false;
    await load();
  } catch (e) { opError(e, '保存失败'); } finally { saving.value = false; }
}

function removeRole(g: AdminRole) {
  Modal.warning({
    title: '删除自定义角色',
    content: `删除「${g.name}」。仍有成员时后端会拒绝——请先把这 ${g.members} 名管理员改派到其他角色。`,
    hideCancel: false,
    onOk: async () => {
      try {
        await api(`/admin-roles/${encodeURIComponent(g.key)}`, { method: 'DELETE' });
        Message.success('角色已删除');
        await load();
      } catch (e) { opError(e, '删除失败'); }
    }
  });
}
</script>

<style scoped>
/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }

.bd-section-title { font-size: 15px; font-weight: 600; color: var(--bd-t1); margin-bottom: 14px; }

/* 三权分立说明条 */
.bd-sep__note {
  display: flex; align-items: flex-start; gap: 9px; margin-bottom: 16px;
  background: var(--bd-primary-1); border: 1px solid var(--bd-primary-b); border-radius: var(--bd-radius);
  padding: 12px 14px; font-size: 12.5px; line-height: 1.7; color: var(--bd-t2);
}
.bd-sep__note :deep(svg) { color: var(--bd-primary); font-size: 16px; flex: none; margin-top: 2px; }
.bd-sep__note b { color: var(--bd-t1); font-weight: 600; }

.bd-warn {
  display: flex; align-items: center; gap: 8px; margin-bottom: 14px; padding: 10px 14px;
  border-radius: var(--bd-radius); background: #fff3e8; color: #ad4b00; font-size: 12.5px;
}

/* 角色卡片行 */
.bd-groups { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 14px; }
.bd-gcard { position: relative; padding: 16px 16px 16px 20px; overflow: hidden; }
.bd-gcard__bar { position: absolute; left: 0; top: 0; bottom: 0; width: 4px; background: var(--pc); }
.bd-gcard__top { display: flex; align-items: center; gap: 8px; }
.bd-gcard__dot { width: 9px; height: 9px; border-radius: 50%; background: var(--pc); flex: none; }
.bd-gcard__name { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.bd-gcard__meta { display: flex; align-items: center; gap: 10px; margin: 12px 0 8px; }
.bd-gcard__power { font-size: 12px; font-weight: 600; }
.bd-gcard__members { margin-left: auto; font-size: 12px; color: var(--bd-t3); }
.bd-gcard__members b { font-size: 16px; font-weight: 700; color: var(--bd-t1); margin-right: 2px; }
.bd-gcard__perms { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px; }
.bd-perm { font-size: 11px; padding: 1px 7px; border-radius: 5px; background: var(--bd-fill-2); color: var(--bd-t2); }
.bd-gcard__scope { font-size: 12px; color: var(--bd-t3); line-height: 1.6; }
.bd-gcard__ops { margin-top: 10px; font-size: 12px; }

.bd-rolebar { display: flex; align-items: center; gap: 12px; margin-top: 14px; }
.bd-hint { font-size: 12px; color: var(--bd-t3); }

/* 搜索框内 input 复位 */
.bd-searchbox input { border: none; background: transparent; outline: none; flex: 1; min-width: 0; font-size: 13px; color: var(--bd-t1); }
.bd-btn--ghost :deep(svg), .bd-btn :deep(svg) { font-size: 14px; }

/* 消息通道表 */
.bd-target { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bd-lastdetail {
  display: block; max-width: 320px; font-size: 11.5px; color: var(--bd-t3);
  line-height: 1.5; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

/* 集群（控制面温备） */
.bd-cl__head {
  display: flex; gap: 10px; align-items: flex-start;
  padding: 14px 16px; border-radius: 8px; margin-bottom: 14px;
}
.bd-cl__head.ok { background: rgb(0 180 42 / 8%); }
.bd-cl__head.bad { background: rgb(245 63 63 / 8%); }
.bd-cl__head :deep(svg) { font-size: 17px; flex: none; margin-top: 1px; }
.bd-cl__head.ok :deep(svg) { color: #00B42A; }
.bd-cl__head.bad :deep(svg) { color: #F53F3F; }
.bd-cl__sum { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.bd-cl__note { font-size: 12.5px; color: var(--bd-t3); line-height: 1.7; margin-top: 4px; }
.bd-cl__box { margin-top: 16px; padding: 16px; }
.bd-cl__boxt { font-size: 13px; font-weight: 600; color: var(--bd-t1); margin-bottom: 8px; }
.bd-cl__list { margin: 0 0 0 18px; padding: 0; }
.bd-cl__list li { font-size: 12.5px; color: var(--bd-t3); line-height: 1.9; }
.bd-cl__cmd {
  margin: 8px 0 0; padding: 10px 12px; border-radius: 7px;
  background: var(--bd-fill-2); color: var(--bd-t2);
  font-family: var(--bd-mono-font, ui-monospace, SFMono-Regular, Menlo, monospace);
  font-size: 12px; line-height: 1.7; white-space: pre-wrap; word-break: break-all;
}

/* 空态 */
.bd-empty { text-align: center; color: var(--bd-t3); padding: 28px 0; }
.bd-empty--lg {
  display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px;
  min-height: 300px; padding: 32px 24px;
}
.bd-empty--lg :deep(svg) { font-size: 30px; color: var(--bd-t4); }
.bd-empty__t { font-size: 15px; font-weight: 600; color: var(--bd-t2); }
.bd-empty__d { font-size: 12.5px; color: var(--bd-t3); line-height: 1.8; max-width: 620px; }
.bd-nev { margin: 10px 0 4px; padding: 10px 12px; border-radius: 6px; background: var(--bd-fill-1); }
.bd-nev__h { font-size: 12.5px; font-weight: 600; color: var(--bd-t2); margin-bottom: 7px; }
.bd-nev__i { display: flex; gap: 10px; align-items: flex-start; padding: 4px 0; font-size: 12px; line-height: 1.6; }
.bd-nev__i.off { opacity: 0.72; }
.bd-nev__n { flex: none; width: 168px; display: flex; align-items: center; gap: 5px; color: var(--bd-t1); }
.bd-nev__ok { color: var(--bd-success); }
.bd-nev__no { color: var(--bd-t3); }
.bd-nev__s { flex: 1; color: var(--bd-t3); }
</style>
