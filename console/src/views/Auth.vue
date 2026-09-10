<template>
  <div class="bd-page">
    <!-- 本页对认证源 / 策略 / 待批准入都没有任何演示回落（MOCK_RULES 只是「自适应认证规则」页签那个
         常驻的交互沙盘，与 live 无关），所以离线标签按 DESIGN.md §2「拉不到就不画的页」口径写
         「数据未读取」（红）——此前手写的橙色「降级演示」是在说一件没发生的事：那一刻页面上什么
         演示数据都没有，只有一个因读取失败而为空的列表。live 三态：undefined = 首轮读取还没回来，
         不画标签（否则初值 false 会先闪一下红）。 -->
    <PageHeader title="认证源接入" subtitle="统一身份源 · 自适应认证：身份 × 终端 × 行为动态定级"
      :live="live" off-text="数据未读取" off-color="red" />

    <!-- Tab 切换：真 button（可 Tab、可回车），选中态由 aria-selected 表达 -->
    <div class="bd-tabs" role="tablist">
      <button type="button" class="bd-tab" role="tab" :aria-selected="tab === 'source'" @click="tab = 'source'">认证源</button>
      <button type="button" class="bd-tab" role="tab" :aria-selected="tab === 'policy'" @click="tab = 'policy'">认证策略</button>
      <button type="button" class="bd-tab" role="tab" :aria-selected="tab === 'rule'" @click="tab = 'rule'">自适应认证规则</button>
    </div>

    <!-- ============ 认证源（真落库、真探测、真参与登录）============ -->
    <div v-show="tab === 'source'">
      <div class="bd-srctoolbar">
        <div class="bd-srctoolbar__sub">
          <!-- ★列表读取失败时不许写「已接入 0 个」：那与「真没接入」同形，管理员会去重新接入一份 LDAP。
               首轮读取还在路上时同理：那一刻 recs 是初值空数组，写「已接入 0 个」是在报一个还没问出来的数。 -->
          <template v-if="!loaded">正在读取身份源清单…</template>
          <template v-else-if="srcErr">身份源数量不可判定（列表未读取）</template>
          <template v-else>已接入 <b>{{ recs.length }}</b> 个身份源</template><!--
            ★聚合拿不到时整条不渲染而不是显示 0：「0 个绑定账号」与「没拿到计数」是两回事。
          --><template v-if="sources.length"> · 外部目录已绑定 <b>{{ totalBoundExternal }}</b> 个账号</template>
          <!-- "已绑定账号"= auth_source_bindings 的真实条数（外部用户登录过一次即建绑定），
               不是目录纳管用户数——后者要全量遍历 LDAP，白帝没有那个能力。 -->
<!--
            ★这句话曾经是「登录按『本地目录 → 外部源（按优先级）』依次询问」，而"依次询问"
            在 wave8 认证域路由落地时就被删掉了（api.routeDirectory 返回值长度恒 ≤1）。
            留着它的后果不只是文案陈旧：管理员会据此以为"把某个源的优先级调小 = 让它先被问到"，
            于是去调一个对登录判定毫无影响的旋钮，而真正决定问谁的是用户在登录页选的认证域。
            -->
          <span class="bd-srchint">登录先查本地目录；未命中则只问<b>用户选定的那一个认证域</b>——一次登录只把口令交给一台服务器</span>
        </div>
        <button class="bd-btn" @click="openSrcCreate"><icon-plus />接入认证源</button>
      </div>

      <!-- 聚合（/authsrc）只喂账号计数。它拉不到时卡片上的「已绑定账号」本来就画「—」，
           这里把后端原话摆出来：不然那几个「—」看起来像是"还没有人登录过"。 -->
      <div v-if="aggErr" class="bd-notice bd-notice--danger">
        <icon-exclamation-circle-fill />
        <span>账号计数未读取：{{ aggErr }}——卡片上的「已绑定账号」显示为「—」，不是 0。</span>
      </div>

      <div class="bd-srcgrid">
        <!-- 首屏骨架：改造前这块在请求在途期间直接画「尚未接入任何认证源」——那句话在
             /authsrc/sources 还没回来的 0.2~1s 里是**假的**，而它与真的空库一模一样。
             骨架把"还没拿到"画成还没拿到；三张是占位数量，不代表将来有几条。 -->
        <template v-if="!loaded">
          <div v-for="i in 3" :key="'sk' + i" class="bd-card bd-srccard bd-srccard--sk">
            <SkeletonBlock kind="card" :rows="3" />
          </div>
        </template>
        <div v-for="s in recs" :key="s.id" class="bd-card bd-srccard">
          <div class="bd-srccard__top">
            <span class="bd-srcicon" :class="'bd-srcicon--' + kindTone(s.kind)">
              <component :is="kindIcon(s.kind)" />
            </span>
            <div class="bd-srccard__id">
              <div class="bd-srccard__name">
                {{ s.name }}
                <span v-if="s.kind === 'local'" class="bd-primarytag"><icon-star-fill />内置</span>
              </div>
              <span class="bd-tg" :class="'bd-tg--' + kindTone(s.kind)">{{ kindLabel(s.kind) }}</span>
            </div>
            <!-- 启用/停用取自库里的 auth_sources.enabled（登录链路真读它），状态点走全局语义类。 -->
            <span class="bd-st bd-srccard__st" :class="s.enabled ? 'bd-st--ok' : 'bd-st--off'">
              <span class="d" />
              {{ s.enabled ? '已启用' : '已停用' }}
            </span>
          </div>

          <!-- 探测结果：真去连目录 / 拉发现文档 -->
          <div v-if="probeOf(s.id)" class="bd-probe" :class="probeOf(s.id)!.ok ? 'ok' : 'bad'">
            <component :is="probeOf(s.id)!.ok ? 'icon-check-circle-fill' : 'icon-close-circle-fill'" />
            <span>{{ probeOf(s.id)!.detail }}</span>
            <span v-if="probeOf(s.id)!.elapsedMs !== undefined" class="bd-probe__ms">
              {{ probeOf(s.id)!.elapsedMs }}ms
            </span>
          </div>

          <!-- RADIUS 安全逃生舱的常驻警示：管理员要能在列表上**一眼**看出哪条源放弃了这层保护。
               只在「已放弃」那一档画——默认姿态（要求应答带 Message-Authenticator）是常态，
               给每条正常的源都挂一句「保护已启用」只会把真正该看的那条淹掉。
               判据见 radiusWaiver()（与后端执行方逐字同构）。 -->
          <div v-if="s.kind === 'radius' && radiusWaiver(s)" class="bd-srccard__waive">
            <icon-exclamation-circle-fill />
            <span>{{ RADIUS_WAIVER_BADGE }}</span>
          </div>

          <div class="bd-srccard__foot">
            <div class="bd-srccard__kv">
              <span>{{ s.kind === 'local' ? '本地账号' : '已绑定账号' }}</span>
              <b>{{ boundText(s.id) }}</b>
            </div>
            <div class="bd-srccard__kv">
              <span>凭据</span>
              <b v-if="s.kind === 'local'">—</b>
              <b v-else-if="s.hasSecret" class="bd-mono">已配置 · {{ s.secretFingerprint || '••••' }}</b>
              <b v-else class="bd-warn">未配置</b>
            </div>
            <!-- 操作列是真 <button>：可 Tab、可回车、探测中禁用（禁用态由全局 button.bd-link[disabled] 画）。
                 「内置不可改」不是动作而是一句说明，仍用文本，不做成点不动的按钮。 -->
            <span class="bd-acts bd-srccard__acts">
              <template v-if="s.kind !== 'local'">
                <button type="button" class="bd-link" :disabled="probing === s.id" @click="probe(s)">
                  {{ probing === s.id ? '测试中…' : '测试连接' }}
                </button>
                <button type="button" class="bd-link" @click="openSrcEdit(s)">编辑</button>
                <button type="button" class="bd-link bd-link--danger" @click="removeSource(s)">删除</button>
              </template>
              <span v-else class="bd-srccard__note">内置不可改</span>
            </span>
          </div>
        </div>
        <!-- 空态分两种处境，且**读取失败排在前面**：本地目录是内置行，后端正常时这份列表不会为空，
             所以"列表为空"在实际部署里几乎只有一种成因——没读到。此前两种处境共用一句
             「尚未接入任何认证源」，/authsrc/sources 回 5xx 时管理员看到的与全新库一模一样。 -->
        <div v-if="loaded && !recs.length" class="bd-card bd-srcgrid__empty">
          <EmptyState v-if="srcErr" size="md" tone="danger" title="认证源列表未读取"
            :desc="`${srcErr}——这里显示的不是「尚未接入任何认证源」，别据此重新接入`" />
          <EmptyState v-else size="md" title="尚未接入任何认证源">
            <template #action><button class="bd-btn" @click="openSrcCreate"><icon-plus />接入认证源</button></template>
          </EmptyState>
        </div>
      </div>

      <!-- 待批清单拉不到 ≠ 没有待批：可能正有人被「需管理员批准」那道闸挡着等批。
           不说出来的话，这块常态就是不渲染的，失败与"没人等"在页面上完全同形。 -->
      <div v-if="admitErr" class="bd-notice bd-notice--danger bd-admit__err">
        <icon-exclamation-circle-fill />
        <span>待批外部身份准入未读取：{{ admitErr }}——这里没有列出待批条目，不代表没有人在等批准。</span>
      </div>

      <!-- 待批外部身份准入。★它是「需管理员批准」那档唯一的批复入口，
           删掉这块等于把闸挡住的人永远挡在外面。 -->
      <div v-if="admissions.length" class="bd-admit">
        <div class="bd-section-title">
          待批外部身份准入
          <span class="bd-admit__count">{{ admissions.length }} 条</span>
        </div>
        <div class="bd-admit__hint">
          这些身份已通过所属目录的认证，但该认证源配置了「需管理员批准后才建号」。
          批准后他们**下次登录**才会建号（用登录那一刻的真实身份，不是申请时的快照）。
        </div>
        <div v-for="a in admissions" :key="a.approvalId" class="bd-card bd-admit__row">
          <div class="bd-admit__who">
            <b>{{ a.displayName || a.username || '—' }}</b>
            <span class="bd-admit__acct">{{ a.username || '—' }}</span>
            <span class="bd-tg">{{ a.sourceName }}</span>
          </div>
          <div class="bd-admit__meta">
            <span v-if="a.email">{{ a.email }}</span>
            <span v-if="a.groups?.length">组：{{ a.groups.join('、') }}</span>
            <span class="bd-mono bd-admit__sub" :title="a.subject">{{ a.subject }}</span>
            <span>申请于 {{ a.createdAt }}</span>
          </div>
          <div class="bd-admit__act">
            <a-button size="mini" type="primary" :loading="admitBusy === a.approvalId"
              @click="decideAdmission(a, 'approved')">批准</a-button>
            <a-button size="mini" status="danger" :loading="admitBusy === a.approvalId"
              @click="decideAdmission(a, 'rejected')">拒绝</a-button>
          </div>
        </div>
      </div>
    </div>

    <!-- ============ 认证策略（FR-AUTH-12：PC/WEB 与 移动端 分栏认证）============ -->
    <div v-show="tab === 'policy'">
      <div class="bd-srctoolbar">
        <div class="bd-srctoolbar__sub">
          按<b>用户目录</b>分组编排 ·
          <!-- ★读取失败时不写「共 0 条」：那与「一条策略都没配」同形，而后者在页面上意味着"全体走默认策略"。
               首轮在途同理，见认证源页签那条注释。 -->
          <template v-if="!loaded">正在读取策略…</template>
          <template v-else-if="polErr">策略数不可判定（未读取）</template>
          <template v-else>共 <b>{{ policies.length }}</b> 条策略</template>
          · 每条声明<b>可接受的二次认证方式</b>与自适应规则（主认证方式由认证源与认证域路由决定，不在这里配）
          <span class="bd-srchint">自适应规则由登录链路实时求值：命中增强条件且未被豁免即要求二次认证</span>
        </div>
        <button class="bd-btn" @click="openCreate"><icon-plus />新增策略</button>
      </div>

      <!-- /authpolicy 是这一页签唯一的数据源（策略 + 目录 + 能力声明 + 组织/用户组候选），拉不到时
           下面按目录分组的列表整个为空、能力说明只剩一个标题——与「一条策略都没配」完全同形。
           这里把后端原话摆出来，且排在能力说明之前。 -->
      <!-- 首屏骨架同认证源页签：能力说明与分组列表都出自 /authpolicy 那一次请求。 -->
      <div v-if="!loaded" class="bd-card bd-capbox"><SkeletonBlock kind="card" :rows="4" /></div>

      <div v-else-if="polErr" class="bd-card">
        <EmptyState size="md" tone="danger" title="认证策略未读取"
          :desc="`${polErr}——这里显示的不是「没有策略」；目录、能力声明与适用范围候选也一并没有读到`" />
      </div>

      <!-- 能力说明：哪几条能判、判据是什么；判不了的在这里就说清，不留"配了不生效"的想象空间。
           读取失败时不画：能力清单本来就是 /authpolicy 那一次请求带回来的，失败了就只剩一个空壳。 -->
      <div v-else class="bd-card bd-capbox">
        <div class="bd-capbox__h"><icon-info-circle />规则生效说明</div>
        <div class="bd-caprow" v-for="c in capabilities" :key="c.key" :class="{ off: !c.available }">
          <span class="bd-tg" :class="c.kind === 'enhance' ? 'bd-tg--gold' : 'bd-tg--green'">
            {{ c.kind === 'enhance' ? '增强' : '豁免' }}
          </span>
          <b class="bd-caprow__n">{{ c.label }}</b>
          <span v-if="!c.available" class="bd-tg bd-tg--off">本版本不可用</span>
          <span class="bd-caprow__d">{{ c.available ? c.effect : c.reason }}</span>
        </div>
      </div>

      <div v-for="g in grouped" :key="g.dir" class="bd-pgroup">
        <div class="bd-pgroup__head">
          <span class="bd-srcicon bd-pgroup__ic" :class="'bd-srcicon--' + typeTone(g.dir)"><component :is="srcIcon(g.dir as any)" /></span>
          <span class="bd-pgroup__name">{{ g.name }}</span>
          <span class="bd-pgroup__cnt">{{ g.list.length }} 条策略</span>
        </div>
        <!-- 已接入认证源却零策略：这不是"还没配"，是一条正在生效的认证降级。 -->
        <div v-if="g.warning" class="bd-notice bd-notice--warn bd-pgroup__warn">
          <icon-exclamation-circle-fill /><span>{{ g.warning }}</span>
        </div>

        <div class="bd-card bd-pcard" :class="{ off: !p.enabled }" v-for="p in g.list" :key="p.id">
          <!-- 行头：名称 + 范围 + 默认/优先级 -->
          <div class="bd-pcard__head">
            <div class="bd-pcard__title">
              <span class="bd-pcard__name">{{ p.name }}</span>
              <span v-if="p.isDefault" class="bd-tg bd-tg--default">默认策略</span>
              <span class="bd-tg bd-tg--pri">优先级 {{ p.priority }}</span>
              <span v-if="!p.enabled" class="bd-tg bd-tg--off">已停用</span>
            </div>
            <!-- 真 <button>；默认策略那一格是**禁用**的删除位而不是另一个可点的东西，
                 禁用态与不可聚焦由全局 button.bd-link[disabled] 一处给。 -->
            <span class="bd-acts bd-pcard__acts">
              <button type="button" class="bd-link" @click="openEdit(p)"><icon-edit />编辑</button>
              <button
                v-if="!p.isDefault"
                type="button"
                class="bd-link bd-link--danger"
                @click="removePolicy(p)"
              ><icon-delete />删除</button>
              <button v-else type="button" class="bd-link" disabled title="默认策略不可删除"><icon-lock />默认</button>
            </span>
          </div>
          <div class="bd-pcard__scope">
            <span v-if="p.scope">{{ p.scope }}</span>
            <!-- 真正参与匹配的是下面这些主体；文字说明只是备注 -->
            <template v-if="p.isDefault">
              <span class="bd-tg bd-tg--pri">该目录全体用户（默认策略）</span>
            </template>
            <template v-else-if="(p.scopeOrgs || []).length || (p.scopeGroups || []).length">
              <span v-for="o in p.scopeOrgs || []" :key="'o' + o" class="bd-tg bd-tg--green">
                组织 {{ orgName(o) }}<em class="bd-sub">含子部门</em>
              </span>
              <span v-for="g in p.scopeGroups || []" :key="'g' + g" class="bd-tg bd-tg--gold">
                用户组 {{ groupName(g) }}
              </span>
              <span class="bd-tg bd-tg--pri">生效账号 {{ effectiveOf(p).length }}</span>
            </template>
            <!-- 未绑定范围的非默认策略匹配不到任何人：如实说出来，别让它看着像在生效 -->
            <span v-else class="bd-tg bd-tg--warnbox">未绑定适用范围，不会命中任何账号</span>
          </div>

          <!-- 二次认证方式。不分 PC/移动端：三端走同一个 /portal/login，请求里没有端标识 -->
          <div class="bd-plat">
            <div class="bd-plat__row">
              <span class="bd-plat__k">可接受的二次认证方式</span>
              <template v-if="(p.secondary || []).length">
                <span v-for="s in p.secondary" :key="s" class="bd-tg bd-tg--sec">{{ secondaryLabel(s) }}</span>
                <span class="bd-plat__none">· 演示验证码对本策略覆盖的账号不成立</span>
              </template>
              <span v-else class="bd-plat__none">未声明（要求二次认证时，未绑认证器的账号可走演示验证码回落）</span>
            </div>
          </div>

          <!-- 自适应摘要 -->
          <div class="bd-pcard__foot">
            <span class="bd-foot__k">自适应</span>
            <span v-for="e in exemptChips(p)" :key="'ex-' + e" class="bd-mtg bd-mtg--ok"><icon-check-circle />{{ e }}</span>
            <span v-for="e in enhanceChips(p)" :key="'en-' + e" class="bd-mtg bd-mtg--warn"><icon-exclamation-circle />{{ e }}</span>
            <span v-if="!hasAdaptive(p)" class="bd-plat__none">未启用自适应</span>
          </div>
          <!-- ★同时开了「豁免」与「风险增强」时必须写出谁赢：风险条件命中时豁免不生效。
               只并排列标签的话，绿色的「免二次」在视觉上像结论，语义会被读反。 -->
          <div v-if="exemptVsRisk(p)" class="bd-pcard__note">
            <icon-info-circle /><span>{{ exemptVsRisk(p) }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 认证策略 编辑抽屉 -->
    <a-drawer
      v-model:visible="editVisible"
      :width="560"
      :title="editing.id ? '编辑认证策略' : '新增认证策略'"
      ok-text="保存"
      :on-before-ok="savePolicy"
      @cancel="editVisible = false"
    >
      <div class="bd-form">
        <div class="bd-form__row">
          <label class="bd-form__lab">策略名称 <em>*</em></label>
          <a-input v-model="editing.name" placeholder="如：财务部 · 高敏加严" allow-clear />
        </div>
        <div class="bd-form__2col">
          <div class="bd-form__row">
            <label class="bd-form__lab">所属用户目录 <em>*</em></label>
            <a-select v-model="editing.directory" placeholder="选择目录" :disabled="editing.isDefault">
              <a-option v-for="s in directorySources" :key="s.key" :value="s.key">{{ s.name }}</a-option>
            </a-select>
          </div>
          <div class="bd-form__row">
            <label class="bd-form__lab">优先级（小者先匹配）</label>
            <a-input-number v-model="editing.priority" :min="1" :max="999" :disabled="editing.isDefault" />
          </div>
        </div>
        <div class="bd-form__row">
          <label class="bd-form__lab">适用范围说明（仅备注）</label>
          <a-input v-model="editing.scope" placeholder="如：研发中心 / 架构组、外部协作安全组" allow-clear />
        </div>
        <!-- ★真正参与匹配的适用范围。默认策略覆盖该目录全体用户，不需要（也不能）绑定主体 -->
        <template v-if="!editing.isDefault">
          <div class="bd-form__2col">
            <div class="bd-form__row">
              <label class="bd-form__lab">适用组织（含子部门） <em>*</em></label>
              <a-select v-model="editing.scopeOrgs" multiple allow-clear placeholder="不按组织匹配">
                <a-option v-for="o in orgOpts" :key="o.id" :value="o.id">
                  {{ o.name }}（{{ o.accounts.length }} 人）
                </a-option>
              </a-select>
            </div>
            <div class="bd-form__row">
              <label class="bd-form__lab">适用用户组</label>
              <a-select v-model="editing.scopeGroups" multiple allow-clear placeholder="不按用户组匹配">
                <a-option v-for="g in groupOpts" :key="g.id" :value="g.id">
                  {{ g.name }}（{{ g.accounts.length }} 人）
                </a-option>
              </a-select>
            </div>
          </div>
          <div class="bd-form__hint" :class="{ bad: !editingScopeCount }">
            <template v-if="editing.scopeOrgs.length || editing.scopeGroups.length">
              当前范围展开后覆盖 <b>{{ editingScopeCount }}</b> 个账号（与登录判定用的是同一次展开）
            </template>
            <template v-else>
              非默认策略必须至少选一个组织或用户组，否则它匹配不到任何账号（保存会被拒绝）
            </template>
          </div>
        </template>
        <div v-else class="bd-form__hint">默认策略覆盖该用户目录的全体账号，无需绑定组织/用户组。</div>

        <!-- ★别在这里加回「主认证方式」下拉：策略匹配第一步就按目录筛，一条策略只作用于
             已被该目录认出来的人，对他说"主认证用证书"不可能生效（同义反复，不是没接线）。
             也别按 PC / 移动端分栏：三端走同一个 /portal/login，请求里没有端标识。 -->
        <div class="bd-form__hint bd-form__hint--lead">
          主认证方式由<b>认证源配置</b>与登录时的<b>认证域路由</b>决定（命中即只问该源），
          不在这里配。<b>PC 与移动端也不分栏</b>——三端走同一个 /portal/login，请求里没有端标识。
          本抽屉只配<b>二次认证</b>——它是真执行的：已注册 passkey/TOTP 的账号无条件强制，
          策略只能加强不能削弱。
        </div>
        <div class="bd-form__row">
          <label class="bd-form__lab">可接受的二次认证方式（可多选）</label>
          <a-select v-model="editing.secondary" multiple placeholder="留空 = 不额外约束" :max-tag-count="3">
            <a-option v-for="m in SECONDARY_OPTS" :key="m.value" :value="m.value" :disabled="!methodAvailable(m.value)">
              {{ m.label }}{{ methodAvailable(m.value) ? '' : '（未实现）' }}
            </a-option>
          </a-select>
        </div>
        <!-- ★这一栏的**唯一执行语义**要说清楚，否则它就是又一个装饰。
             它不决定"用哪个因子"（那由账号已注册的认证器决定：passkey > TOTP）。 -->
        <div class="bd-form__hint">
          选中后：本策略要求二次认证、而该账号<b>既没绑 passkey 也没绑 TOTP</b> 时，
          一律回「请先注册」，<b>不接受演示验证码回落</b>。留空则保持回落（行为不变）。
          这一栏不决定用哪个因子——那由账号已注册的认证器决定（passkey 优先于 TOTP）。
        </div>
        <!-- 方式能力说明：置灰的是未实现的（后端能力声明同源，保存也会被拒）。 -->
        <div v-if="totpMethod" class="bd-form__hint bd-form__hint--gap">
          <b>TOTP 动态口令</b>：{{ totpMethod.effect }}
          <template v-if="frozenMethodNote">　<span class="bd-form__hint-dim">{{ frozenMethodNote }}</span></template>
        </div>

        <!-- 自适应 · 增强认证（命中则要求二次认证；每条开关下都写清判据） -->
        <div class="bd-form__sec">
          <div class="bd-form__sech">自适应 · 增强认证（命中则要求二次认证）</div>
          <div class="bd-form__rules">
            <div class="bd-rulerow">
              <a-checkbox v-model="editing.enhance.always" :disabled="!can('enhance.always')">
                范围内一律二次认证
              </a-checkbox>
              <div class="bd-rulerow__d">{{ capText('enhance.always') }}</div>
            </div>
            <div class="bd-rulerow">
              <a-checkbox v-model="editing.enhance.weakPwd" :disabled="!can('enhance.weakPwd')">弱密码</a-checkbox>
              <div class="bd-rulerow__d">{{ capText('enhance.weakPwd') }}</div>
            </div>
            <div class="bd-rulerow">
              <a-checkbox v-model="editing.enhance.offHours" :disabled="!can('enhance.offHours')">非工作时段</a-checkbox>
              <div class="bd-rulerow__d">{{ capText('enhance.offHours') }}</div>
              <div v-if="editing.enhance.offHours" class="bd-rulerow__cfg">
                <span>工作时段</span>
                <a-time-picker v-model="editing.enhance.workStart" format="HH:mm" class="bd-rulerow__time" />
                <span>—</span>
                <a-time-picker v-model="editing.enhance.workEnd" format="HH:mm" class="bd-rulerow__time" />
                <a-select v-model="editing.enhance.workDays" multiple placeholder="工作日（默认周一至周五）" class="bd-rulerow__days">
                  <a-option v-for="d in WEEKDAYS" :key="d.value" :value="d.value">{{ d.label }}</a-option>
                </a-select>
              </div>
            </div>
            <!-- ★不可用的规则置灰 + 说明原因，而不是让它看起来能开、开了又静默不生效 -->
            <div class="bd-rulerow off">
              <a-checkbox :model-value="false" disabled>异地登录</a-checkbox>
              <span class="bd-tg bd-tg--off">本版本不可用</span>
              <div class="bd-rulerow__d">{{ capText('enhance.geoAnomaly') }}</div>
            </div>
          </div>
        </div>

        <!-- 自适应 · 豁免（只压制上面的策略性增强，压不掉已注册 passkey 的强制断言） -->
        <div class="bd-form__sec">
          <div class="bd-form__sech">自适应 · 免二次认证豁免</div>
          <div class="bd-form__rules">
            <div class="bd-rulerow">
              <a-checkbox v-model="editing.exempt.trustedDevice" :disabled="!can('exempt.trustedDevice')">
                使用授信终端时
              </a-checkbox>
              <div class="bd-rulerow__d">{{ capText('exempt.trustedDevice') }}</div>
            </div>
            <div class="bd-rulerow">
              <a-checkbox v-model="editing.exempt.trustedNetwork" :disabled="!can('exempt.trustedNetwork')">
                满足可信网络时
              </a-checkbox>
              <div class="bd-rulerow__d">{{ capText('exempt.trustedNetwork') }}</div>
              <div v-if="editing.exempt.trustedNetwork" class="bd-rulerow__cfg">
                <a-input-tag v-model="editing.exempt.networks" placeholder="输入 CIDR 后回车，如 10.8.0.0/16" allow-clear />
              </div>
              <div v-if="editing.exempt.trustedNetwork && !editing.exempt.networks.length" class="bd-form__hint bad">
                未配置网段时这条豁免永远不会命中，保存会被拒绝
              </div>
            </div>
            <div class="bd-rulerow off">
              <a-checkbox :model-value="false" disabled>Windows 域环境时</a-checkbox>
              <span class="bd-tg bd-tg--off">本版本不可用</span>
              <div class="bd-rulerow__d">{{ capText('exempt.winDomain') }}</div>
            </div>
          </div>
          <div class="bd-form__hint">
            豁免只压制上面的策略性增强要求：<b>已注册 passkey 的账号仍会被强制断言</b>，策略只能加强、不能削弱。
          </div>
        </div>

        <div class="bd-form__2col">
          <div class="bd-form__row">
            <label class="bd-form__lab">启用策略</label>
            <a-switch v-model="editing.enabled" />
          </div>
        </div>
      </div>
    </a-drawer>

    <!-- ============ 自适应认证规则（P6 可视化规则构建器）============ -->
    <div v-show="tab === 'rule'" class="bd-rulewrap">
      <div class="bd-rulemain">
        <div class="bd-ruleintro bd-card">
          <icon-safe class="bd-ruleintro__ic" />
          <div>
            按 <b>优先级从上至下</b>逐条求值，命中第一条规则即采用其动作。拖拽手柄可调整优先级；
            条件以「身份 × 终端 × 行为」信号组合，替代手写 JSON 编排。
            <!-- ★如实标注：这一页是交互沙盘，改动不落库、不参与登录判定。
                 真正生效的自适应规则在「认证策略」tab（后端 authpolicy.Evaluate 实时求值）。 -->
            <!-- ★正文必须裹在一个 <span> 里：这一层是 flex 容器，散着的文本段与 <b>/<button>
                 会各自变成一个 flex item，整句被切成七八块竖排（1280 下尤其明显）。 -->
            <div class="bd-ruleintro__warn">
              <icon-exclamation-circle />
              <span>
                本页为规则编排<b>交互沙盘</b>：改动不落库、不参与登录判定。真正在登录链路生效的自适应规则请在
                <button type="button" class="bd-link" @click="tab = 'policy'">「认证策略」</button>中配置。
              </span>
            </div>
          </div>
        </div>

        <div
          v-for="(r, ri) in rules"
          :key="r.id"
          class="bd-card bd-rule"
          :class="{ off: !r.enabled }"
        >
          <span class="bd-rule__handle" title="拖拽调整优先级"><icon-drag-dot-vertical /></span>
          <span class="bd-rule__pri">{{ ri + 1 }}</span>

          <div class="bd-rule__body">
            <div class="bd-rule__head">
              <span class="bd-rule__name">{{ r.name }}</span>
              <a-switch v-model="r.enabled" size="small" class="bd-rule__sw" />
            </div>

            <div class="bd-rule__flow">
              <!-- IF 区 -->
              <div class="bd-if">
                <span class="bd-clause">IF</span>
                <template v-for="(c, ci) in r.conditions" :key="ci">
                  <span class="bd-chip">
                    {{ condText(c) }}
                    <icon-close class="bd-chip__x" @click="removeCond(r, ci)" />
                  </span>
                  <span
                    v-if="ci < r.conditions.length - 1"
                    class="bd-logic"
                    :class="r.logic === 'AND' ? 'and' : 'or'"
                    @click="r.logic = r.logic === 'AND' ? 'OR' : 'AND'"
                  >{{ r.logic }}</span>
                </template>
                <button class="bd-addcond" @click="addCond(r)"><icon-plus-circle />条件</button>
              </div>

              <icon-right class="bd-flow__arrow" />

              <!-- THEN 区 -->
              <div class="bd-then">
                <span class="bd-clause">THEN</span>
                <div class="bd-actionwrap" :class="evalClass(r.action)">
                  <span class="bd-actiondot" />
                  <a-select v-model="r.action" size="small" class="bd-actionsel">
                    <a-option v-for="a in ACTIONS" :key="a.value" :value="a.value">{{ a.label }}</a-option>
                  </a-select>
                </div>
              </div>
            </div>
          </div>
        </div>

        <button class="bd-btn--ghost bd-btn bd-addrule" @click="addRule"><icon-plus />新增规则</button>
      </div>

      <!-- 规则求值预览 -->
      <div class="bd-rulepreview">
        <div class="bd-card bd-preview">
          <div class="bd-section-title">规则求值预览</div>
          <div class="bd-preview__sub">勾选模拟上下文，实时按优先级取第一条命中规则</div>

          <div class="bd-ctxlist">
            <label v-for="cx in CTX" :key="cx.field" class="bd-ctxrow">
              <a-checkbox v-model="ctx[cx.field]" />
              <span class="bd-ctxrow__t">{{ cx.label }}</span>
              <span class="bd-ctxrow__d">{{ cx.detail }}</span>
            </label>
          </div>

          <div class="bd-evalout" :class="evalResult.action ? evalClass(evalResult.action) : 'none'">
            <template v-if="evalResult.rule">
              <div class="bd-evalout__l">命中规则</div>
              <div class="bd-evalout__rule">{{ evalResult.rule.name }}</div>
              <div class="bd-evalout__arrow"><icon-arrow-down /></div>
              <div class="bd-evalout__l">最终动作</div>
              <div class="bd-evalout__act">{{ actionLabel(evalResult.action!) }}</div>
            </template>
            <template v-else>
              <div class="bd-evalout__l">无规则命中</div>
              <div class="bd-evalout__rule muted">采用默认动作</div>
              <div class="bd-evalout__arrow"><icon-arrow-down /></div>
              <div class="bd-evalout__l">最终动作</div>
              <div class="bd-evalout__act muted">放行（默认）</div>
            </template>
          </div>
        </div>
      </div>
    </div>

    <!-- ============ 认证源编辑抽屉 ============ -->
    <a-drawer v-model:visible="srcDrawer" :width="560" :title="srcForm.id ? '编辑认证源' : '接入认证源'" unmount-on-close>
      <div class="bd-srcform">
        <div class="bd-srcform__row">
          <label>名称</label>
          <a-input v-model="srcForm.name" placeholder="如：总部 AD 域" allow-clear />
        </div>

        <div class="bd-srcform__row">
          <label>类型</label>
          <a-select v-model="srcForm.kind" :disabled="!!srcForm.id || !supported">
            <a-option v-for="k in KIND_OPTS" :key="k.v" :value="k.v" :disabled="!!supported && !supported.includes(k.v)">
              {{ k.label }}<template v-if="!!supported && !supported.includes(k.v)">（本版本未实现）</template>
            </a-option>
          </a-select>
          <!-- ★未实现的类型必须在这里就置灰：能选而后端拒收，等于把人引向一条不通的路。
               清单由后端 supportedKinds 下发，这里不写死——**也不猜**：读不到时（supported 为 null）
               整条下拉锁定并说出后端原话，而不是拿一份"应该支持这几种"的乐观清单顶上去。 -->
          <div v-if="!supported" class="bd-srcform__warn">{{ unsupportedKindsNote }}</div>
          <div v-else class="bd-srcform__hint">
            {{ unsupportedKindsNote }}
            <template v-if="supported.includes('radius')">
              RADIUS 已实现（PAP/CHAP 口令认证源，未与 FreeRADIUS / 商用设备实机互通验证；不做 EAP，不做多轮挑战）
            </template>
          </div>
        </div>

        <div class="bd-srcform__row bd-srcform__row--inline">
          <a-switch v-model="srcForm.enabled" /><span>启用（参与登录）</span>
          <!--
            ★正名，不是删（wave11 行动 8-④）。这个旋钮曾叫「优先级」，语义是"多个源时先问谁"；
            wave8 认证域路由落地后**那个行为整个不存在了**（routeDirectory 返回值长度恒 ≤1，
            一次登录只问用户选定的那一个域）。但它没有变成纯装饰——后端 ORDER BY 仍在读它，
            可见效果是本页卡片、用户目录页的身份源选项卡、以及**登录页认证域下拉**的排列顺序，
            多目录部署里"把最多人用的域排在第一个"是有意义的。
            所以改名叫「排列顺序」并当面说清它管什么、不管什么——留着"优先级"三个字，
            管理员会去调一个对登录判定毫无影响的数字来解决"某个域没被问到"的问题。
          -->
          <span class="bd-srcform__pri">排列顺序
            <a-input-number v-model="srcForm.priority" :min="0" :max="99" size="small" class="bd-num--pri" />
          </span>
        </div>
        <div class="bd-srcform__hint">
          排列顺序只决定本页卡片、用户目录选项卡与<b>登录页认证域下拉</b>的先后（小者靠前，本地目录恒排最前）。
          它<b>不决定登录时先问哪个源</b>——一次登录只问用户选定的那一个认证域。
        </div>

        <!-- ── LDAP / AD ── -->
        <template v-if="srcForm.kind === 'ldap' || srcForm.kind === 'ad'">
          <div class="bd-srcform__sec">目录连接</div>
          <div class="bd-srcform__row"><label>主机</label>
            <a-input v-model="ldap.host" placeholder="dc01.corp.example" allow-clear /></div>
          <div class="bd-srcform__row"><label>端口</label>
            <a-input-number v-model="ldap.port" :min="0" :max="65535" placeholder="0 = 按传输方式取默认" class="bd-num--full" /></div>
          <div class="bd-srcform__row"><label>传输</label>
            <a-select v-model="ldap.tlsMode">
              <a-option value="ldaps">LDAPS（推荐）</a-option>
              <a-option value="starttls">StartTLS</a-option>
              <a-option value="plaintext">明文（不推荐）</a-option>
            </a-select>
            <!-- ★明文 LDAP 会把用户口令明文送上网。这不是"不够优雅"，是直接泄露凭据。 -->
            <div v-if="ldap.tlsMode === 'plaintext'" class="bd-srcform__warn">
              明文 LDAP 会把用户口令以明文送上网络，仅限隔离网段联调
            </div>
          </div>
          <div class="bd-srcform__row"><label>CA 证书</label>
            <a-textarea v-model="ldap.caCert" :auto-size="{ minRows: 2, maxRows: 4 }"
              placeholder="PEM；留空用系统根证书池。填了就只信这一把（比系统池+私有CA更严）" /></div>
          <div class="bd-srcform__row bd-srcform__row--inline">
            <a-switch v-model="ldap.insecureSkipVerify" size="small" /><span>跳过证书校验</span>
          </div>
          <div v-if="ldap.insecureSkipVerify" class="bd-srcform__warn">
            跳过校验后 TLS 只加密不认证，中间人可无声接管并拿到用户明文口令——比明文更坏，
            因为它看起来是有 TLS 的
          </div>

          <div class="bd-srcform__sec">服务账号与搜索</div>
          <div class="bd-srcform__row"><label>Bind DN</label>
            <a-input v-model="ldap.bindDn" placeholder="CN=svc-baidi,OU=Svc,DC=corp,DC=example" allow-clear /></div>
          <div class="bd-srcform__row"><label>Base DN</label>
            <a-input v-model="ldap.baseDn" placeholder="OU=Users,DC=corp,DC=example" allow-clear /></div>
          <div class="bd-srcform__row"><label>用户过滤器</label>
            <a-input v-model="ldap.userFilter" placeholder="留空用类型默认；须含 {{username}} 占位符" allow-clear /></div>
          <div class="bd-srcform__row"><label>登录名属性</label>
            <a-input v-model="ldap.usernameAttr"
              :placeholder="srcForm.kind === 'ad' ? '默认 sAMAccountName' : '默认 uid'" allow-clear /></div>
        </template>

        <!-- ── OIDC ── -->
        <template v-else-if="srcForm.kind === 'oidc'">
          <div class="bd-srcform__sec">OpenID Connect</div>
          <div class="bd-srcform__row"><label>Issuer</label>
            <a-input v-model="oidc.issuer" placeholder="https://idp.example.com/realms/corp" allow-clear /></div>
          <div class="bd-srcform__row"><label>Client ID</label>
            <a-input v-model="oidc.clientId" allow-clear /></div>
          <div class="bd-srcform__row"><label>回调地址</label>
            <a-input v-model="oidc.redirectUri" placeholder="https://vpn.example.com/api/v1/authsrc/oidc/callback" allow-clear /></div>
          <div class="bd-srcform__row bd-srcform__row--inline">
            <a-switch v-model="oidc.useUserInfo" size="small" /><span>登录时调 UserInfo 端点补全属性</span>
          </div>
          <div class="bd-srcform__hint">
            仅接受 RS256/ES256 这类非对称签名；alg=none 与 HS256 会被拒绝（算法混淆攻击面）
          </div>
          <div class="bd-srcform__hint">
            ★配了下方「允许的邮箱域 / 用户组」就要留意这个开关：白名单判的是 email 与 groups，
            而有些 IdP（精简配置的 Keycloak 等）不把它们放进 ID Token，只在 UserInfo 里给。
            拿不到属性时准入闸一律拒绝（fail-closed），表现为该源的用户全都进不来、
            而白名单看着完全正确。默认关：多打一次 UserInfo 是一次真出网。
          </div>
        </template>

        <!-- ── RADIUS（FR-INT-03）── -->
        <template v-else-if="srcForm.kind === 'radius'">
          <div class="bd-srcform__sec">RADIUS 服务器</div>
          <div class="bd-srcform__row"><label>主机</label>
            <a-input v-model="rad.host" placeholder="radius.corp.example 或 IP" allow-clear /></div>
          <div class="bd-srcform__row"><label>端口</label>
            <a-input-number v-model="rad.port" :min="0" :max="65535" placeholder="0 = 1812（认证口）" class="bd-num--full" />
            <div class="bd-srcform__hint">1812 是认证口；1813 是计费口，填它不会报错但永远等不到应答</div>
          </div>
          <div class="bd-srcform__row"><label>NAS-Identifier</label>
            <a-input v-model="rad.nasIdentifier" placeholder="留空 = baidi-control" allow-clear />
            <div class="bd-srcform__hint">服务端按它找客户端条目 / 挑策略；须与服务器上登记的一致</div>
          </div>
          <div class="bd-srcform__row"><label>口令协议</label>
            <a-select v-model="rad.protocol">
              <a-option value="pap">PAP（默认，互通面最广）</a-option>
              <a-option value="chap">CHAP（服务端须持有明文口令）</a-option>
            </a-select>
            <div v-if="rad.protocol === 'chap'" class="bd-srcform__warn">
              CHAP 要求 RADIUS 服务器侧存有用户的明文口令；接 AD 后端的 FreeRADIUS 通常只放行 PAP——
              选它前先确认服务端，否则表现为「所有人密码错误」
            </div>
          </div>
          <div class="bd-srcform__row"><label>组属性</label>
            <a-select v-model="rad.groupAttr">
              <a-option value="">不映射组</a-option>
              <a-option value="class">Class（25）</a-option>
              <a-option value="filter-id">Filter-Id（11）</a-option>
              <a-option value="reply-message">Reply-Message（18）</a-option>
            </a-select>
            <!-- ★这段照后端 api.radiusSyncableGroups 的实际语义写，别写回"组会同步成用户组"：
                 映射出来的值只用于①准入闸的「允许的组」比对 ②**库里已存在**的同名外部用户组的
                 成员同步，API 层绝不从这些值自动新建用户组——把 Class 用作逐会话标识的服务器
                 （Cisco ISE 的 CACS:<session>…、FreeRADIUS 的会话状态 Class）每次登录都回一个新值，
                 自动建组等于让对面决定我们这边建多少行。而那种「已存在的外部组」只可能是升级前
                 自动建出来的存量行，所以新部署里这一项实际就只服务准入闸——照实说，别给人一条
                 "去建个同名用户组就能同步"的路（页面上没有建外部组的入口）。 -->
            <div class="bd-srcform__hint">
              组由服务端策略写进应答的标准属性。映射出来的值<b>只用于「允许的组」白名单比对</b>；
              <b>绝不据此新建用户组</b>（成员同步只对库里已存在的同名外部组生效，新部署里没有这种组）。
              单次登录最多考察 32 个值、每个 ≤128 字节，超出的丢弃。不做厂商私有属性（VSA）
            </div>
          </div>
          <div class="bd-srcform__row bd-srcform__row--inline">
            <span class="bd-srcform__pri">单次等待
              <a-input-number v-model="rad.timeoutMs" :min="0" :max="30000" :step="500" size="small" class="bd-num--ms" /> ms
            </span>
            <span class="bd-srcform__pri">重发
              <a-input-number v-model="rad.retries" :min="0" :max="5" size="small" class="bd-num--n" /> 次
            </span>
          </div>
          <div class="bd-srcform__hint">
            总预算 = 单次等待 × (重发+1)，且不超过外部认证 8s 预算；<b>重发 0 次 = 只发一次</b>
            （后端按 DTO 里的显式 0 执行，不会悄悄改回默认的 1）。RADIUS 是 UDP：共享密钥不对、
            或本机未在服务器上登记为客户端时，多数服务器**静默丢包**——表现为超时而不是报错
          </div>
          <div class="bd-srcform__hint">
            RADIUS 应答里没有邮箱与显示名，也没有账号状态回验通道（目录侧停用一个人后，
            白帝这边只能等他的会话自然过期）。EAP、MS-CHAPv2、多轮挑战应答（Access-Challenge）本版本不做
          </div>

          <!-- ── 应答完整性（Blast-RADIUS 逃生舱）──
               ★这个开关此前**在控制台上根本不存在**，而后端已经在读它（api.radiusWaiverFromConfig →
               radiussrc.Config.AllowMissingResponseMessageAuthenticator）：老设备真不回该属性时，
               管理员在页面上找不到任何地方能打开它；反过来，一条不知怎么被打开了的源也没法在这里关掉，
               而保存回执（radiusWaiverWarning）还指着一个不存在的开关。默认关 = 要求带该属性。 -->
          <div class="bd-srcform__sec">应答完整性（Blast-RADIUS / CVE-2024-3596）</div>
          <div class="bd-srcform__row bd-srcform__row--inline">
            <a-switch v-model="rad.allowMissingResponseMessageAuthenticator" size="small" />
            <span>允许应答不带 Message-Authenticator</span>
          </div>
          <!-- 打开时当面告警。文案与后端保存回执 api.radiusWaiverWarning 同源（那句是保存那一刻的回执，
               这句是配置时的常驻说明），别在这里把它写软。 -->
          <div v-if="rad.allowMissingResponseMessageAuthenticator" class="bd-srcform__warn">
            打开后该源会接受<b>不携带</b> Message-Authenticator（RFC 2869 §5.14）的应答，等于放弃
            Blast-RADIUS（CVE-2024-3596）缓解里唯一还站得住的那层 HMAC——应答完整性只剩已被攻破的
            MD5 Response Authenticator。只在确认该服务器确实不回这个属性时保持开启；
            能在服务端开启应答侧 Message-Authenticator 的话，请关掉这个开关。
          </div>
          <div class="bd-srcform__hint">
            默认关 = 要求应答带该属性，缺席即判「认证源不可用」。★它<b>只放宽「缺席」</b>：
            带了却校验不过（共享密钥不匹配，或报文在途中被改）在任何配置下都拒。
            RADIUS/TLS（RadSec）才是根治，本版本不做
          </div>
        </template>

        <!-- ── 账号状态回验（wave8 行动 11）── -->
        <template v-if="srcForm.kind === 'ldap' || srcForm.kind === 'ad'">
          <div class="bd-srcform__sec">账号状态回验</div>
          <div class="bd-srcform__row"><label>状态属性</label>
            <a-input v-model="ldap.statusAttr" allow-clear
              :placeholder="srcForm.kind === 'ad' ? '留空即可（AD 用内置的 userAccountControl 位）' : 'accountEnable / nsAccountLock / pwdAccountLockedTime'" />
          </div>
          <div class="bd-srcform__row"><label>表示停用的值</label>
            <a-input-tag v-model="statusDisabledValues" allow-clear
              placeholder="FALSE（回车添加；留空 = 该属性存在即视为停用）" />
          </div>
          <div class="bd-srcform__row"><label>常见预设</label>
            <a-space wrap>
              <a-button size="mini" @click="applyStatusPreset('idtrust')">IDTrust accountEnable=FALSE</a-button>
              <a-button size="mini" @click="applyStatusPreset('389ds')">389DS nsAccountLock=true</a-button>
              <a-button size="mini" @click="applyStatusPreset('ppolicy')">OpenLDAP pwdAccountLockedTime 存在即锁</a-button>
              <a-button size="mini" @click="applyStatusPreset('clear')">清空</a-button>
            </a-space>
          </div>
          <div v-if="srcForm.kind !== 'ad' && !ldap.statusAttr" class="bd-srcform__warn">
            未配置状态属性：通用 LDAP 协议里**没有**"禁用"这个语义，回验此时只能识别
            「条目被删除或移出 BaseDN」。目录侧把人停用（而不是删除）时，白帝这边不会禁号——
            他的会话与隧道会一直有效到自然过期。
          </div>
          <div class="bd-srcform__hint">
            回验按 entryDN 周期直查；条目被挪出 BaseDN 也判为已失效。
            源不可用（网络/绑定失败）绝不动手——那是运维故障，不是账号的问题。
          </div>
        </template>

        <!-- 外部身份准入。★这一段是真判定不是提示：自动建号的账号落进「外部目录」单元，
             其父是根组织——把资源授权给根组织就把这批人全覆盖了。
             ★新建认证源默认预选「需管理员批准」（见 ADMIT_NEW），编辑存量源则如实回显它当前的行为。 -->
        <template v-if="srcForm.kind !== 'local'">
          <div class="bd-srcform__sec">外部身份准入</div>
          <div class="bd-srcform__row"><label>未导入用户</label>
            <a-select v-model="admit.admitPolicy">
              <a-option value="auto">认证通过即自动建号</a-option>
              <a-option value="approval">需管理员批准后才建号（推荐 · 新建默认）</a-option>
            </a-select>
          </div>
          <div v-if="admit.admitPolicy !== 'approval'" class="bd-srcform__warn">
            当前为自动建号：该目录里**任何**能通过认证的条目（服务账号、承包商、刚建的号）
            首登即获得白帝账号与门户会话，无审批。若已把资源授权给上级组织，他们即刻拥有该资源的访问权。
          </div>
          <div class="bd-srcform__row"><label>允许邮箱域</label>
            <a-input-tag v-model="admitDomains" allow-clear :disabled="srcForm.kind === 'radius'"
              :placeholder="srcForm.kind === 'radius' ? 'RADIUS 应答里没有邮箱，此项不可用' : 'corp.example（回车添加；留空=不限）'" />
            <!-- ★不是"暂不支持"，是配了就全拒：域白名单对拿不到邮箱的源 fail-closed，后端保存即拒。 -->
            <div v-if="srcForm.kind === 'radius'" class="bd-srcform__hint">
              域白名单判的是邮箱，RADIUS 拿不到邮箱 → 配了会让该源所有用户被准入闸拒绝，后端保存时直接拒收。按组限制请用下方「允许的组」+ 上方「组属性」
            </div>
          </div>
          <div class="bd-srcform__row"><label>允许的组</label>
            <a-input-tag v-model="admitGroups" placeholder="vpn-users（回车添加；留空=不限）" allow-clear />
          </div>
          <div class="bd-srcform__hint">
            白名单**每次登录都判**——目录侧把人移出允许组后，他下次登录即被拒（审批只判首次建号）。
            两项都填则两项都要过。配了域白名单但认证源没返回邮箱时按拒绝处理（准入闸 fail-closed）。
          </div>
        </template>

        <!-- ── 凭据（只写不读）── -->
        <template v-if="srcForm.kind !== 'local'">
          <div class="bd-srcform__sec">凭据</div>
          <div class="bd-srcform__row">
            <label>{{ srcForm.kind === 'oidc' ? 'Client Secret' : srcForm.kind === 'radius' ? '共享密钥' : 'Bind 口令' }}</label>
            <a-input-password v-model="srcSecret" allow-clear
              :placeholder="srcForm.hasSecret ? '已配置（指纹 ' + (srcForm.secretFingerprint || '••••') + '）；留空则不改' : '未配置'" />
            <!-- ★只写不读：没有任何端点能把凭据读回去，回显只有泄露面。
                 空口令在 LDAP 上会退化成匿名 bind 并"看起来成功"，后端会拒。 -->
            <div class="bd-srcform__hint">加密落库，永不回显。留空表示保持原有凭据不变</div>
            <div v-if="srcForm.kind === 'radius'" class="bd-srcform__hint">
              即 RADIUS 服务器上为本机客户端条目配置的 shared secret。不配它这条源不可用（保存回执会点名）
            </div>
          </div>
        </template>
      </div>

      <template #footer>
        <a-space>
          <a-button @click="srcDrawer = false">取消</a-button>
          <a-button type="primary" :loading="srcSaving" @click="saveSource">保存</a-button>
        </a-space>
      </template>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import {
  api, failReason, failStatus, type AuthSrcBundle, type AuthSource, type AdaptiveRule, type RuleCond,
  type AuthPolicy, type AuthPolicyResp, type AuthRuleCapability, type AuthMethodCapability, type AuthDirectory, type EnhanceRule,
  type SecondaryMethod, type SubjectOption,
  type AuthSourceRec, type AuthSourcesResp, type ProbeResp, type SaveSourceResp,
  type LdapConfig, type OidcConfig, type RadiusConfig, type AdmitConfig, type ExtAdmission
} from '@/lib/api';
import PageHeader from '@/components/PageHeader.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

/** 目录/源类型的图标与配色键。★页面本地定义、不从 API 类型推导：这套映射还要覆盖
 *  存量策略引用的历史目录名（radius/oauth/sms/cert），那几类不会出现在认证源列表里。 */
type SrcType = 'local' | 'ad' | 'ldap' | 'radius' | 'oauth' | 'sms' | 'cert';
type CondField = RuleCond['field'];
type Action = AdaptiveRule['action'];

const tab = ref<'source' | 'policy' | 'rule'>('source');
/* 连接态三态：undefined = 首轮读取还没回来（页头不画标签）；之后 = 「认证源」页签的两次读取
 * （/authsrc 聚合 + /authsrc/sources 列表）是否都成功。★刻意只看这两次：策略与待批准入各有
 * 自己的页内失败态（polErr / admitErr），把它们也并进来的话，/authpolicy 一挂，默认打开的
 * 认证源页签会顶着一枚红色「数据未读取」而列表完好、原因却在另一个页签里。 */
const live = ref<boolean | undefined>(undefined);
/* 四次读取各自的失败原话（后端原文，经 failReason 收口）；空串 = 这次读成功了。
 * ★不许 bare catch 置空：认证源列表、策略、待批准入都没有演示回落，「拿不到」若渲染成
 * 「没有」，管理员会去重新接入一份 LDAP / 以为全体在走默认策略 / 以为没人在等批准。 */
const aggErr = ref('');
const srcErr = ref('');
const polErr = ref('');
const admitErr = ref('');
/* 首屏是否已跑完一轮读取。★只在 onMounted 那一轮从 false 翻成 true，之后的刷新
 * （保存/删除后的 loadSources）不再翻回去——否则每保存一次整屏都会退回骨架，
 * 而那一刻页面上明明还有一份完好的旧数据。骨架回答的是"首屏还没拿到"这一个问题。 */
const loaded = ref(false);

/* MOCK_RULES 只服务「自适应认证规则」页签那个**交互沙盘**：改动不落库、不参与登录判定，
 * 页面上有醒目提示。★真正在登录链路生效的自适应认证在「认证策略」页签（authpolicy 实时
 * 求值），别把这份种子挪去那里，也别给认证源列表配任何演示回落。 */
const MOCK_RULES: AdaptiveRule[] = [
  {
    id: 'r1', name: '弱口令 + 异地登录 → 阻断', enabled: true, logic: 'AND', action: 'block', priority: 1,
    conditions: [
      { field: 'weakPwd', op: 'is', value: 'true' },
      { field: 'geoAnomaly', op: 'is', value: 'true' }
    ]
  },
  {
    id: 'r2', name: '高风险分或未授信终端 → 升级认证', enabled: true, logic: 'OR', action: 'stepup', priority: 2,
    conditions: [
      { field: 'riskScore', op: 'gt', value: '70' },
      { field: 'untrustedDevice', op: 'is', value: 'true' }
    ]
  },
  {
    id: 'r3', name: '新设备或异常时段 → 二次认证', enabled: true, logic: 'OR', action: 'mfa', priority: 3,
    conditions: [
      { field: 'newDevice', op: 'is', value: 'true' },
      { field: 'offHours', op: 'in', value: '22:00-06:00' }
    ]
  },
  {
    id: 'r4', name: '低风险授信终端 → 直接放行', enabled: true, logic: 'AND', action: 'allow', priority: 4,
    conditions: [
      { field: 'riskScore', op: 'gt', value: '0' }
    ]
  }
];

/** 认证源聚合（GET /api/v1/authsrc）：与下面的 recs 同一批库行，多带一个真实账号计数。 */
const sources = ref<AuthSource[]>([]);
/** 沙盘规则（本地推演，见上）。 */
const rules = ref<AdaptiveRule[]>(MOCK_RULES);

/* ══════════ 认证源：整套走真实端点（/authsrc/sources 与 /authsrc 聚合）══════════ */
const recs = ref<AuthSourceRec[]>([]);
/* 后端下发的已实现清单（GET /authsrc/sources 的 supportedKinds）。
   ★三态：**null = 还没读到（判不出来）**，既不是"一种都不支持"，也不能拿一份前端写死的清单顶上。
   改造前这里的初值是乐观的 ['local','ldap','ad','oidc','radius']，且只在读取成功且非空时被覆盖——
   /authsrc/sources 回 5xx/403 时那份乐观值就是最终值，于是某个类型看着可选、选了保存被后端拒。
   显形条件正是「控制台比控制面新」，而那恰好是下面「未实现的类型必须在这里就置灰」点名要防的场景。 */
const supported = ref<string[] | null>(null);
/** 清单读不到的原因：后端原话，或"这个控制面没下发这一项"。要当面说，不猜。 */
const supportedErr = ref('');
const probes = ref<Record<string, ProbeResp>>({});
const probing = ref('');

const KIND_OPTS: { v: string; label: string }[] = [
  { v: 'ldap', label: '通用 LDAP' },
  { v: 'ad', label: 'Active Directory' },
  { v: 'oidc', label: 'OpenID Connect' },
  // RADIUS 作为**口令认证源**已真实现（PAP/CHAP，FR-INT-03）。★与下方 SECONDARY_OPTS 里的
  // 'radius'（「Radius 动态令牌」，二次认证方式）不是一回事——那一栏仍冻结。
  { v: 'radius', label: 'RADIUS' },
  // 下面两类后端未实现，靠 supported 置灰而不是从列表里删掉——
  // 删掉会让人以为"白帝不支持这些"，置灰+注明才说清是"本版本没做"。
  { v: 'sms', label: '短信网关' },
  { v: 'cert', label: '商密证书（SM2）' }
];

const KIND_LABEL: Record<string, string> = {
  local: '本地目录', ldap: '通用 LDAP', ad: 'Active Directory', oidc: 'OpenID Connect',
  radius: 'RADIUS', sms: '短信网关', cert: '商密证书'
};
/* 源类型的**区分色**：只给标签与图标底做区分，不表达好坏，所以走 .bd-tg-- 与 .bd-srcicon--
 * 那套语义类而不是 inline 十六进制（页面里不再出现裸色值；主题换了这里跟着换）。
 * ★注释里不写「星号+斜杠」通配：那会提前闭合本段注释（tokens.css 规则五守的正是这一手）。
 * 认不出的类型落 grey——不许回落成某个具体颜色，那会让未知类型冒充已知的一种。 */
type Tone = 'blue' | 'purple' | 'green' | 'gold' | 'grey';
const KIND_TONE: Record<string, Tone> = {
  local: 'blue', ldap: 'purple', ad: 'blue', oidc: 'green', radius: 'gold'
};
const KIND_ICON: Record<string, string> = {
  local: 'icon-user', ldap: 'icon-mind-mapping', ad: 'icon-storage', oidc: 'icon-link', radius: 'icon-wifi'
};
function kindLabel(k: string) { return KIND_LABEL[k] ?? k; }
/** 类型下拉底下那句话，三态各一句：
 *  ① 清单没读到 → 判不出来，带后端原话，下拉整条锁定（渲染成 .bd-srcform__warn，那是个真问题）；
 *  ② 读到了、有未实现的类型 → 逐个点名已置灰；
 *  ③ 读到了、全都实现 → 空。
 *  ★这句话与下拉里的灰项必须指向同一批类型（都读同一个 supported），写死一份就会在过渡期自相矛盾。 */
const unsupportedKindsNote = computed(() => {
  if (!supported.value) {
    return `已实现类型清单未读取（${supportedErr.value || '尚未拉取 /authsrc/sources'}）：` +
      `无法判断哪些类型可选，新建时的类型选择已锁定。请先修复该读取再接入新源——` +
      `这里不猜一份清单，猜错就是让人选一个后端会拒的类型。`;
  }
  const off = KIND_OPTS.filter((k) => !supported.value!.includes(k.v)).map((k) => k.label);
  return off.length ? `${off.join(' / ')} 本版本未实现，已置灰。` : '';
});
function kindTone(k: string): Tone { return KIND_TONE[k] ?? 'grey'; }
function kindIcon(k: string) { return KIND_ICON[k] ?? 'icon-question-circle'; }
function probeOf(id: string): ProbeResp | undefined { return probes.value[id]; }

/* ── 抽屉表单 ── */
const srcDrawer = ref(false);
const srcSaving = ref(false);
const srcSecret = ref('');
const srcForm = reactive<{
  id: string; name: string; kind: string; enabled: boolean; priority: number;
  hasSecret: boolean; secretFingerprint?: string;
}>({ id: '', name: '', kind: 'ldap', enabled: true, priority: 10, hasSecret: false });
const ldap = reactive<LdapConfig>({ host: '', port: 0, tlsMode: 'ldaps', baseDn: '' });
const oidc = reactive<OidcConfig>({ issuer: '', clientId: '', redirectUri: '', useUserInfo: false });
/* RADIUS：端口 0 = 1812；重发缺省 1，与后端 radiussrc 的默认值一致。
   ★后端 DTO 的 retries 现在是 *int：**缺席 = 取默认 1，显式 0 = 只发一次不重发**
   （api.radiusRetries 把 nil 翻成 -1 交给 radiussrc 取默认，显式值含 0 原样传）。
   所以表单里的 0 是一个真会被执行的选择，`:min` 必须是 0——写成 1 就把这档从界面上抹掉了。 */
/** 表单里那份 RADIUS 配置 = api.ts 的 RadiusConfig + 那个安全逃生舱。
 *  ★键刻意不加进 api.ts 的公共 DTO，与后端同款取舍（见 api.radiusWaiverFromConfig 的注释：
 *  键名的唯一真相源是常量 radiusAllowMissingRespMAKey，而且它不进 DTO 才能让"填了非布尔值"
 *  得到一句点名键名的中文 400，而不是一行英文解码错误）。这里同理把它留在页面的表单类型上，
 *  与它唯一的消费方（抽屉里那个开关）挨着。 */
type RadiusForm = RadiusConfig & { allowMissingResponseMessageAuthenticator: boolean };
/** 逃生舱在落库 config 里的键名。★与后端常量 api.radiusAllowMissingRespMAKey 同名——
 *  两处对不上的症状是「页面上打开了、保存回执说已打开，而执行方那边恒 false」。
 *  类型标成 keyof RadiusForm：敲错一个字母 tsc 当场就报，而不是等到读不出值。 */
const RADIUS_WAIVER_KEY: keyof RadiusForm = 'allowMissingResponseMessageAuthenticator';
/** 列表卡上那条常驻警示的正文。与后端保存回执 api.radiusWaiverWarning 同源（同一件事的两个时刻：
 *  那句在保存那一刻回，这句在此后天天挂着），别只写「已放弃校验」——要说清放弃的是哪一层、还剩什么。 */
const RADIUS_WAIVER_BADGE = '已放弃应答侧 Message-Authenticator 校验：该源接受不带该属性的应答，' +
  'Blast-RADIUS（CVE-2024-3596）攻破的 MD5 Response Authenticator 是此时唯一的应答完整性保护。' +
  '确认服务器其实会回该属性的话，请到「编辑」里关掉这个开关。';
const RAD_DEFAULT: RadiusForm = {
  host: '', port: 0, nasIdentifier: '', protocol: 'pap', groupAttr: '', timeoutMs: 3000, retries: 1,
  // ★显式 false 而不是省略：与后端「缺席 = false = 要求带 MA」同向，且让下面 resetSrcForm 的默认值
  // 里真的有这一项——省略的话，一次编辑带进来的 true 只能靠"清空"那一步兜住，两道守卫少一道。
  allowMissingResponseMessageAuthenticator: false
};
const rad = reactive<RadiusForm>({ ...RAD_DEFAULT });

/* ── 外部身份准入的两个"默认"，刻意不是同一个（wave11 行动 8-②）──
 *
 * ADMIT_NEW  新建认证源时预选的值：**需管理员批准**（PRD FR-USER-13 的默认就是不允许）。
 * ADMIT_EXISTING 编辑一条**存量**源、而它的 config 里根本没有 admitPolicy 这一项时的回显值：
 *   auto——与后端 store.NormalizeAdmitPolicy 的归一结果逐字一致，页面显示的必须是它真实的行为。
 *
 * ★两者不能合并成一个常量。auto 那个缺省是 wave8 给**存量行**留的向后兼容（改成 approval
 *   会把已经在用的目录用户当场挡在门外），而新建这一刻没有任何存量语义要兼容——默认就该是拒绝。
 *   改造前两处共用 'auto'，于是页面自己把 approval 标成「（推荐）」却预选了不推荐的那一项：
 *   接一个新 AD 域、一路下一步保存，该目录里**任何**能通过认证的条目（服务账号、承包商、
 *   刚建的号）首登即获得白帝账号与门户会话，无审批。
 * ★别顺手把 openSrcEdit 的回显也改成 approval：那会让一条实际在自动建号的存量源
 *   在页面上显示成「需批准」，而保存之前它的行为一点没变。
 */
const ADMIT_NEW = 'approval' as const;
const ADMIT_EXISTING = 'auto' as const;

/** 一条 RADIUS 源当前是不是放弃了应答侧 Message-Authenticator 校验。
 *  ★判据与真正的执行方 api.radiusWaiverFromConfig **逐字同构**：只认真正的布尔，
 *  缺席 / null / 类型不对 / 整份 config 解不开一律 false（= 要求带该属性，收紧那一侧）。
 *  自己另写一套更宽的判据（比如把字符串 "true" 也算开）会让列表上写着「已放弃」而登录时其实在要求——
 *  两句相反的话都出自我们自己，谁也不知道该信哪句。 */
function radiusWaiver(s: AuthSourceRec): boolean {
  try {
    const cfg = JSON.parse(s.config || '{}');
    return cfg?.[RADIUS_WAIVER_KEY] === true;
  } catch {
    return false;
  }
}
/* 准入设置（各类源共用）。 */
const admit = reactive<AdmitConfig>({ admitPolicy: ADMIT_EXISTING });
const statusDisabledValues = ref<string[]>([]);

/* 常见目录的状态属性预设。★这不是"帮你填个默认值"，是把各家的方言写在界面上——
   通用 LDAP 没有统一的禁用属性，管理员不查文档根本不知道该填什么，
   而填错的后果是静默的（回验永远判 active）。 */
function applyStatusPreset(kind: 'idtrust' | '389ds' | 'ppolicy' | 'clear') {
  const presets: Record<string, [string, string[]]> = {
    idtrust: ['accountEnable', ['FALSE']],
    '389ds': ['nsAccountLock', ['true']],
    ppolicy: ['pwdAccountLockedTime', []],
    clear: ['', []]
  };
  const [attr, vals] = presets[kind];
  ldap.statusAttr = attr;
  statusDisabledValues.value = vals;
}

const admitDomains = ref<string[]>([]);
const admitGroups = ref<string[]>([]);

/** 把一个 reactive 表单对象**先清空再写默认值**。
 *
 * ★`Object.assign(obj, DEFAULT)` 只覆盖默认值里有的键，**删不掉多余的键**。而 openSrcEdit 走的是
 * `Object.assign(rad, { ...RAD_DEFAULT, ...cfg })`——库里那份 config 带的、默认值里没有的键
 * （准入三项、以及安全逃生舱这类刻意不在 DTO 里的键）会**留在表单对象上**。于是
 * 「编辑一个已开逃生舱的 RADIUS 源 → 取消 → 点新建 → 保存」会把
 * `allowMissingResponseMessageAuthenticator: true` 一起 POST 出去：新源静默带着
 * 「已放弃 CVE-2024-3596 缓解」的姿态建出来，页面上只有一条一闪而过的 toast。
 * 这对**任何 DTO 之外的配置键**都成立，不只这一个，所以修法是结构性的（先删后写），
 * 而不是给那一个键补一行默认值——两道都上：RAD_DEFAULT 里也有显式 false。
 * 顺带修掉同族的一处：`ldap.statusAttr` 此前根本不在重置清单里，编辑过一条配了状态属性的
 * LDAP 源之后新建，那个属性会跟着过来。
 */
function assignFresh<T extends object>(target: T, defaults: T) {
  for (const k of Object.keys(target)) delete (target as Record<string, unknown>)[k];
  Object.assign(target, defaults);
}

function resetSrcForm() {
  assignFresh(srcForm, { id: '', name: '', kind: 'ldap', enabled: true, priority: 10, hasSecret: false, secretFingerprint: undefined });
  assignFresh(ldap, { host: '', port: 0, tlsMode: 'ldaps', caCert: '', insecureSkipVerify: false, bindDn: '', baseDn: '', userFilter: '', usernameAttr: '' });
  assignFresh(oidc, { issuer: '', clientId: '', redirectUri: '', scopes: undefined, useUserInfo: false });
  assignFresh(rad, { ...RAD_DEFAULT });
  // ★这里用 ADMIT_EXISTING（auto）而不是新建默认：resetSrcForm 是**两条路共用**的清场，
  //   openSrcEdit 紧接着会用库里的值覆盖它，覆盖不到（config 里没有这一项）的那种情况
  //   正是"存量行"，此时页面必须显示它真实的行为。新建那条路由 openSrcCreate 显式改写。
  assignFresh(admit, { admitPolicy: ADMIT_EXISTING });
  statusDisabledValues.value = [];
  admitDomains.value = [];
  admitGroups.value = [];
  srcSecret.value = '';
}

function openSrcCreate() {
  resetSrcForm();
  // 新建认证源默认「需管理员批准」，理由见 ADMIT_NEW / ADMIT_EXISTING 的注释。
  admit.admitPolicy = ADMIT_NEW;
  srcDrawer.value = true;
}

function openSrcEdit(r: AuthSourceRec) {
  resetSrcForm();
  Object.assign(srcForm, {
    id: r.id, name: r.name, kind: r.kind, enabled: r.enabled, priority: r.priority,
    hasSecret: r.hasSecret, secretFingerprint: r.secretFingerprint
  });
  // config 是后端存的 JSON 字符串。解析失败不能把表单搞成空白——
  // 那会让"保存"变成一次静默的配置清空。
  try {
    const cfg = JSON.parse(r.config || '{}');
    if (r.kind === 'oidc') Object.assign(oidc, cfg);
    else if (r.kind === 'radius') Object.assign(rad, { ...RAD_DEFAULT, ...cfg });
    else Object.assign(ldap, cfg);
    // ★存量源缺这一项时回显 ADMIT_EXISTING（auto）而不是留空、也不是新建默认：
    //   留空会让下拉显示未选中；显示成「需批准」则是替一条正在自动建号的源说了假话。
    admit.admitPolicy = cfg.admitPolicy === 'approval' ? 'approval' : ADMIT_EXISTING;
    statusDisabledValues.value = Array.isArray(cfg.statusDisabledValues) ? cfg.statusDisabledValues : [];
    admitDomains.value = Array.isArray(cfg.allowedDomains) ? cfg.allowedDomains : [];
    admitGroups.value = Array.isArray(cfg.allowedGroups) ? cfg.allowedGroups : [];
  } catch {
    Message.warning('该认证源的配置不是合法 JSON，已按空白载入——保存会覆盖原配置');
  }
  srcDrawer.value = true;
}

/* 待批外部身份准入。★空列表就整块不画——常态零噪声。
   拿不到（5xx / 旧后端 404 / 非安全管理员 403）**不能**与"确实没有待批"同形：
   这块是「需管理员批准」那档唯一的批复入口，读不到时可能正有人被闸挡着等批，
   下一步动作（先把读取修好）与"没人等"完全不同——原话经 admitErr 渲染成页内红条。 */
const admissions = ref<ExtAdmission[]>([]);
const admitBusy = ref('');

async function loadAdmissions() {
  try {
    const r = await api<{ admissions: ExtAdmission[] }>('/authsrc/admissions');
    admissions.value = r.admissions ?? [];
    admitErr.value = '';
  } catch (e) {
    admissions.value = [];
    admitErr.value = failReason(e);
  }
}

async function decideAdmission(a: ExtAdmission, decision: 'approved' | 'rejected') {
  const zh = decision === 'approved' ? '批准' : '拒绝';
  let reason = '';
  if (decision === 'rejected') {
    reason = window.prompt(`拒绝 ${a.username || a.subject} 的准入申请，理由（会记入审计并回给该用户）：`) ?? '';
  }
  admitBusy.value = a.approvalId;
  try {
    await api(`/authsrc/admissions/${encodeURIComponent(a.approvalId)}/decide`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, reason })
    });
    Message.success(decision === 'approved'
      ? `已批准；该身份下次登录时才会建号`
      : `已拒绝 ${a.username || a.subject} 的准入`);
    await loadAdmissions();
  } catch (e) {
    Message.error(`${zh}失败：${failReason(e)}`);
  } finally {
    admitBusy.value = '';
  }
}

async function loadSources() {
  try {
    const r = await api<AuthSourcesResp>('/authsrc/sources');
    recs.value = r.sources ?? [];
    // ★清单只认后端下发的那一份。没下发（控制面较旧）同样是"判不出来"，不能退回到前端猜的一份：
    // 那正是「控制台比控制面新」这个过渡期，也正是猜错代价最大的时候。
    supported.value = r.supportedKinds?.length ? r.supportedKinds : null;
    supportedErr.value = supported.value ? '' : '该控制面的 /authsrc/sources 没有下发 supportedKinds 字段';
    srcErr.value = '';
  } catch (e) {
    // ★认证源是真数据，拿不到就留空，不降级到演示数据；但「留空」必须带着原因：
    // 本地目录是内置行，后端正常时这份列表永不为空，所以空列表在实际部署里几乎只有
    // "没读到"一种成因——不记原因的话它与全新库长得一模一样（2026-09-07 复现：5xx 时页面
    // 显示「已接入 0 个身份源 / 尚未接入任何认证源」，零报错）。
    recs.value = [];
    srcErr.value = failReason(e);
    // 同一次读取带来的清单也没了：**绝不保留上一次那个好值**（那会让下拉停在一份可能已经过时的
    // 清单上，与「取不到一律降级成不可判定」同一条纪律），更不回落成前端写死的乐观集合。
    supported.value = null;
    supportedErr.value = failReason(e);
  }
  // 连接态跟着这两次读取走（见 live 的注释）；首轮之后每次 loadSources 都会重算，
  // 保存 / 删除后的刷新若失败，页头会如实翻红而不是停在上一次的绿。
  live.value = !srcErr.value && !aggErr.value;
}

/** 写凭据（只写不读的独立端点），回指纹。 */
async function putSourceSecret(id: string, secret: string): Promise<string> {
  const sr = await api<{ ok: boolean; fingerprint: string }>(
    `/authsrc/sources/${encodeURIComponent(id)}/secret`,
    { method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret }) });
  return sr.fingerprint;
}

/**
 * 保存认证源。**一次保存只弹一条回执。**
 *
 * ★改造前的形态：先 POST 配置、再 PUT 凭据，两个响应各弹一条。而后端的「保存即校验」
 * （handleSaveAuthSource 里的 buildProvider）读的是**库里那一刻**的凭据——凭据还没写进去，
 * 于是新建一条 RADIUS 源并同时填了共享密钥时，页面会同时弹出
 *   ①「凭据已更新（指纹 3f2a…）」  ②「配置已保存，但当前还不可用：radiussrc: 未配置共享密钥」
 * 两条互相矛盾的回执，而 ② 描述的是 ① 发生之前的状态。管理员据 ② 会回头去再配一次密钥。
 *
 * 现在的顺序按「凭据能不能先写」分两路，两路都只出一条回执：
 *   · 编辑已有源：先 PUT 凭据、再 POST 配置 → 那一次 POST 的 warning 天然是最终状态。零额外请求。
 *   · 新建源：id 由后端在 POST 里才分配，凭据只能后写；写完再 POST 一次**同样的配置**，
 *     让后端在"凭据已落库"的状态下重算一次可用性。这一次是幂等 upsert。
 * ★这里刻意**不**在前端推断「写了密钥所以那条警告不算数了」：warning 是后端拼的一句话，
 *   可能同时含别的成因（如 FR-AUTH-10 自动建默认策略那半句），猜错就是替后端说了它没说过的话。
 */
async function saveSource() {
  if (!srcForm.name.trim()) { Message.warning('请填写名称'); return; }
  // ★清单读到了才拦；判不出来时**不在前端拦**：真闸在后端（handleSaveAuthSource 对未实现的类型回
  // 400 并点名当前支持哪几种），前端猜一句"本版本未实现"会把一次本来能成的保存拦在一条自己编的话上。
  // 与 lib/me.ts 的 can() 判不出来时 fail-open 同向。此时类型下拉已经锁定，这里不再多加一道假闸。
  if (supported.value && !supported.value.includes(srcForm.kind)) {
    Message.error(`${kindLabel(srcForm.kind)} 本版本未实现，无法保存`);
    return;
  }
  srcSaving.value = true;
  try {
    // 准入设置并进 config：后端各类源共用同一组键（admitPolicy/allowedDomains/allowedGroups）。
    const base = srcForm.kind === 'oidc' ? { ...oidc }
      : srcForm.kind === 'radius' ? { ...rad }
      : { ...ldap, statusDisabledValues: statusDisabledValues.value };
    const config = {
      ...base,
      ...(srcForm.kind === 'local' ? {} : {
        // ★兜底值仍是 ADMIT_EXISTING（auto）：这里是"表单里那一项莫名丢了"的分支，
        //   它只可能发生在编辑存量源的路径上（新建那条由 openSrcCreate 显式置成 approval）。
        //   把兜底改成 approval 等于一次编辑就悄悄改掉了这条源的准入语义。
        admitPolicy: admit.admitPolicy ?? ADMIT_EXISTING,
        // RADIUS 拿不到邮箱：域白名单对它恒 fail-closed，后端保存即拒；表单里已禁用，这里不再带上。
        allowedDomains: srcForm.kind === 'radius' ? [] : admitDomains.value,
        allowedGroups: admitGroups.value
      })
    };
    // 凭据留空 = 保持原有凭据不变，不能拿空串去覆盖。
    const pendingSecret = srcSecret.value.trim();
    const isNew = !srcForm.id;
    const postBody = () => JSON.stringify({
      id: srcForm.id, name: srcForm.name, kind: srcForm.kind,
      enabled: srcForm.enabled, priority: srcForm.priority, config
    });
    const post = () => api<SaveSourceResp>('/authsrc/sources', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: postBody()
    });

    let fingerprint = '';
    if (pendingSecret && !isNew) fingerprint = await putSourceSecret(srcForm.id, pendingSecret);

    let resp = await post();
    if (pendingSecret && isNew) {
      fingerprint = await putSourceSecret(resp.source.id, pendingSecret);
      // 重存一次同样的配置，只为拿到「凭据已落库」之后后端算出来的那句话（见函数注释）。
      // 顺带把后端分配的 id 记回表单：源已经真的建出来了，这一步或下一步若抛错，
      // 用户再点一次「保存」应当是**改这一条**，而不是又建一条同名的。
      srcForm.id = resp.source.id;
      resp = await post();
    }

    // 后端「保存即校验」：配置写错了当场就说，而不是等到有人登录不上才发现。
    // ★这是本次保存唯一的一条回执，且失败那支原样转述后端原话（不追加、不改写）。
    if (resp.warning) Message.warning(resp.warning);
    else if (fingerprint) Message.success(`认证源已保存；凭据已更新（指纹 ${fingerprint}）`);
    else Message.success('认证源已保存');
    srcDrawer.value = false;
    await loadSources();
    await loadAdmissions();
  } catch (e) {
    Message.error(`保存失败：${failReason(e)}`);
  } finally {
    srcSaving.value = false;
  }
}

/** 真实连通性探测（真去连目录 / 拉发现文档）。 */
async function probe(r: AuthSourceRec) {
  probing.value = r.id;
  try {
    probes.value = {
      ...probes.value,
      [r.id]: await api<ProbeResp>(`/authsrc/sources/${encodeURIComponent(r.id)}/probe`, { method: 'POST' })
    };
  } catch (e) {
    // 后端原话原样进结果条（探测端点本身 200 回 ok:false；走到这里是 HTTP 层失败）。
    probes.value = { ...probes.value, [r.id]: { ok: false, detail: failReason(e) } };
  } finally {
    probing.value = '';
  }
}

function removeSource(r: AuthSourceRec) {
  Modal.warning({
    title: `删除认证源「${r.name}」`,
    // ★必须说清连带后果：删源会一起清掉身份绑定，那些外部用户下次登录会被重新建号。
    content: '删除会连同该源的凭据与外部身份绑定一起清除。绑定过的外部用户下次登录将被重新建号（原有本地账号会留成孤儿）。',
    okText: '确认删除', cancelText: '取消', hideCancel: false,
    onOk: async () => {
      try {
        await api(`/authsrc/sources/${encodeURIComponent(r.id)}`, { method: 'DELETE' });
        Message.success('已删除');
        await loadSources();
      } catch (e) {
        Message.error(`删除失败：${failReason(e)}`);
      }
    }
  });
}

/** 源 id → 归属该源的账号数（外部源 = 已绑定条数；本地目录 = 无外部绑定的账号数）。
 *  ★这不是"目录纳管用户数"，后者要遍历整个 LDAP。拿不到聚合返回 undefined，卡片显示 — 不是 0。 */
const boundBySource = computed<Record<string, number>>(() => {
  const m: Record<string, number> = {};
  for (const s of sources.value) m[s.key] = s.boundAccounts;
  return m;
});
function boundText(id: string): string {
  const n = boundBySource.value[id];
  return n === undefined ? '—' : `${n}`;
}
/** 外部源已绑定账号合计（本地目录不计入：那是本地账号，不是"从外部目录接进来的人"）。 */
const totalBoundExternal = computed(() =>
  sources.value.filter((s) => s.type !== 'local').reduce((n, s) => n + s.boundAccounts, 0)
);

/* ── 认证源映射 ── */
const TYPE_LABEL: Record<SrcType, string> = {
  local: '本地账号', ad: 'AD 域', ldap: 'LDAP', radius: 'RADIUS', oauth: 'OAuth', sms: '短信', cert: '证书'
};
/* 同 KIND_TONE，覆盖面多了存量策略引用的历史目录名（oauth/sms/cert）。 */
const TYPE_TONE: Record<SrcType, Tone> = {
  local: 'blue', ad: 'blue', ldap: 'purple', radius: 'gold', oauth: 'green', sms: 'gold', cert: 'purple'
};
const TYPE_ICON: Record<SrcType, string> = {
  local: 'icon-user', ad: 'icon-storage', ldap: 'icon-mind-mapping', radius: 'icon-wifi',
  oauth: 'icon-link', sms: 'icon-message', cert: 'icon-lock'
};
function srcIcon(t: SrcType) { return TYPE_ICON[t]; }
function typeTone(t: string): Tone { return TYPE_TONE[t as SrcType] ?? 'grey'; }
// ★卡片上刻意没有常驻的在线/离线状态灯：认证源可达性只有「测试连接」那一刻才知道，
// 常驻灯等于替一台可能早已宕掉的目录打包票。探测结果就地渲染在卡片上。

/* ── 规则：动作 ── */
const ACTIONS: { value: Action; label: string }[] = [
  { value: 'allow', label: '放行' },
  { value: 'mfa', label: '二次认证（MFA）' },
  { value: 'stepup', label: '升级认证强度' },
  { value: 'block', label: '阻断' }
];
const ACTION_LABEL: Record<Action, string> = {
  allow: '放行', mfa: '二次认证（MFA）', stepup: '升级认证强度', block: '阻断'
};
function actionLabel(a: Action) { return ACTION_LABEL[a]; }
function evalClass(a: Action) {
  return a === 'block' ? 'block' : a === 'allow' ? 'allow' : 'warn';
}

/* ── 规则：条件文案 ── */
const FIELD_LABEL: Record<CondField, string> = {
  weakPwd: '弱口令', geoAnomaly: '异地登录', offHours: '异常时段',
  riskScore: '风险分', untrustedDevice: '未授信终端', newDevice: '新设备'
};
const OP_SYMBOL: Record<RuleCond['op'], string> = { is: '=', gt: '>', in: '∈' };
function condText(c: RuleCond): string {
  const f = FIELD_LABEL[c.field];
  // 布尔类信号直接展示名称
  if (c.op === 'is' && (c.value === 'true' || c.value === 'false')) {
    return c.value === 'true' ? f : `非${f}`;
  }
  return `${f} ${OP_SYMBOL[c.op]} ${c.value}`;
}

function removeCond(r: AdaptiveRule, idx: number) {
  if (r.conditions.length <= 1) { Message.warning('每条规则至少保留一个条件'); return; }
  r.conditions.splice(idx, 1);
}
function addCond(r: AdaptiveRule) {
  r.conditions.push({ field: 'riskScore', op: 'gt', value: '60' });
}
function addRule() {
  const n = rules.value.length + 1;
  rules.value.push({
    id: 'r' + Date.now(), name: `新增规则 ${n}`, enabled: true, logic: 'AND', action: 'mfa', priority: n,
    conditions: [{ field: 'newDevice', op: 'is', value: 'true' }]
  });
}
/* ── 认证策略（FR-AUTH-12）── */
const policies = ref<AuthPolicy[]>([]);

/* ★这里的 'radius' 是「Radius 动态令牌」——**二次认证方式**（登录口令之外再验一次动态码），
 * 由后端 authpolicy.SecondaryMethods 能力声明置灰，本版本仍冻结。
 * 它与认证源列表里的 RADIUS（作为**口令认证源**，FR-INT-03，已实现）不是一回事：
 * 前者要把 RADIUS 当 OTP 校验器接进二次认证回合，后者是把口令交给 RADIUS 服务器去验。别顺手解灰。 */
const SECONDARY_OPTS: { value: SecondaryMethod; label: string }[] = [
  { value: 'sms', label: '短信' },
  { value: 'totp', label: 'TOTP 令牌' },
  { value: 'radius', label: 'Radius 动态令牌' },
  { value: 'cert', label: '证书 / USB-Key' },
  { value: 'http', label: 'HTTP(S) 令牌' }
];
const SECONDARY_LABEL: Record<string, string> = Object.fromEntries(SECONDARY_OPTS.map((o) => [o.value, o.label]));
function secondaryLabel(m: string) { return SECONDARY_LABEL[m] ?? m; }

/* 可作为「用户目录」被策略绑定的取值由后端下发（GET /authpolicy 的 directories）。
 * ★不许在前端写死一份：登录链路把 directory 置成真实认证源的 kind，前端少一个值，
 * 那个源的用户就在 Match 的第一刀里被筛光（永不二次认证），且页面上选不出、无从修。 */
const directories = ref<AuthDirectory[]>([]);
/** 目录 key → 友好名（后端下发的目录名优先；拿不到时回退到类型名或 key） */
function dirName(dir: string) {
  const d = directories.value.find((x) => x.key === dir);
  if (d) return d.name;
  return TYPE_LABEL[dir as SrcType] ?? dir;
}
const directorySources = computed(() =>
  directories.value.length
    ? directories.value.map((d) => ({
        key: d.key,
        // 未配置认证源的目录如实标注：留着可选（存量策略要能编辑），但不假装它在生效
        name: d.configured
          ? (d.sources.length ? `${d.name}（${d.sources.join('、')}）` : d.name)
          : `${d.name}（当前无已配置认证源）`
      }))
    : [{ key: 'local', name: '本地用户目录' }]
);

/** 按目录分组，组内按优先级升序（小者先匹配，默认策略优先级 100 自然沉底） */
/* ★分组以**后端下发的目录清单**为准，不能只遍历已有策略：已接入认证源却零策略的目录
   会整个从页面上消失，而那种目录的用户登录时 Match 找不到策略 → 二次认证要求为零，
   且零值分支一条审计都不写，三处都看不出异常（FR-AUTH-10）。 */
const grouped = computed(() => {
  const map = new Map<string, AuthPolicy[]>();
  for (const p of policies.value) {
    if (!map.has(p.directory)) map.set(p.directory, []);
    map.get(p.directory)!.push(p);
  }
  // 已配置认证源的目录一律成组（哪怕零策略），好让下面那条告警有地方显示。
  const dirs = directories.value ?? [];
  for (const d of dirs) {
    if (d.configured && !map.has(d.key)) map.set(d.key, []);
  }
  return [...map.entries()].map(([dir, list]) => ({
    dir, name: dirName(dir),
    warning: dirs.find((d) => d.key === dir)?.warning ?? '',
    list: [...list].sort((a, b) => a.priority - b.priority)
  }));
});

/* 摘要 chip：只展示**真会生效**的规则，且把判据一起摆出来（网段、工作时段），
 * 免得管理员要点进抽屉才知道"可信网络"到底指哪几段。 */
function exemptChips(p: AuthPolicy): string[] {
  const out: string[] = [];
  if (p.exempt.trustedDevice) out.push('授信终端免二次');
  if (p.exempt.trustedNetwork) out.push(`可信网络免二次（${(p.exempt.networks || []).join('、') || '未配网段'}）`);
  return out;
}
function enhanceChips(p: AuthPolicy): string[] {
  const out: string[] = [];
  if (p.enhance.always) out.push('范围内一律二次认证');
  if (p.enhance.weakPwd) out.push('弱密码增强');
  if (p.enhance.offHours) out.push(`非工作时段增强（${workWindowText(p.enhance)}）`);
  return out;
}
function workWindowText(e: EnhanceRule): string {
  const days = e.workDays?.length ? e.workDays : [1, 2, 3, 4, 5];
  const names = ['一', '二', '三', '四', '五', '六', '日'];
  const ds = days.filter((d) => d >= 1 && d <= 7).map((d) => '周' + names[d - 1]).join('/');
  return `${ds} ${e.workStart || '09:00'}-${e.workEnd || '18:00'}`;
}
/** 同时配了豁免与**风险**增强时，说清优先级（FR-AUTH-21：风险条件下豁免不生效）。
 *  只在两者同时存在时出现——没有冲突时不打扰人。
 *  ★「范围内一律二次认证」属基础档，可被豁免，故不计入风险档。 */
function exemptVsRisk(p: AuthPolicy): string {
  const hasExempt = p.exempt.trustedDevice || p.exempt.trustedNetwork;
  const risks: string[] = [];
  if (p.enhance.weakPwd) risks.push('弱密码');
  if (p.enhance.offHours) risks.push('非工作时段');
  if (!hasExempt || !risks.length) return '';
  return `命中「${risks.join('、')}」时，上面的免二次认证豁免**不生效**，仍会要求二次认证`
    + `（风险已经出现的时刻不该被豁免掉）；豁免只免除「范围内一律二次认证」那一档。`;
}

function hasAdaptive(p: AuthPolicy): boolean {
  return exemptChips(p).length > 0 || enhanceChips(p).length > 0;
}

/* 规则能力：能不能判、判据是什么，全部来自后端（与保存校验同源）。
 * 拿不到（后端不可达）时保守地按"可用"渲染，避免把可用的开关误置灰。 */
const capabilities = ref<AuthRuleCapability[]>([]);
function capOf(key: string): AuthRuleCapability | undefined {
  return capabilities.value.find((c) => c.key === key);
}
function can(key: string): boolean {
  const c = capOf(key);
  return c ? c.available : true;
}
/* 二次认证方式能力（authpolicy.SecondaryMethods）：置灰与保存校验同源。
 * 未拿到声明（降级演示模式）时不置灰——与 can() 同一条回退纪律。 */
const methodCaps = ref<AuthMethodCapability[]>([]);
function methodAvailable(key: string): boolean {
  const m = methodCaps.value.find((x) => x.key === key);
  return m ? m.available : true;
}
const totpMethod = computed(() => methodCaps.value.find((m) => m.key === 'totp' && m.available));
const frozenMethodNote = computed(() => {
  const off = methodCaps.value.filter((m) => !m.available).map((m) => m.label);
  return off.length ? `置灰的方式（${off.join('/')}）本版本未实现，保存也会被拒。` : '';
});
function capText(key: string): string {
  const c = capOf(key);
  if (!c) return '';
  return c.available ? c.effect : c.reason;
}

const WEEKDAYS = [
  { value: 1, label: '周一' }, { value: 2, label: '周二' }, { value: 3, label: '周三' },
  { value: 4, label: '周四' }, { value: 5, label: '周五' }, { value: 6, label: '周六' }, { value: 7, label: '周日' }
];

/* 适用范围候选：与资源策略页同一个来源（accounts 是服务端展开好的，含组织子树）。
 * ★前端绝不自己走组织树——子树语义实现两遍，管理员看到的人数迟早与判定用的对不上。 */
const orgOpts = ref<SubjectOption[]>([]);
const groupOpts = ref<SubjectOption[]>([]);
function orgName(id: string) { return orgOpts.value.find((o) => o.id === id)?.name || id; }
function groupName(id: string) { return groupOpts.value.find((g) => g.id === id)?.name || id; }
function expandAccounts(orgIds: string[], groupIds: string[]): string[] {
  const set = new Set<string>();
  for (const id of orgIds) orgOpts.value.find((o) => o.id === id)?.accounts.forEach((a) => set.add(a));
  for (const id of groupIds) groupOpts.value.find((g) => g.id === id)?.accounts.forEach((a) => set.add(a));
  return [...set];
}
function effectiveOf(p: AuthPolicy) { return expandAccounts(p.scopeOrgs || [], p.scopeGroups || []); }

/* 编辑抽屉 */
const editVisible = ref(false);
function blankPolicy(): AuthPolicy {
  return {
    id: '', name: '', directory: directorySources.value[0]?.key ?? 'local', isDefault: false,
    scope: '', priority: 50, enabled: true,
    secondary: [],
    scopeOrgs: [], scopeGroups: [],
    exempt: { trustedDevice: false, trustedNetwork: false, networks: [], winDomain: false },
    enhance: {
      always: false, weakPwd: false, offHours: false,
      workStart: '09:00', workEnd: '18:00', workDays: [1, 2, 3, 4, 5], geoAnomaly: false
    },
  };
}
/** 老库读回来的策略可能缺新字段（后端已回填，这里是渲染侧兜底）：补齐再进表单，避免 v-model 挂在 undefined 上。 */
function normalizePolicy(p: AuthPolicy): AuthPolicy {
  const b = blankPolicy();
  return {
    ...p,
    scopeOrgs: p.scopeOrgs ?? [], scopeGroups: p.scopeGroups ?? [],
    secondary: p.secondary ?? [],
    exempt: { ...b.exempt, ...(p.exempt ?? {}), networks: p.exempt?.networks ?? [] },
    enhance: { ...b.enhance, ...(p.enhance ?? {}), workDays: p.enhance?.workDays ?? [] }
  };
}
const editingScopeCount = computed(() => expandAccounts(editing.value.scopeOrgs, editing.value.scopeGroups).length);
const editing = ref<AuthPolicy>(blankPolicy());
function openCreate() { editing.value = blankPolicy(); editVisible.value = true; }
function openEdit(p: AuthPolicy) {
  // 深拷贝，避免抽屉里编辑直接改到列表（取消时还能回滚）
  editing.value = normalizePolicy(JSON.parse(JSON.stringify(p)));
  editVisible.value = true;
}
/* reportPolicyFailure 认证策略读写失败的统一转述口（原话仍由 failReason 收口）。
 *
 * ★409 单独走 Modal：那是后端的**防自锁闸**（FR-ADMIN-20）——正文是一段
 * 「谁会被挡在门外 + 两条真实存在的补救路径」的长文案，而 Message 是 3 秒后自动消失的
 * 浮层。读不完就没了的话，管理员看到的只剩"保存失败"四个字，会去反复重试同一个
 * 注定失败的操作；而这段话正是他唯一的出路说明。其余错误照旧走 toast。 */
function reportPolicyFailure(title: string, e: unknown) {
  const msg = failReason(e);
  if (failStatus(e) === 409) {
    Modal.error({ title, content: msg, okText: '知道了', width: 620 });
    return;
  }
  Message.error(`${title}：${msg}`);
}
async function savePolicy(): Promise<boolean> {
  const p = editing.value;
  if (!p.name.trim()) { Message.warning('请填写策略名称'); return false; }
  if (!p.directory) { Message.warning('请选择所属用户目录'); return false; }
  // 与后端 authpolicy.Validate 同口径的前置提醒（真正的闸在后端，这里只是少跑一趟）
  if (!p.isDefault && !p.scopeOrgs.length && !p.scopeGroups.length) {
    Message.warning('非默认策略必须绑定适用范围（组织或用户组），否则它匹配不到任何账号');
    return false;
  }
  if (p.exempt.trustedNetwork && !p.exempt.networks.length) {
    Message.warning('启用「可信网络」豁免必须至少配置一个网段（CIDR）');
    return false;
  }
  try {
    await api<{ ok: boolean; policy: AuthPolicy }>('/authpolicy', { method: 'POST', body: JSON.stringify(p) });
    Message.success(p.id ? '策略已更新' : '策略已新增');
    await loadPolicies();
    return true;
  } catch (e) {
    reportPolicyFailure('保存失败', e);
    return false;
  }
}
function removePolicy(p: AuthPolicy) {
  Modal.warning({
    title: '删除认证策略',
    content: `确认删除「${p.name}」？该范围用户将回落到所属目录的默认策略。`,
    hideCancel: false,
    onOk: async () => {
      try {
        await api(`/authpolicy/${p.id}`, { method: 'DELETE' });
        Message.success('策略已删除');
        await loadPolicies();
      } catch (e) {
        reportPolicyFailure('删除失败', e);
      }
    }
  });
}
async function loadPolicies() {
  try {
    const r = await api<AuthPolicyResp>('/authpolicy');
    policies.value = (r.policies ?? []).map(normalizePolicy);
    capabilities.value = r.capabilities ?? [];
    methodCaps.value = r.methods ?? [];
    directories.value = r.directories ?? [];
    orgOpts.value = r.orgs ?? [];
    groupOpts.value = r.groups ?? [];
    polErr.value = '';
  } catch (e) {
    // ★不能只是"保持空列表"：空列表在策略页签上渲染成「共 0 条策略」+ 零分组，
    // 与「一条都没配、全体走默认」完全同形；原话经 polErr 渲染成页签内的 danger 空态。
    // 上一次成功读到的策略 / 候选一并清掉——否则页面一边说「未读取」一边画着旧数据。
    policies.value = [];
    capabilities.value = [];
    methodCaps.value = [];
    directories.value = [];
    orgOpts.value = [];
    groupOpts.value = [];
    polErr.value = failReason(e);
  }
}

/* ── 规则求值预览 ── */
type CtxKey = CondField | 'highRisk';
const CTX: { field: CtxKey; label: string; detail: string }[] = [
  { field: 'weakPwd', label: '弱口令', detail: '口令命中弱密码字典' },
  { field: 'geoAnomaly', label: '异地登录', detail: '登录地与常用地不符' },
  { field: 'untrustedDevice', label: '未授信终端', detail: '设备未纳管或未绑定' },
  { field: 'newDevice', label: '新设备', detail: '首次出现的设备指纹' },
  { field: 'offHours', label: '异常时段', detail: '处于 22:00-06:00 时段' },
  { field: 'highRisk', label: '风险分偏高', detail: '综合风险分 > 70' }
];

const ctx = reactive<Record<string, boolean>>({
  weakPwd: false, geoAnomaly: false, untrustedDevice: false, newDevice: false, offHours: false, highRisk: false
});

/** 单条件求值：把模拟上下文映射到条件命中与否 */
function condHit(c: RuleCond): boolean {
  switch (c.field) {
    case 'weakPwd': return ctx.weakPwd;
    case 'geoAnomaly': return ctx.geoAnomaly;
    case 'untrustedDevice': return ctx.untrustedDevice;
    case 'newDevice': return ctx.newDevice;
    case 'offHours': return ctx.offHours;
    case 'riskScore': {
      // gt：上下文风险分高视为 ~85，否则 ~20
      const score = ctx.highRisk ? 85 : 20;
      return score > Number(c.value);
    }
    default: return false;
  }
}
function ruleHit(r: AdaptiveRule): boolean {
  if (!r.enabled) return false;
  return r.logic === 'AND'
    ? r.conditions.every(condHit)
    : r.conditions.some(condHit);
}
const evalResult = computed<{ rule: AdaptiveRule | null; action: Action | null }>(() => {
  for (const r of rules.value) {
    if (ruleHit(r)) return { rule: r, action: r.action };
  }
  return { rule: null, action: null };
});

/* ── 拉取 ── */
onMounted(async () => {
  try {
    // 聚合只用来取真实账号计数（源清单本身以 loadSources 那份为准，两者同源同库）。
    const b = await api<AuthSrcBundle>('/authsrc');
    sources.value = b.sources ?? [];
    aggErr.value = '';
  } catch (e) {
    // 拿不到就清空计数：卡片上显示 —，而不是继续挂着上一次的数字或回落演示值。
    // 原因经 aggErr 渲染成页内红条——不然那几个「—」看起来像"还没有人登录过"。
    sources.value = [];
    aggErr.value = failReason(e);
  }
  await loadPolicies();
  await loadSources(); // 这一步结束时 live 才从 undefined 落成 true/false，页头标签在此之前不画
  await loadAdmissions();
  // 首屏骨架撤下：四次读取都已有结论（成功或失败原话），此后页面上不再有"还没问出来"的格子。
  loaded.value = true;
});
</script>

<style scoped>
/* 本页只保留**页面自有**的类。已全局化的 .bd-tabs/.bd-tab、.bd-section-title、.bd-link--danger、
   .bd-link--disabled（改用 button[disabled]）、.bd-mono、.bd-acts 都已从这里删掉——
   页内再抄一份的话，改全局那次就只有 20 页跟上、这一页留在原地。 */

/* 认证源（真数据那一套）*/
.bd-srchint { color: var(--bd-t3); margin-left: var(--bd-sp-3); font-size: var(--bd-fs-sm); }
/* 空态占满卡片网格的一整行（EmptyState 自己不知道它在 grid 里） */
.bd-srcgrid__empty { grid-column: 1 / -1; }
.bd-warn { color: var(--bd-warning); }
/* .bd-mono 的字体来自全局；这里只压回卡片大数字那一栏的字号（指纹不是一个"数"） */
.bd-srccard__kv b.bd-mono { font-size: var(--bd-fs-sm); font-weight: 500; }
.bd-probe { display: flex; align-items: center; gap: var(--bd-sp-2); font-size: var(--bd-fs-sm);
  padding: var(--bd-sp-2) var(--bd-sp-3); border-radius: var(--bd-radius-s);
  margin: var(--bd-sp-3) 0 2px; line-height: var(--bd-lh); }
.bd-probe.ok { color: var(--bd-success-t); background: var(--bd-success-1); }
.bd-probe.bad { color: var(--bd-danger-t); background: var(--bd-danger-1); }
.bd-probe__ms { margin-left: auto; opacity: .7; }

/* 认证源抽屉表单 */
.bd-srcform { display: flex; flex-direction: column; gap: var(--bd-sp-3); }
.bd-srcform__row { display: flex; flex-direction: column; gap: 6px; }
.bd-srcform__row label { font-size: var(--bd-fs-md); color: var(--bd-t2); }
.bd-srcform__row--inline { flex-direction: row; align-items: center; gap: var(--bd-sp-2); font-size: var(--bd-fs-md); }
.bd-srcform__pri { margin-left: auto; display: inline-flex; align-items: center; gap: 6px; color: var(--bd-t2); font-size: var(--bd-fs-md); }
.bd-srcform__sec { font-size: var(--bd-fs-sm); font-weight: 600; color: var(--bd-t3); letter-spacing: .5px;
  border-top: 1px solid var(--bd-border); padding-top: var(--bd-sp-3); margin-top: 2px; }
.bd-srcform__hint { font-size: var(--bd-fs-sm); color: var(--bd-t3); line-height: var(--bd-lh-loose); }
/* 字段级警示（不是页面级提示条，所以不用 .bd-notice）：紧贴着它解释的那个控件 */
.bd-srcform__warn { font-size: var(--bd-fs-sm); color: var(--bd-warning-t); line-height: var(--bd-lh-loose);
  background: var(--bd-warning-1); border: 1px solid var(--bd-warning-b);
  padding: var(--bd-sp-2) var(--bd-sp-3); border-radius: var(--bd-radius-s); }
/* 抽屉里几个定宽数字框（此前是 inline style="width:…"） */
.bd-num--pri { width: 76px; }
.bd-num--full { width: 100%; }
.bd-num--ms { width: 96px; }
.bd-num--n { width: 64px; }

/* ── 认证源 ── */
.bd-srctoolbar { display: flex; align-items: center; gap: var(--bd-sp-4); margin-bottom: var(--bd-sp-4); }
.bd-srctoolbar__sub { flex: 1; min-width: 0; font-size: var(--bd-fs-md); color: var(--bd-t3); line-height: var(--bd-lh); }
.bd-srctoolbar__sub b { color: var(--bd-t1); font-weight: 600; }
.bd-srctoolbar .bd-btn { margin-left: auto; flex: none; }

.bd-srcgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(312px, 1fr)); gap: var(--bd-sp-4); }
.bd-srccard { padding: var(--bd-sp-4) var(--bd-sp-5);
  transition: border-color var(--bd-dur-base) var(--bd-ease), box-shadow var(--bd-dur-base) var(--bd-ease); }
.bd-srccard:hover { border-color: var(--bd-primary-b); box-shadow: var(--bd-shadow-2); }
/* 骨架卡不响应 hover：它不是一张能点的卡 */
.bd-srccard--sk { padding: 0; pointer-events: none; }
.bd-srccard--sk:hover { border-color: var(--bd-border); box-shadow: none; }
.bd-srccard__top { display: flex; align-items: flex-start; gap: var(--bd-sp-3); }
.bd-srcicon { width: 40px; height: 40px; border-radius: var(--bd-radius); flex: none;
  display: inline-flex; align-items: center; justify-content: center; font-size: 20px; }
/* 源类型区分色：底/字成对，取值全部来自 token（此前是 inline 的 `色值 + '1A'`） */
.bd-srcicon--blue   { color: var(--bd-primary); background: var(--bd-tag-blue-bg); }
.bd-srcicon--purple { color: var(--bd-purple);  background: var(--bd-tag-purple-bg); }
.bd-srcicon--green  { color: var(--bd-success); background: var(--bd-success-1); }
.bd-srcicon--gold   { color: var(--bd-warning); background: var(--bd-warning-1); }
.bd-srcicon--grey   { color: var(--bd-t3);      background: var(--bd-fill-2); }
.bd-srccard__id { flex: 1; min-width: 0; }
.bd-srccard__name { font-size: var(--bd-fs-base); font-weight: 600; color: var(--bd-t1);
  display: flex; align-items: center; gap: var(--bd-sp-2); margin-bottom: 6px; }
.bd-primarytag { display: inline-flex; align-items: center; gap: 3px; font-size: var(--bd-fs-xs); font-weight: 500;
  color: var(--bd-warning-t); background: var(--bd-warning-1); padding: 1px 7px; border-radius: var(--bd-radius-pill); }
.bd-srccard__st { margin-left: auto; flex: none; }
/* RADIUS 源放弃应答侧 Message-Authenticator 校验时的常驻警示条。
   走 danger 那一族（底/边/字配套）：这是一层已经被亲手拿掉的保护，不是"注意一下"。 */
.bd-srccard__waive { display: flex; align-items: flex-start; gap: var(--bd-sp-2);
  margin-top: var(--bd-sp-3); padding: var(--bd-sp-2) var(--bd-sp-3);
  border: 1px solid var(--bd-danger-b); border-radius: var(--bd-radius-s);
  background: var(--bd-danger-1); color: var(--bd-danger-t);
  font-size: var(--bd-fs-sm); line-height: var(--bd-lh); }
.bd-srccard__waive svg { flex: none; margin-top: 2px; font-size: var(--bd-fs-base); }
.bd-srccard__foot { display: flex; align-items: center; margin-top: var(--bd-sp-4);
  padding-top: var(--bd-sp-3); border-top: 1px solid var(--bd-border-2); }
.bd-srccard__kv { display: flex; flex-direction: column; gap: 2px; }
.bd-srccard__kv span { font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.bd-srccard__kv b { font-size: 18px; font-weight: 700; color: var(--bd-t1); line-height: 1; }
.bd-srccard__acts { margin-left: auto; font-size: var(--bd-fs-md); }
/* 「内置不可改」是说明不是动作，所以不是按钮，也不给主色 */
.bd-srccard__note { font-size: var(--bd-fs-md); color: var(--bd-t3); }

/* ── 自适应认证规则 ── */
.bd-rulewrap { display: flex; gap: var(--bd-sp-4); align-items: flex-start; }
.bd-rulemain { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: var(--bd-sp-3); }
.bd-rulepreview { width: 316px; flex: none; position: sticky; top: var(--bd-sp-5); }

.bd-ruleintro { display: flex; gap: var(--bd-sp-3); padding: var(--bd-sp-3) var(--bd-sp-4);
  font-size: var(--bd-fs-md); line-height: var(--bd-lh-loose); color: var(--bd-t2);
  background: var(--bd-primary-1); border-color: var(--bd-primary-b); }
.bd-ruleintro__ic { color: var(--bd-primary); font-size: 18px; flex: none; margin-top: 2px; }
.bd-ruleintro b { color: var(--bd-t1); font-weight: 600; }

/* 规则行 */
.bd-rule { display: flex; align-items: stretch; padding: var(--bd-sp-3) var(--bd-sp-4) var(--bd-sp-3) var(--bd-sp-2);
  gap: var(--bd-sp-3); transition: opacity var(--bd-dur-fast) var(--bd-ease); }
.bd-rule.off { opacity: .58; }
.bd-rule__handle { display: flex; align-items: center; color: var(--bd-t4); cursor: grab; font-size: var(--bd-fs-lg); }
.bd-rule__handle:active { cursor: grabbing; }
.bd-rule__pri { width: 22px; height: 22px; border-radius: var(--bd-radius-xs); flex: none; align-self: center;
  display: inline-flex; align-items: center; justify-content: center;
  font-size: var(--bd-fs-sm); font-weight: 700; color: var(--bd-primary); background: var(--bd-primary-1); }
.bd-rule__body { flex: 1; min-width: 0; }
.bd-rule__head { display: flex; align-items: center; margin-bottom: var(--bd-sp-3); }
.bd-rule__name { font-size: var(--bd-fs-base); font-weight: 600; color: var(--bd-t1); }
.bd-rule__sw { margin-left: auto; }

.bd-rule__flow { display: flex; align-items: center; gap: var(--bd-sp-3); flex-wrap: wrap; }
.bd-clause { font-size: var(--bd-fs-xs); font-weight: 700; letter-spacing: .5px; color: var(--bd-t3); font-family: var(--bd-font-mono); }

.bd-if { display: flex; align-items: center; gap: var(--bd-sp-2); flex-wrap: wrap; flex: 1; min-width: 0; }
.bd-chip { display: inline-flex; align-items: center; gap: 6px; font-size: var(--bd-fs-md); color: var(--bd-t1);
  background: var(--bd-bg-1); border: 1px solid var(--bd-border); border-radius: var(--bd-radius-pill);
  padding: var(--bd-sp-1) var(--bd-sp-3); font-weight: 500; }
.bd-chip__x { font-size: var(--bd-fs-xs); color: var(--bd-t4); cursor: pointer; }
.bd-chip__x:hover { color: var(--bd-danger); }
.bd-logic { font-size: var(--bd-fs-xs); font-weight: 700; padding: 3px 9px; border-radius: var(--bd-radius-pill);
  cursor: pointer; user-select: none; transition: background var(--bd-dur-fast) var(--bd-ease); }
.bd-logic.and { color: var(--bd-primary); background: var(--bd-primary-1); }
.bd-logic.or { color: var(--bd-purple); background: var(--bd-tag-purple-bg); }
.bd-logic:hover { filter: brightness(.96); }
.bd-addcond { display: inline-flex; align-items: center; gap: var(--bd-sp-1); font-size: var(--bd-fs-sm);
  color: var(--bd-primary); background: transparent; border: 1px dashed var(--bd-primary-b);
  border-radius: var(--bd-radius-pill); padding: 3px var(--bd-sp-3); cursor: pointer; }
.bd-addcond:hover { background: var(--bd-primary-1); }

.bd-flow__arrow { color: var(--bd-t4); font-size: var(--bd-fs-lg); flex: none; }

.bd-then { display: flex; align-items: center; gap: var(--bd-sp-2); flex: none; }
/* 动作下拉：用自管 wrapper 着色，避开 Arco view 内部样式优先级 */
.bd-actionwrap { display: inline-flex; align-items: center; gap: 7px; height: 30px; padding: 0 var(--bd-sp-2) 0 11px;
  border: 1px solid var(--bd-border); border-radius: var(--bd-radius-s); --bd-act: var(--bd-t2); }
.bd-actionwrap.block { --bd-act: var(--bd-danger); border-color: var(--bd-danger); background: var(--bd-danger-1); }
.bd-actionwrap.warn { --bd-act: var(--bd-warning); border-color: var(--bd-warning); background: var(--bd-warning-1); }
.bd-actionwrap.allow { --bd-act: var(--bd-success); border-color: var(--bd-success); background: var(--bd-success-1); }
.bd-actiondot { width: 7px; height: 7px; border-radius: 50%; flex: none; background: var(--bd-act); }
.bd-actionsel { width: 142px; }
/* 经带 scope 的 wrapper 用 :deep 穿透到 Arco view（select 根无 scope 属性） */
.bd-actionwrap :deep(.arco-select-view) { background: transparent !important; border: none !important; box-shadow: none !important; padding: 0; color: var(--bd-act) !important; }
.bd-actionwrap :deep(.arco-select-view-value) { color: var(--bd-act); font-weight: 600; }
.bd-actionwrap :deep(.arco-select-view-icon) { color: var(--bd-act); }

.bd-addrule { align-self: flex-start; border-style: dashed; }

/* ── 求值预览 ── */
.bd-preview { padding: var(--bd-sp-4) var(--bd-sp-5) var(--bd-sp-5); }
.bd-preview__sub { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin-bottom: var(--bd-sp-3); }
.bd-ctxlist { display: flex; flex-direction: column; gap: 2px; margin-bottom: var(--bd-sp-4); }
.bd-ctxrow { display: flex; align-items: center; gap: 9px; padding: var(--bd-sp-2); border-radius: var(--bd-radius-s);
  cursor: pointer; transition: background var(--bd-dur-fast) var(--bd-ease); }
.bd-ctxrow:hover { background: var(--bd-fill-1); }
.bd-ctxrow__t { font-size: var(--bd-fs-md); font-weight: 500; color: var(--bd-t1); }
.bd-ctxrow__d { margin-left: auto; font-size: var(--bd-fs-xs); color: var(--bd-t3); text-align: right; }

.bd-evalout { border-radius: var(--bd-radius); padding: var(--bd-sp-4); text-align: center;
  border: 1px solid var(--bd-border); background: var(--bd-fill-1); }
.bd-evalout__l { font-size: var(--bd-fs-xs); color: var(--bd-t3); }
.bd-evalout__rule { font-size: var(--bd-fs-base); font-weight: 600; color: var(--bd-t1); margin-top: var(--bd-sp-1); }
.bd-evalout__rule.muted { color: var(--bd-t3); font-weight: 500; }
.bd-evalout__arrow { color: var(--bd-t4); font-size: var(--bd-fs-base); margin: 6px 0; }
.bd-evalout__act { font-size: var(--bd-fs-xl); font-weight: 700; margin-top: var(--bd-sp-1); }
.bd-evalout__act.muted { color: var(--bd-t3); font-weight: 600; }
/* 按动作着色边框 + 文字 */
.bd-evalout.block { border-color: var(--bd-danger); background: var(--bd-danger-1); }
.bd-evalout.block .bd-evalout__act { color: var(--bd-danger); }
.bd-evalout.warn { border-color: var(--bd-warning); background: var(--bd-warning-1); }
.bd-evalout.warn .bd-evalout__act { color: var(--bd-warning); }
.bd-evalout.allow { border-color: var(--bd-success); background: var(--bd-success-1); }
.bd-evalout.allow .bd-evalout__act { color: var(--bd-success); }

/* ── 认证策略 ── */
.bd-pgroup { margin-bottom: var(--bd-sp-6); }
.bd-pgroup__head { display: flex; align-items: center; gap: var(--bd-sp-3); margin-bottom: var(--bd-sp-3); }
.bd-pgroup__ic { width: 30px; height: 30px; border-radius: var(--bd-radius-s); font-size: var(--bd-fs-lg); }
.bd-pgroup__name { font-size: var(--bd-fs-base); font-weight: 600; color: var(--bd-t1); }
.bd-pgroup__cnt { font-size: var(--bd-fs-sm); color: var(--bd-t3); background: var(--bd-fill-2);
  padding: 2px 9px; border-radius: var(--bd-radius-pill); }
/* 分组告警用全局 .bd-notice--warn，这里只收一下它在分组内的下间距 */
.bd-pgroup__warn { margin-bottom: var(--bd-sp-3); }

.bd-pcard { padding: var(--bd-sp-4) var(--bd-sp-5); margin-bottom: var(--bd-sp-3);
  transition: opacity var(--bd-dur-fast) var(--bd-ease), box-shadow var(--bd-dur-base) var(--bd-ease); }
.bd-pcard:hover { box-shadow: var(--bd-shadow-2); }
.bd-pcard.off { opacity: .62; }
.bd-pcard__head { display: flex; align-items: flex-start; gap: var(--bd-sp-3); }
.bd-pcard__title { display: flex; align-items: center; gap: var(--bd-sp-2); flex-wrap: wrap; flex: 1; min-width: 0; }
.bd-pcard__name { font-size: var(--bd-fs-base); font-weight: 600; color: var(--bd-t1); }
.bd-tg--default { color: var(--bd-primary); background: var(--bd-primary-1); font-weight: 600; }
.bd-tg--pri { color: var(--bd-t3); background: var(--bd-fill-2); }
.bd-tg--off { color: var(--bd-t3); background: var(--bd-fill-2); }
.bd-tg--sec { color: var(--bd-purple); background: var(--bd-tag-purple-bg); }
.bd-pcard__acts { flex: none; }
.bd-pcard__acts .bd-link { display: inline-flex; align-items: center; gap: var(--bd-sp-1); font-size: var(--bd-fs-md); }
.bd-pcard__scope { font-size: var(--bd-fs-md); color: var(--bd-t3); margin: var(--bd-sp-1) 0 var(--bd-sp-3); }

.bd-plat { border: 1px solid var(--bd-border-2); border-radius: var(--bd-radius-s);
  padding: var(--bd-sp-3) var(--bd-sp-4); background: var(--bd-fill-1); }
.bd-plat__row { display: flex; align-items: baseline; gap: 6px; flex-wrap: wrap; margin-top: 0; }
/* ★不设定宽：PC/移动端两栏合并后这里只剩一行，56px 是那个两行布局的遗留，
   它把「可接受的二次认证方式」挤成三行、右边空一大片。 */
.bd-plat__k { font-size: var(--bd-fs-sm); color: var(--bd-t3); flex: none; }
.bd-plat__none { font-size: var(--bd-fs-sm); color: var(--bd-t4); }

.bd-pcard__foot { display: flex; align-items: center; gap: var(--bd-sp-2); flex-wrap: wrap;
  margin-top: var(--bd-sp-3); padding-top: var(--bd-sp-3); border-top: 1px solid var(--bd-border-2); }
.bd-foot__k { font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.bd-mtg { display: inline-flex; align-items: center; gap: var(--bd-sp-1); font-size: var(--bd-fs-sm);
  font-weight: 500; padding: 2px 9px; border-radius: var(--bd-radius-pill); }
.bd-mtg--ok { color: var(--bd-success-t); background: var(--bd-success-1); }
.bd-mtg--warn { color: var(--bd-warning-t); background: var(--bd-warning-1); }

/* ── 编辑抽屉表单 ── */
.bd-form { display: flex; flex-direction: column; gap: var(--bd-sp-4); }
.bd-form__row { display: flex; flex-direction: column; gap: 6px; }
.bd-form__lab { font-size: var(--bd-fs-md); color: var(--bd-t2); font-weight: 500; }
.bd-form__lab em { color: var(--bd-danger); font-style: normal; }
.bd-form__2col { display: grid; grid-template-columns: 1fr 1fr; gap: var(--bd-sp-3); }
.bd-form__sec { border: 1px solid var(--bd-border-2); border-radius: var(--bd-radius-s);
  padding: var(--bd-sp-3) var(--bd-sp-4); background: var(--bd-fill-1); }
.bd-form__sech { font-size: var(--bd-fs-md); font-weight: 600; color: var(--bd-t2); margin-bottom: var(--bd-sp-3); }

/* ── 规则能力说明 / 规则行（每条开关下面就写清判据，不必点进文档）── */
.bd-capbox { padding: var(--bd-sp-3) var(--bd-sp-4); margin-bottom: var(--bd-sp-3); }
.bd-capbox__h { display: flex; align-items: center; gap: 6px; font-size: var(--bd-fs-md); font-weight: 600;
  color: var(--bd-t2); margin-bottom: var(--bd-sp-2); }
.bd-caprow { display: flex; align-items: baseline; gap: var(--bd-sp-2); padding: 5px 0;
  border-top: 1px solid var(--bd-border-2); font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.bd-caprow:first-of-type { border-top: none; }
.bd-caprow.off { opacity: .72; }
.bd-caprow__n { color: var(--bd-t1); font-weight: 600; flex: none; }
.bd-caprow__d { color: var(--bd-t3); line-height: var(--bd-lh-loose); }
.bd-tg--warnbox { color: var(--bd-warning-t); background: var(--bd-warning-1); }
.bd-sub { font-style: normal; margin-left: var(--bd-sp-1); opacity: .75; }

.bd-ruleintro__warn { display: flex; align-items: baseline; gap: 6px; margin-top: var(--bd-sp-2);
  padding-top: var(--bd-sp-2); border-top: 1px dashed var(--bd-border);
  color: var(--bd-warning-t); font-size: var(--bd-fs-sm); line-height: var(--bd-lh-loose); }
.bd-ruleintro__warn .bd-link { color: var(--bd-primary); }

.bd-form__rules { display: flex; flex-direction: column; gap: var(--bd-sp-3); }
.bd-rulerow { display: flex; flex-direction: column; gap: var(--bd-sp-1); }
.bd-rulerow.off { opacity: .7; }
.bd-rulerow__d { font-size: var(--bd-fs-sm); color: var(--bd-t3); line-height: var(--bd-lh-loose); padding-left: var(--bd-sp-6); }
.bd-rulerow__cfg { display: flex; align-items: center; gap: var(--bd-sp-2); flex-wrap: wrap;
  padding-left: var(--bd-sp-6); margin-top: var(--bd-sp-1); }
.bd-rulerow__time { width: 106px; }
.bd-rulerow__days { min-width: 240px; }
.bd-form__hint { font-size: var(--bd-fs-sm); color: var(--bd-t3); line-height: var(--bd-lh-loose); }
.bd-form__hint.bad { color: var(--bd-warning-t); }
.bd-form__hint--lead { margin-bottom: var(--bd-sp-3); }
.bd-form__hint--gap { margin-top: var(--bd-sp-2); }
.bd-form__hint-dim { color: var(--bd-t3); }

/* 待批外部身份准入 */
.bd-admit { margin-top: var(--bd-sp-5); }
.bd-admit__err { margin-top: var(--bd-sp-4); }
.bd-admit__count { margin-left: var(--bd-sp-3); font-size: var(--bd-fs-sm); font-weight: 400; color: var(--bd-t3); }
.bd-admit__hint { font-size: var(--bd-fs-md); color: var(--bd-t3); line-height: var(--bd-lh-loose); margin: 6px 0 var(--bd-sp-3); }
.bd-admit__row { display: flex; align-items: center; gap: var(--bd-sp-3); padding: var(--bd-sp-3) var(--bd-sp-4); margin-bottom: var(--bd-sp-2); }
.bd-admit__who { display: flex; align-items: center; gap: var(--bd-sp-2); font-size: var(--bd-fs-base); min-width: 260px; }
.bd-admit__acct { color: var(--bd-t3); font-size: var(--bd-fs-sm); }
.bd-admit__meta { display: flex; flex-wrap: wrap; gap: var(--bd-sp-3); font-size: var(--bd-fs-sm); color: var(--bd-t3); flex: 1; }
.bd-admit__sub { max-width: 320px; font-size: var(--bd-fs-sm); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bd-admit__act { display: flex; gap: var(--bd-sp-2); flex: none; }
.bd-pcard__note { display: flex; align-items: flex-start; gap: 6px; margin-top: var(--bd-sp-2);
  padding: var(--bd-sp-2) var(--bd-sp-3); font-size: var(--bd-fs-sm); line-height: var(--bd-lh-loose);
  border-radius: var(--bd-radius-xs); color: var(--bd-t3); background: var(--bd-fill-1); }

/* 1280×800：右侧求值预览栏与左窄栏一起收，避免整页横向滚动 */
@media (max-width: 1320px) {
  .bd-rulepreview { width: 276px; }
  .bd-srcgrid { grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); }
}
</style>
