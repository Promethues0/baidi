<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">认证源接入</div>
        <div class="bd-page__sub">统一身份源 · 自适应认证：身份 × 终端 × 行为动态定级</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'source' }" @click="tab = 'source'">认证源</span>
      <span class="bd-tab" :class="{ on: tab === 'policy' }" @click="tab = 'policy'">认证策略</span>
      <span class="bd-tab" :class="{ on: tab === 'rule' }" @click="tab = 'rule'">自适应认证规则</span>
    </div>

    <!-- ============ 认证源（真落库、真探测、真参与登录）============ -->
    <div v-show="tab === 'source'">
      <div class="bd-srctoolbar">
        <div class="bd-srctoolbar__sub">
          已接入 <b>{{ recs.length }}</b> 个身份源<!--
            ★聚合拿不到时整条不渲染，而不是显示 0：「0 个绑定账号」与「我没拿到计数」
               是两回事，后者不该长成前者的样子。
          --><template v-if="sources.length"> · 外部目录已绑定 <b>{{ totalBoundExternal }}</b> 个账号</template>
          <!-- ★"已绑定账号"= auth_source_bindings 里的真实条数（外部用户登录过一次即建绑定），
               **不是**目录纳管用户数：后者要全量遍历 LDAP 才数得出来，白帝没有那个能力，
               原实现里的「AD 域 1160 用户」是凭空写的。 -->
          <span class="bd-srchint">登录按「本地目录 → 外部源（按优先级）」依次询问</span>
        </div>
        <button class="bd-btn" @click="openSrcCreate"><icon-plus />接入认证源</button>
      </div>

      <div class="bd-srcgrid">
        <div v-for="s in recs" :key="s.id" class="bd-card bd-srccard">
          <div class="bd-srccard__top">
            <span class="bd-srcicon" :style="kindIconStyle(s.kind)">
              <component :is="kindIcon(s.kind)" />
            </span>
            <div class="bd-srccard__id">
              <div class="bd-srccard__name">
                {{ s.name }}
                <span v-if="s.kind === 'local'" class="bd-primarytag"><icon-star-fill />内置</span>
              </div>
              <span class="bd-tg" :style="tagStyle(kindColor(s.kind))">{{ kindLabel(s.kind) }}</span>
            </div>
            <span class="bd-st bd-srccard__st">
              <span class="d" :style="{ background: s.enabled ? '#00B42A' : '#86909C' }" />
              {{ s.enabled ? '已启用' : '已停用' }}
            </span>
          </div>

          <!-- 探测结果：这个按钮此前是纯装饰，现在真的去连目录 / 拉发现文档 -->
          <div v-if="probeOf(s.id)" class="bd-probe" :class="probeOf(s.id)!.ok ? 'ok' : 'bad'">
            <component :is="probeOf(s.id)!.ok ? 'icon-check-circle-fill' : 'icon-close-circle-fill'" />
            <span>{{ probeOf(s.id)!.detail }}</span>
            <span v-if="probeOf(s.id)!.elapsedMs !== undefined" class="bd-probe__ms">
              {{ probeOf(s.id)!.elapsedMs }}ms
            </span>
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
            <div class="bd-srccard__acts">
              <span v-if="s.kind !== 'local'" class="bd-link" @click="probe(s)">
                {{ probing === s.id ? '测试中…' : '测试连接' }}
              </span>
              <span v-if="s.kind !== 'local'" class="bd-link" @click="openSrcEdit(s)">编辑</span>
              <span v-if="s.kind !== 'local'" class="bd-link bd-link--danger" @click="removeSource(s)">删除</span>
              <span v-else class="bd-link bd-link--grey">内置不可改</span>
            </div>
          </div>
        </div>
        <div v-if="!recs.length" class="bd-srcempty">尚未接入任何认证源</div>
      </div>

      <!-- ── 待批准入（wave8 行动 10）──
           ★没有这一块，「需管理员批准」那档就是个死路：闸挡住了人，
           而管理员在界面上没有任何地方能批。 -->
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
          按<b>用户目录</b>分组编排 · 共 <b>{{ policies.length }}</b> 条策略 · PC/WEB 端与移动端 APP 分别配置主认证 / 二次认证
          <span class="bd-srchint">自适应规则由登录链路实时求值：命中增强条件且未被豁免即要求二次认证</span>
        </div>
        <button class="bd-btn" @click="openCreate"><icon-plus />新增策略</button>
      </div>

      <!-- 能力说明：哪几条能判、判据是什么；判不了的在这里就说清，不留"配了不生效"的想象空间 -->
      <div class="bd-card bd-capbox">
        <div class="bd-capbox__h"><icon-info-circle />规则生效说明</div>
        <div class="bd-caprow" v-for="c in capabilities" :key="c.key" :class="{ off: !c.available }">
          <span class="bd-tg" :style="tagStyle(c.kind === 'enhance' ? '#FF7D00' : '#00B42A')">
            {{ c.kind === 'enhance' ? '增强' : '豁免' }}
          </span>
          <b class="bd-caprow__n">{{ c.label }}</b>
          <span v-if="!c.available" class="bd-tg bd-tg--off">本版本不可用</span>
          <span class="bd-caprow__d">{{ c.available ? c.effect : c.reason }}</span>
        </div>
      </div>

      <div v-for="g in grouped" :key="g.dir" class="bd-pgroup">
        <div class="bd-pgroup__head">
          <span class="bd-srcicon bd-pgroup__ic" :style="srcIconStyle(g.dir as any)"><component :is="srcIcon(g.dir as any)" /></span>
          <span class="bd-pgroup__name">{{ g.name }}</span>
          <span class="bd-pgroup__cnt">{{ g.list.length }} 条策略</span>
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
            <div class="bd-pcard__acts">
              <span class="bd-link" @click="openEdit(p)"><icon-edit />编辑</span>
              <span
                v-if="!p.isDefault"
                class="bd-link bd-link--danger"
                @click="removePolicy(p)"
              ><icon-delete />删除</span>
              <span v-else class="bd-link bd-link--disabled" title="默认策略不可删除"><icon-lock />默认</span>
            </div>
          </div>
          <div class="bd-pcard__scope">
            <span v-if="p.scope">{{ p.scope }}</span>
            <!-- 真正参与匹配的是下面这些主体；文字说明只是备注 -->
            <template v-if="p.isDefault">
              <span class="bd-tg bd-tg--pri">该目录全体用户（默认策略）</span>
            </template>
            <template v-else-if="(p.scopeOrgs || []).length || (p.scopeGroups || []).length">
              <span v-for="o in p.scopeOrgs || []" :key="'o' + o" class="bd-tg" :style="tagStyle('#00B42A')">
                组织 {{ orgName(o) }}<em class="bd-sub">含子部门</em>
              </span>
              <span v-for="g in p.scopeGroups || []" :key="'g' + g" class="bd-tg" :style="tagStyle('#FF7D00')">
                用户组 {{ groupName(g) }}
              </span>
              <span class="bd-tg bd-tg--pri">生效账号 {{ effectiveOf(p).length }}</span>
            </template>
            <!-- 未绑定范围的非默认策略匹配不到任何人：如实说出来，别让它看着像在生效 -->
            <span v-else class="bd-tg bd-tg--warnbox">未绑定适用范围，不会命中任何账号</span>
          </div>

          <!-- 两端分栏 -->
          <div class="bd-platgrid">
            <div class="bd-plat">
              <div class="bd-plat__h"><icon-desktop /> PC / WEB 端</div>
              <div class="bd-plat__row">
                <span class="bd-plat__k">主认证</span>
                <span class="bd-tg" :style="tagStyle(primaryColor(p.pc.primary))">{{ primaryLabel(p.pc.primary) }}</span>
              </div>
              <div class="bd-plat__row">
                <span class="bd-plat__k">二次认证</span>
                <template v-if="p.pc.secondary.length">
                  <span v-for="s in p.pc.secondary" :key="s" class="bd-tg bd-tg--sec">{{ secondaryLabel(s) }}</span>
                </template>
                <span v-else class="bd-plat__none">无（单因素）</span>
              </div>
            </div>
            <div class="bd-plat">
              <div class="bd-plat__h"><icon-mobile /> 移动端 APP</div>
              <div class="bd-plat__row">
                <span class="bd-plat__k">主认证</span>
                <span class="bd-tg" :style="tagStyle(primaryColor(p.mobile.primary))">{{ primaryLabel(p.mobile.primary) }}</span>
              </div>
              <div class="bd-plat__row">
                <span class="bd-plat__k">二次认证</span>
                <template v-if="p.mobile.secondary.length">
                  <span v-for="s in p.mobile.secondary" :key="s" class="bd-tg bd-tg--sec">{{ secondaryLabel(s) }}</span>
                </template>
                <span v-else class="bd-plat__none">无（单因素）</span>
              </div>
            </div>
          </div>

          <!-- 自适应摘要 -->
          <div class="bd-pcard__foot">
            <span class="bd-foot__k">自适应</span>
            <span v-for="e in exemptChips(p)" :key="'ex-' + e" class="bd-mtg bd-mtg--ok"><icon-check-circle />{{ e }}</span>
            <span v-for="e in enhanceChips(p)" :key="'en-' + e" class="bd-mtg bd-mtg--warn"><icon-exclamation-circle />{{ e }}</span>
            <span v-if="!hasAdaptive(p)" class="bd-plat__none">未启用自适应</span>
            <span class="bd-foot__authz"><icon-apps />{{ p.authzApps || '不授权' }}</span>
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

        <!-- 两端认证方式 -->
        <div class="bd-form__platgrid">
          <div class="bd-form__plat">
            <div class="bd-form__plath"><icon-desktop /> PC / WEB 端</div>
            <label class="bd-form__lab">主认证 <em>*</em></label>
            <a-select v-model="editing.pc.primary" placeholder="选择主认证方式">
              <a-option v-for="m in PRIMARY_OPTS" :key="m.value" :value="m.value">{{ m.label }}</a-option>
            </a-select>
            <label class="bd-form__lab" style="margin-top: 10px">二次认证（可多选）</label>
            <a-select v-model="editing.pc.secondary" multiple placeholder="无则单因素登录" :max-tag-count="3">
              <a-option v-for="m in SECONDARY_OPTS" :key="m.value" :value="m.value" :disabled="!methodAvailable(m.value)">
                {{ m.label }}{{ methodAvailable(m.value) ? '' : '（未实现）' }}
              </a-option>
            </a-select>
          </div>
          <div class="bd-form__plat">
            <div class="bd-form__plath"><icon-mobile /> 移动端 APP</div>
            <label class="bd-form__lab">主认证 <em>*</em></label>
            <a-select v-model="editing.mobile.primary" placeholder="选择主认证方式">
              <a-option v-for="m in PRIMARY_OPTS" :key="m.value" :value="m.value">{{ m.label }}</a-option>
            </a-select>
            <label class="bd-form__lab" style="margin-top: 10px">二次认证（可多选）</label>
            <a-select v-model="editing.mobile.secondary" multiple placeholder="无则单因素登录" :max-tag-count="3">
              <a-option v-for="m in SECONDARY_OPTS" :key="m.value" :value="m.value" :disabled="!methodAvailable(m.value)">
                {{ m.label }}{{ methodAvailable(m.value) ? '' : '（未实现）' }}
              </a-option>
            </a-select>
          </div>
        </div>
        <!-- 方式能力说明：置灰的是未实现的（后端能力声明同源，保存也会被拒）。 -->
        <div v-if="totpMethod" class="bd-form__hint" style="margin-top: 8px">
          <b>TOTP 动态口令</b>：{{ totpMethod.effect }}
          <template v-if="frozenMethodNote">　<span style="color: var(--bd-t3)">{{ frozenMethodNote }}</span></template>
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
                <a-time-picker v-model="editing.enhance.workStart" format="HH:mm" style="width: 106px" />
                <span>—</span>
                <a-time-picker v-model="editing.enhance.workEnd" format="HH:mm" style="width: 106px" />
                <a-select v-model="editing.enhance.workDays" multiple placeholder="工作日（默认周一至周五）" style="min-width: 240px">
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
            <label class="bd-form__lab">默认授权应用</label>
            <a-input v-model="editing.authzApps" placeholder="如：默认授权全部应用 / 仅 OA / 不授权" allow-clear />
          </div>
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
            <div class="bd-ruleintro__warn">
              <icon-exclamation-circle />
              本页为规则编排<b>交互沙盘</b>：改动不落库、不参与登录判定。真正在登录链路生效的自适应规则请在
              <span class="bd-link" @click="tab = 'policy'">「认证策略」</span>中配置。
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
          <a-select v-model="srcForm.kind" :disabled="!!srcForm.id">
            <a-option v-for="k in KIND_OPTS" :key="k.v" :value="k.v" :disabled="!supported.includes(k.v)">
              {{ k.label }}<template v-if="!supported.includes(k.v)">（本版本未实现）</template>
            </a-option>
          </a-select>
          <!-- ★未实现的类型在这里就置灰。此前它们看起来可选，但后端从来没有实现过——
               「界面上能选、后端静默不生效」是这个项目反复吃亏的形态。 -->
          <div class="bd-srcform__hint">RADIUS / 短信网关 / 商密证书三类本版本未实现，已置灰</div>
        </div>

        <div class="bd-srcform__row bd-srcform__row--inline">
          <a-switch v-model="srcForm.enabled" /><span>启用（参与登录）</span>
          <span class="bd-srcform__pri">优先级
            <a-input-number v-model="srcForm.priority" :min="0" :max="99" size="small" style="width:76px" />
          </span>
        </div>

        <!-- ── LDAP / AD ── -->
        <template v-if="srcForm.kind === 'ldap' || srcForm.kind === 'ad'">
          <div class="bd-srcform__sec">目录连接</div>
          <div class="bd-srcform__row"><label>主机</label>
            <a-input v-model="ldap.host" placeholder="dc01.corp.example" allow-clear /></div>
          <div class="bd-srcform__row"><label>端口</label>
            <a-input-number v-model="ldap.port" :min="0" :max="65535" placeholder="0 = 按传输方式取默认" style="width:100%" /></div>
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
          <div class="bd-srcform__hint">
            仅接受 RS256/ES256 这类非对称签名；alg=none 与 HS256 会被拒绝（算法混淆攻击面）
          </div>
        </template>

        <!-- ── 外部身份准入（wave8 行动 10）──
             ★这一段是真判定，不是提示：改造前认证通过即自动建号，
             而自动建号的账号落进「外部目录」单元，其父是根组织——
             把资源授权给根组织就把这批人全覆盖了。 -->
        <template v-if="srcForm.kind !== 'local'">
          <div class="bd-srcform__sec">外部身份准入</div>
          <div class="bd-srcform__row"><label>未导入用户</label>
            <a-select v-model="admit.admitPolicy">
              <a-option value="auto">认证通过即自动建号</a-option>
              <a-option value="approval">需管理员批准后才建号（推荐）</a-option>
            </a-select>
          </div>
          <div v-if="admit.admitPolicy !== 'approval'" class="bd-srcform__warn">
            当前为自动建号：该目录里**任何**能通过认证的条目（服务账号、承包商、刚建的号）
            首登即获得白帝账号与门户会话，无审批。若已把资源授权给上级组织，他们即刻拥有该资源的访问权。
          </div>
          <div class="bd-srcform__row"><label>允许邮箱域</label>
            <a-input-tag v-model="admitDomains" placeholder="corp.example（回车添加；留空=不限）" allow-clear />
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
            <label>{{ srcForm.kind === 'oidc' ? 'Client Secret' : 'Bind 口令' }}</label>
            <a-input-password v-model="srcSecret" allow-clear
              :placeholder="srcForm.hasSecret ? '已配置（指纹 ' + (srcForm.secretFingerprint || '••••') + '）；留空则不改' : '未配置'" />
            <!-- ★只写不读：没有任何端点能把它读回去。回显原文没有操作价值（配错了重设即可），
                 只有泄露面。空口令在 LDAP 上会退化成匿名 bind 并"看起来成功"，后端会拒。 -->
            <div class="bd-srcform__hint">加密落库，永不回显。留空表示保持原有凭据不变</div>
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
  api, type AuthSrcBundle, type AuthSource, type AdaptiveRule, type RuleCond,
  type AuthPolicy, type AuthPolicyResp, type AuthRuleCapability, type AuthMethodCapability, type AuthDirectory, type EnhanceRule,
  type PrimaryMethod, type SecondaryMethod, type SubjectOption,
  type AuthSourceRec, type AuthSourcesResp, type ProbeResp, type SaveSourceResp,
  type LdapConfig, type OidcConfig, type AdmitConfig, type ExtAdmission
} from '@/lib/api';

/** 目录/源类型的图标与配色键。★页面本地定义，刻意不再从 API 类型推导：
 *  这套映射要覆盖「认证策略」里存量策略引用的历史目录名（radius/oauth/sms/cert），
 *  而那几类后端从未实现、也不会出现在真实的认证源列表里。 */
type SrcType = 'local' | 'ad' | 'ldap' | 'radius' | 'oauth' | 'sms' | 'cert';
type CondField = RuleCond['field'];
type Action = AdaptiveRule['action'];

const tab = ref<'source' | 'policy' | 'rule'>('source');
const live = ref(false);

/* ★这里曾经有一份 MOCK_SOURCES：7 条编造的认证源（「总部 AD 域 1846 用户」
 * 「OpenLDAP 目录 524 用户」…），与后端那份同样编造的种子互相印证，看起来毫无破绽。
 * 已整体删除——认证源列表现在只来自 GET /api/v1/authsrc/sources 与 /authsrc 聚合，
 * 两者读的都是 auth_sources 真实行。拉不到就是空列表，不回落演示数据。
 *
 * 下面的 MOCK_RULES 保留，但它服务的是「自适应认证规则」页签那个**明确标注为
 * 交互沙盘**的编排器（改动不落库、不参与登录判定，页面上有醒目提示）。
 * 真正在登录链路生效的自适应认证是「认证策略」页签（authpolicy 实时求值）。 */
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

/* ══════════ 认证源：真落库的那一套 ══════════
 *
 * 上面的 MOCK_SOURCES 只保留给「自适应规则」两个 tab 的降级演示用。
 * 认证源 tab 已经完全走真实端点——它此前是一整页内存种子，
 * 连「AD 域 1160 用户」这个数字都是凭空写的，「同步」按钮背后什么都没有。
 */
const recs = ref<AuthSourceRec[]>([]);
const supported = ref<string[]>(['local', 'ldap', 'ad', 'oidc']);
const probes = ref<Record<string, ProbeResp>>({});
const probing = ref('');

const KIND_OPTS: { v: string; label: string }[] = [
  { v: 'ldap', label: '通用 LDAP' },
  { v: 'ad', label: 'Active Directory' },
  { v: 'oidc', label: 'OpenID Connect' },
  // 这三类后端未实现，靠 supported 置灰而不是从列表里删掉——
  // 删掉会让人以为"白帝不支持这些"，置灰+注明才说清是"本版本没做"。
  { v: 'radius', label: 'RADIUS' },
  { v: 'sms', label: '短信网关' },
  { v: 'cert', label: '商密证书（SM2）' }
];

const KIND_LABEL: Record<string, string> = {
  local: '本地目录', ldap: '通用 LDAP', ad: 'Active Directory', oidc: 'OpenID Connect',
  radius: 'RADIUS', sms: '短信网关', cert: '商密证书'
};
const KIND_COLOR: Record<string, string> = {
  local: '#165DFF', ldap: '#722ED1', ad: '#165DFF', oidc: '#00B42A'
};
const KIND_ICON: Record<string, string> = {
  local: 'icon-user', ldap: 'icon-mind-mapping', ad: 'icon-storage', oidc: 'icon-link'
};
function kindLabel(k: string) { return KIND_LABEL[k] ?? k; }
function kindColor(k: string) { return KIND_COLOR[k] ?? '#86909C'; }
function kindIcon(k: string) { return KIND_ICON[k] ?? 'icon-question-circle'; }
function kindIconStyle(k: string) {
  const c = kindColor(k);
  return { color: c, background: c + '1A' };
}
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
const oidc = reactive<OidcConfig>({ issuer: '', clientId: '', redirectUri: '' });
/* 准入设置（两类源共用）。默认 auto = 与改造前行为一致，升级不把人挡在门外。 */
const admit = reactive<AdmitConfig>({ admitPolicy: 'auto' });
const admitDomains = ref<string[]>([]);
const admitGroups = ref<string[]>([]);

function resetSrcForm() {
  Object.assign(srcForm, { id: '', name: '', kind: 'ldap', enabled: true, priority: 10, hasSecret: false, secretFingerprint: undefined });
  Object.assign(ldap, { host: '', port: 0, tlsMode: 'ldaps', caCert: '', insecureSkipVerify: false, bindDn: '', baseDn: '', userFilter: '', usernameAttr: '' });
  Object.assign(oidc, { issuer: '', clientId: '', redirectUri: '', scopes: undefined });
  Object.assign(admit, { admitPolicy: 'auto' });
  admitDomains.value = [];
  admitGroups.value = [];
  srcSecret.value = '';
}

function openSrcCreate() { resetSrcForm(); srcDrawer.value = true; }

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
    else Object.assign(ldap, cfg);
    // 准入设置回填。★缺省 'auto' 而不是留空：存量配置没有这一项，
    // 留空会让下拉显示为未选中，管理员随手一保存就把它写成空串——
    // 后端归一回 auto 是对的，但页面上那一刻显示的是"没配"，与实际不符。
    admit.admitPolicy = cfg.admitPolicy === 'approval' ? 'approval' : 'auto';
    admitDomains.value = Array.isArray(cfg.allowedDomains) ? cfg.allowedDomains : [];
    admitGroups.value = Array.isArray(cfg.allowedGroups) ? cfg.allowedGroups : [];
  } catch {
    Message.warning('该认证源的配置不是合法 JSON，已按空白载入——保存会覆盖原配置');
  }
  srcDrawer.value = true;
}

/* 待批外部身份准入。★空列表就整块不画——常态零噪声；
   拿不到（旧后端 / 无权限）也是空，与"确实没有待批"同形，这里可接受：
   两者对管理员的下一步动作相同（没有要批的东西）。 */
const admissions = ref<ExtAdmission[]>([]);
const admitBusy = ref('');

async function loadAdmissions() {
  try {
    const r = await api<{ admissions: ExtAdmission[] }>('/authsrc/admissions');
    admissions.value = r.admissions ?? [];
  } catch {
    admissions.value = [];
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
    Message.error(`${zh}失败：${String((e as Error)?.message ?? e)}`);
  } finally {
    admitBusy.value = '';
  }
}

async function loadSources() {
  try {
    const r = await api<AuthSourcesResp>('/authsrc/sources');
    recs.value = r.sources ?? [];
    if (r.supportedKinds?.length) supported.value = r.supportedKinds;
  } catch {
    // 认证源是真数据，拿不到就明确留空并提示，**不降级到假数据**——
    // 这一页的历史问题恰恰就是"看起来有数据其实是编的"。
    recs.value = [];
  }
}

async function saveSource() {
  if (!srcForm.name.trim()) { Message.warning('请填写名称'); return; }
  if (!supported.value.includes(srcForm.kind)) {
    Message.error(`${kindLabel(srcForm.kind)} 本版本未实现，无法保存`);
    return;
  }
  srcSaving.value = true;
  try {
    // 准入设置并进 config：后端两类源共用同一组键（admitPolicy/allowedDomains/allowedGroups）。
    const config = {
      ...(srcForm.kind === 'oidc' ? { ...oidc } : { ...ldap }),
      ...(srcForm.kind === 'local' ? {} : {
        admitPolicy: admit.admitPolicy ?? 'auto',
        allowedDomains: admitDomains.value,
        allowedGroups: admitGroups.value
      })
    };
    const resp = await api<SaveSourceResp>('/authsrc/sources', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: srcForm.id, name: srcForm.name, kind: srcForm.kind,
        enabled: srcForm.enabled, priority: srcForm.priority, config
      })
    });
    // 凭据单独一个端点（只写不读）；留空表示不改，不能拿空串去覆盖。
    if (srcSecret.value.trim()) {
      const sr = await api<{ ok: boolean; fingerprint: string }>(
        `/authsrc/sources/${encodeURIComponent(resp.source.id)}/secret`,
        { method: 'PUT', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ secret: srcSecret.value }) });
      Message.success(`凭据已更新（指纹 ${sr.fingerprint}）`);
    }
    // 后端「保存即校验」：配置写错了当场就说，而不是等到有人登录不上才发现。
    if (resp.warning) Message.warning(resp.warning);
    else Message.success('认证源已保存');
    srcDrawer.value = false;
    await loadSources();
    await loadAdmissions();
  } catch (e) {
    Message.error(`保存失败：${String((e as Error)?.message ?? e)}`);
  } finally {
    srcSaving.value = false;
  }
}

/** 真实连通性探测。此前这个按钮是纯装饰。 */
async function probe(r: AuthSourceRec) {
  probing.value = r.id;
  try {
    probes.value = {
      ...probes.value,
      [r.id]: await api<ProbeResp>(`/authsrc/sources/${encodeURIComponent(r.id)}/probe`, { method: 'POST' })
    };
  } catch (e) {
    probes.value = { ...probes.value, [r.id]: { ok: false, detail: String((e as Error)?.message ?? e) } };
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
        Message.error(`删除失败：${String((e as Error)?.message ?? e)}`);
      }
    }
  });
}

/** 源 id → 归属该源的账号数（外部源 = 已绑定条数；本地目录 = 无外部绑定的账号数）。
 *  ★这不是"目录纳管用户数"：后者要遍历整个 LDAP 才数得出来，白帝没有那个能力，
 *  原实现里的 1160 就是凭空写的。拿不到聚合时返回 undefined，卡片显示 — 而不是 0。 */
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
const TYPE_COLOR: Record<SrcType, string> = {
  local: '#165DFF', ad: '#165DFF', ldap: '#722ED1', radius: '#FF7D00', oauth: '#00B42A', sms: '#FF7D00', cert: '#722ED1'
};
const TYPE_ICON: Record<SrcType, string> = {
  local: 'icon-user', ad: 'icon-storage', ldap: 'icon-mind-mapping', radius: 'icon-wifi',
  oauth: 'icon-link', sms: 'icon-message', cert: 'icon-lock'
};
function srcIcon(t: SrcType) { return TYPE_ICON[t]; }
function srcIconStyle(t: SrcType) {
  const c = TYPE_COLOR[t];
  return { color: c, background: c + '14' };
}
// ★statusColor/statusLabel（在线/告警/离线）随 AuthSource.status 一起删除：
// 那个状态恒为 online，是在替一台可能早已宕掉的目录打包票。认证源可达性只有
// 「测试连接」（probe）那一刻才知道，结果就地渲染在卡片上。
function tagStyle(color: string) { return { color, background: color + '14' }; }

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
function addSource() { Message.info('接入认证源向导（演示）'); }

/* ── 认证策略（FR-AUTH-12）── */
const policies = ref<AuthPolicy[]>([]);

const PRIMARY_OPTS: { value: PrimaryMethod; label: string }[] = [
  { value: 'local', label: '本地账号密码' },
  { value: 'ad', label: 'AD 域' },
  { value: 'ldap', label: 'LDAP 目录' },
  { value: 'radius', label: 'RADIUS 账号' },
  { value: 'oauth', label: '企微/钉钉/飞书' },
  { value: 'sms', label: '短信验证码' },
  { value: 'cert', label: '证书 / USB-Key' }
];
const SECONDARY_OPTS: { value: SecondaryMethod; label: string }[] = [
  { value: 'sms', label: '短信' },
  { value: 'totp', label: 'TOTP 令牌' },
  { value: 'radius', label: 'Radius 动态令牌' },
  { value: 'cert', label: '证书 / USB-Key' },
  { value: 'http', label: 'HTTP(S) 令牌' }
];
const PRIMARY_LABEL: Record<string, string> = Object.fromEntries(PRIMARY_OPTS.map((o) => [o.value, o.label]));
const SECONDARY_LABEL: Record<string, string> = Object.fromEntries(SECONDARY_OPTS.map((o) => [o.value, o.label]));
const PRIMARY_COLOR: Record<string, string> = {
  local: '#165DFF', ad: '#165DFF', ldap: '#722ED1', radius: '#FF7D00', oauth: '#00B42A', sms: '#FF7D00', cert: '#722ED1'
};
function primaryLabel(m: string) { return PRIMARY_LABEL[m] ?? m ?? '—'; }
function primaryColor(m: string) { return PRIMARY_COLOR[m] ?? '#86909C'; }
function secondaryLabel(m: string) { return SECONDARY_LABEL[m] ?? m; }

/* 可作为「用户目录」被策略绑定的取值：**由后端下发**（GET /authpolicy 的 directories）。
 *
 * ★这里此前接的是 GET /authsrc 的演示种子（恒定只有 local 与 ad），而登录链路把
 * directory 置成真实认证源的 kind（local|ldap|ad|oidc）。于是管理员真配一个
 * LDAP/OIDC 源之后，那批人登录时 Match 按目录先筛一刀就把全部策略筛掉（连默认策略
 * 都没有）→ 永不二次认证；而策略页上根本选不出 "ldap"，管理员无从修。
 * 与 capabilities 同一条纪律：前端能选的，后端就得能存。 */
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
const grouped = computed(() => {
  const map = new Map<string, AuthPolicy[]>();
  for (const p of policies.value) {
    if (!map.has(p.directory)) map.set(p.directory, []);
    map.get(p.directory)!.push(p);
  }
  return [...map.entries()].map(([dir, list]) => ({
    dir, name: dirName(dir),
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
    pc: { primary: 'ad', secondary: [] }, mobile: { primary: 'ad', secondary: [] },
    scopeOrgs: [], scopeGroups: [],
    exempt: { trustedDevice: false, trustedNetwork: false, networks: [], winDomain: false },
    enhance: {
      always: false, weakPwd: false, offHours: false,
      workStart: '09:00', workEnd: '18:00', workDays: [1, 2, 3, 4, 5], geoAnomaly: false
    },
    authzApps: ''
  };
}
/** 老库读回来的策略可能缺新字段（后端已回填，这里是渲染侧兜底）：补齐再进表单，避免 v-model 挂在 undefined 上。 */
function normalizePolicy(p: AuthPolicy): AuthPolicy {
  const b = blankPolicy();
  return {
    ...p,
    scopeOrgs: p.scopeOrgs ?? [], scopeGroups: p.scopeGroups ?? [],
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
async function savePolicy(): Promise<boolean> {
  const p = editing.value;
  if (!p.name.trim()) { Message.warning('请填写策略名称'); return false; }
  if (!p.directory) { Message.warning('请选择所属用户目录'); return false; }
  if (!p.pc.primary || !p.mobile.primary) { Message.warning('PC 端与移动端均须配置主认证方式'); return false; }
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
    Message.error('保存失败：' + (e as Error).message);
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
        Message.error('删除失败：' + (e as Error).message);
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
  } catch { /* 后端不可用时保持空列表 */ }
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
    live.value = true;
  } catch {
    // 拿不到就清空计数：卡片上显示 —，而不是继续挂着上一次的数字或回落演示值。
    sources.value = [];
    live.value = false;
  }
  await loadPolicies();
  await loadSources();
  await loadAdmissions();
});
</script>

<style scoped>
/* 认证源（真数据那一套）*/
.bd-srchint { color: var(--bd-t3); margin-left: 10px; font-size: 12px; }
.bd-srcempty { grid-column: 1 / -1; text-align: center; color: var(--bd-t3); font-size: 13px; padding: 40px 0; }
.bd-warn { color: var(--bd-warning); }
.bd-mono { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; }
.bd-link--danger { color: var(--bd-danger); }
.bd-probe { display: flex; align-items: center; gap: 6px; font-size: 12px; padding: 7px 10px;
  border-radius: 6px; margin: 10px 0 2px; line-height: 1.5; }
.bd-probe.ok { color: var(--bd-success); background: var(--bd-tag-green-bg, #E8FFEA); }
.bd-probe.bad { color: var(--bd-danger); background: var(--bd-tag-red-bg, #FFECE8); }
.bd-probe__ms { margin-left: auto; opacity: .7; }

/* 认证源抽屉表单 */
.bd-srcform { display: flex; flex-direction: column; gap: 14px; }
.bd-srcform__row { display: flex; flex-direction: column; gap: 6px; }
.bd-srcform__row label { font-size: 12.5px; color: var(--bd-t2); }
.bd-srcform__row--inline { flex-direction: row; align-items: center; gap: 8px; font-size: 13px; }
.bd-srcform__pri { margin-left: auto; display: inline-flex; align-items: center; gap: 6px; color: var(--bd-t2); font-size: 12.5px; }
.bd-srcform__sec { font-size: 12px; font-weight: 600; color: var(--bd-t3); letter-spacing: .5px;
  border-top: 1px solid var(--bd-border); padding-top: 12px; margin-top: 2px; }
.bd-srcform__hint { font-size: 11.5px; color: var(--bd-t3); line-height: 1.6; }
.bd-srcform__warn { font-size: 11.5px; color: var(--bd-warning); line-height: 1.6;
  background: var(--bd-tag-gold-bg, #FFF7E8); padding: 7px 9px; border-radius: 6px; }

/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }

.bd-section-title { font-size: 15px; font-weight: 600; color: var(--bd-t1); margin-bottom: 4px; }

/* ── 认证源 ── */
.bd-srctoolbar { display: flex; align-items: center; margin-bottom: 16px; }
.bd-srctoolbar__sub { font-size: 13px; color: var(--bd-t3); }
.bd-srctoolbar__sub b { color: var(--bd-t1); font-weight: 600; }
.bd-srctoolbar .bd-btn { margin-left: auto; }

.bd-srcgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(312px, 1fr)); gap: 16px; }
.bd-srccard { padding: 16px 18px; transition: border-color .15s, box-shadow .15s; }
.bd-srccard:hover { border-color: var(--bd-primary-b); box-shadow: 0 4px 14px rgba(22, 93, 255, .06); }
.bd-srccard__top { display: flex; align-items: flex-start; gap: 12px; }
.bd-srcicon { width: 40px; height: 40px; border-radius: 10px; flex: none; display: inline-flex; align-items: center; justify-content: center; font-size: 20px; }
.bd-srccard__id { flex: 1; min-width: 0; }
.bd-srccard__name { font-size: 14.5px; font-weight: 600; color: var(--bd-t1); display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.bd-primarytag { display: inline-flex; align-items: center; gap: 3px; font-size: 11px; font-weight: 500; color: var(--bd-warning); background: var(--bd-tag-gold-bg); padding: 1px 7px; border-radius: 10px; }
.bd-srccard__st { margin-left: auto; flex: none; }
.bd-srccard__foot { display: flex; align-items: center; margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--bd-fill-2); }
.bd-srccard__kv { display: flex; flex-direction: column; gap: 2px; }
.bd-srccard__kv span { font-size: 11.5px; color: var(--bd-t3); }
.bd-srccard__kv b { font-size: 18px; font-weight: 700; color: var(--bd-t1); line-height: 1; }
.bd-srccard__acts { margin-left: auto; display: flex; gap: 14px; font-size: 12.5px; }

/* ── 自适应认证规则 ── */
.bd-rulewrap { display: flex; gap: 16px; align-items: flex-start; }
.bd-rulemain { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 14px; }
.bd-rulepreview { width: 316px; flex: none; position: sticky; top: 18px; }

.bd-ruleintro { display: flex; gap: 12px; padding: 14px 16px; font-size: 13px; line-height: 1.7; color: var(--bd-t2); background: var(--bd-primary-1); border-color: var(--bd-primary-b); }
.bd-ruleintro__ic { color: var(--bd-primary); font-size: 18px; flex: none; margin-top: 2px; }
.bd-ruleintro b { color: var(--bd-t1); font-weight: 600; }

/* 规则行 */
.bd-rule { display: flex; align-items: stretch; padding: 14px 16px 14px 8px; gap: 10px; transition: opacity .15s; }
.bd-rule.off { opacity: .58; }
.bd-rule__handle { display: flex; align-items: center; color: var(--bd-t4); cursor: grab; font-size: 16px; }
.bd-rule__handle:active { cursor: grabbing; }
.bd-rule__pri { width: 22px; height: 22px; border-radius: 6px; flex: none; align-self: center; display: inline-flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; color: var(--bd-primary); background: var(--bd-primary-1); }
.bd-rule__body { flex: 1; min-width: 0; }
.bd-rule__head { display: flex; align-items: center; margin-bottom: 12px; }
.bd-rule__name { font-size: 13.5px; font-weight: 600; color: var(--bd-t1); }
.bd-rule__sw { margin-left: auto; }

.bd-rule__flow { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.bd-clause { font-size: 11px; font-weight: 700; letter-spacing: .5px; color: var(--bd-t3); font-family: ui-monospace, monospace; }

.bd-if { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; flex: 1; min-width: 0; }
.bd-chip { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--bd-t1); background: #fff; border: 1px solid var(--bd-border); border-radius: 14px; padding: 4px 10px; font-weight: 500; }
.bd-chip__x { font-size: 11px; color: var(--bd-t4); cursor: pointer; }
.bd-chip__x:hover { color: var(--bd-danger); }
.bd-logic { font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 12px; cursor: pointer; user-select: none; transition: background .12s; }
.bd-logic.and { color: var(--bd-primary); background: var(--bd-primary-1); }
.bd-logic.or { color: var(--bd-purple); background: var(--bd-tag-purple-bg); }
.bd-logic:hover { filter: brightness(.96); }
.bd-addcond { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; color: var(--bd-primary); background: transparent; border: 1px dashed var(--bd-primary-b); border-radius: 14px; padding: 3px 10px; cursor: pointer; }
.bd-addcond:hover { background: var(--bd-primary-1); }

.bd-flow__arrow { color: var(--bd-t4); font-size: 16px; flex: none; }

.bd-then { display: flex; align-items: center; gap: 8px; flex: none; }
/* 动作下拉：用自管 wrapper 着色，避开 Arco view 内部样式优先级 */
.bd-actionwrap { display: inline-flex; align-items: center; gap: 7px; height: 30px; padding: 0 8px 0 11px; border: 1px solid var(--bd-border); border-radius: 7px; --bd-act: var(--bd-t2); }
.bd-actionwrap.block { --bd-act: var(--bd-danger); border-color: var(--bd-danger); background: var(--bd-tag-red-bg); }
.bd-actionwrap.warn { --bd-act: var(--bd-warning); border-color: var(--bd-warning); background: var(--bd-tag-gold-bg); }
.bd-actionwrap.allow { --bd-act: var(--bd-success); border-color: var(--bd-success); background: var(--bd-tag-green-bg); }
.bd-actiondot { width: 7px; height: 7px; border-radius: 50%; flex: none; background: var(--bd-act); }
.bd-actionsel { width: 142px; }
/* 经带 scope 的 wrapper 用 :deep 穿透到 Arco view（select 根无 scope 属性） */
.bd-actionwrap :deep(.arco-select-view) { background: transparent !important; border: none !important; box-shadow: none !important; padding: 0; color: var(--bd-act) !important; }
.bd-actionwrap :deep(.arco-select-view-value) { color: var(--bd-act); font-weight: 600; }
.bd-actionwrap :deep(.arco-select-view-icon) { color: var(--bd-act); }

.bd-addrule { align-self: flex-start; border-style: dashed; }

/* ── 求值预览 ── */
.bd-preview { padding: 16px 18px 18px; }
.bd-preview__sub { font-size: 12px; color: var(--bd-t3); margin-bottom: 14px; }
.bd-ctxlist { display: flex; flex-direction: column; gap: 2px; margin-bottom: 16px; }
.bd-ctxrow { display: flex; align-items: center; gap: 9px; padding: 8px 8px; border-radius: 7px; cursor: pointer; transition: background .12s; }
.bd-ctxrow:hover { background: var(--bd-fill-1); }
.bd-ctxrow__t { font-size: 13px; font-weight: 500; color: var(--bd-t1); }
.bd-ctxrow__d { margin-left: auto; font-size: 11px; color: var(--bd-t3); text-align: right; }

.bd-evalout { border-radius: var(--bd-radius); padding: 16px; text-align: center; border: 1px solid var(--bd-border); background: var(--bd-fill-1); }
.bd-evalout__l { font-size: 11px; color: var(--bd-t3); }
.bd-evalout__rule { font-size: 13.5px; font-weight: 600; color: var(--bd-t1); margin-top: 4px; }
.bd-evalout__rule.muted { color: var(--bd-t3); font-weight: 500; }
.bd-evalout__arrow { color: var(--bd-t4); font-size: 14px; margin: 6px 0; }
.bd-evalout__act { font-size: 20px; font-weight: 700; margin-top: 4px; }
.bd-evalout__act.muted { color: var(--bd-t3); font-weight: 600; }
/* 按动作着色边框 + 文字 */
.bd-evalout.block { border-color: var(--bd-danger); background: var(--bd-tag-red-bg); }
.bd-evalout.block .bd-evalout__act { color: var(--bd-danger); }
.bd-evalout.warn { border-color: var(--bd-warning); background: var(--bd-tag-gold-bg); }
.bd-evalout.warn .bd-evalout__act { color: var(--bd-warning); }
.bd-evalout.allow { border-color: var(--bd-success); background: var(--bd-tag-green-bg); }
.bd-evalout.allow .bd-evalout__act { color: var(--bd-success); }

/* ── 认证策略 ── */
.bd-pgroup { margin-bottom: 22px; }
.bd-pgroup__head { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
.bd-pgroup__ic { width: 30px; height: 30px; border-radius: 8px; font-size: 16px; }
.bd-pgroup__name { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.bd-pgroup__cnt { font-size: 12px; color: var(--bd-t3); background: var(--bd-fill-2); padding: 2px 9px; border-radius: 10px; }

.bd-pcard { padding: 16px 18px; margin-bottom: 12px; transition: opacity .15s, box-shadow .15s; }
.bd-pcard:hover { box-shadow: 0 4px 14px rgba(22, 93, 255, .06); }
.bd-pcard.off { opacity: .62; }
.bd-pcard__head { display: flex; align-items: flex-start; gap: 12px; }
.bd-pcard__title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; flex: 1; min-width: 0; }
.bd-pcard__name { font-size: 14.5px; font-weight: 600; color: var(--bd-t1); }
.bd-tg--default { color: var(--bd-primary); background: var(--bd-primary-1); font-weight: 600; }
.bd-tg--pri { color: var(--bd-t3); background: var(--bd-fill-2); }
.bd-tg--off { color: var(--bd-t3); background: var(--bd-fill-2); }
.bd-tg--sec { color: var(--bd-purple); background: var(--bd-tag-purple-bg); }
.bd-pcard__acts { display: flex; gap: 14px; flex: none; }
.bd-pcard__acts .bd-link { display: inline-flex; align-items: center; gap: 4px; font-size: 12.5px; }
.bd-link--danger { color: var(--bd-danger); }
.bd-link--disabled { color: var(--bd-t4); cursor: default; }
.bd-pcard__scope { font-size: 12.5px; color: var(--bd-t3); margin: 4px 0 14px; }

.bd-platgrid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.bd-plat { border: 1px solid var(--bd-fill-2); border-radius: 9px; padding: 12px 14px; background: var(--bd-fill-1); }
.bd-plat__h { display: flex; align-items: center; gap: 6px; font-size: 12.5px; font-weight: 600; color: var(--bd-t2); margin-bottom: 10px; }
.bd-plat__row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 7px; }
.bd-plat__k { font-size: 12px; color: var(--bd-t3); width: 56px; flex: none; }
.bd-plat__none { font-size: 12px; color: var(--bd-t4); }

.bd-pcard__foot { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--bd-fill-2); }
.bd-foot__k { font-size: 12px; color: var(--bd-t3); }
.bd-foot__authz { margin-left: auto; display: inline-flex; align-items: center; gap: 5px; font-size: 12px; color: var(--bd-t2); }
.bd-mtg { display: inline-flex; align-items: center; gap: 4px; font-size: 11.5px; font-weight: 500; padding: 2px 9px; border-radius: 11px; }
.bd-mtg--ok { color: var(--bd-success); background: var(--bd-tag-green-bg); }
.bd-mtg--warn { color: var(--bd-warning); background: var(--bd-tag-gold-bg); }

/* ── 编辑抽屉表单 ── */
.bd-form { display: flex; flex-direction: column; gap: 16px; }
.bd-form__row { display: flex; flex-direction: column; gap: 6px; }
.bd-form__lab { font-size: 12.5px; color: var(--bd-t2); font-weight: 500; }
.bd-form__lab em { color: var(--bd-danger); font-style: normal; }
.bd-form__2col { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.bd-form__platgrid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.bd-form__plat { border: 1px solid var(--bd-border); border-radius: 9px; padding: 14px; display: flex; flex-direction: column; gap: 6px; }
.bd-form__plath { display: flex; align-items: center; gap: 6px; font-size: 13px; font-weight: 600; color: var(--bd-t1); margin-bottom: 6px; padding-bottom: 8px; border-bottom: 1px solid var(--bd-fill-2); }
.bd-form__sec { border: 1px solid var(--bd-fill-2); border-radius: 9px; padding: 12px 14px; background: var(--bd-fill-1); }
.bd-form__sech { font-size: 12.5px; font-weight: 600; color: var(--bd-t2); margin-bottom: 10px; }
.bd-form__checks { display: flex; flex-wrap: wrap; gap: 10px 18px; }

/* ── 规则能力说明 / 规则行（每条开关下面就写清判据，不必点进文档）── */
.bd-capbox { padding: 12px 16px; margin-bottom: 14px; }
.bd-capbox__h { display: flex; align-items: center; gap: 6px; font-size: 12.5px; font-weight: 600; color: var(--bd-t2); margin-bottom: 8px; }
.bd-caprow { display: flex; align-items: baseline; gap: 8px; padding: 5px 0; border-top: 1px solid var(--bd-fill-2); font-size: 12px; color: var(--bd-t3); }
.bd-caprow:first-of-type { border-top: none; }
.bd-caprow.off { opacity: .72; }
.bd-caprow__n { color: var(--bd-t1); font-weight: 600; flex: none; }
.bd-caprow__d { color: var(--bd-t3); line-height: 1.6; }
.bd-tg--warnbox { color: var(--bd-warning); background: var(--bd-tag-gold-bg); }
.bd-sub { font-style: normal; margin-left: 4px; opacity: .75; }

.bd-ruleintro__warn { display: flex; align-items: baseline; gap: 6px; margin-top: 8px; padding-top: 8px; border-top: 1px dashed var(--bd-border); color: var(--bd-warning); font-size: 12px; line-height: 1.6; }
.bd-ruleintro__warn .bd-link { color: var(--bd-primary); }

.bd-form__rules { display: flex; flex-direction: column; gap: 12px; }
.bd-rulerow { display: flex; flex-direction: column; gap: 4px; }
.bd-rulerow.off { opacity: .7; }
.bd-rulerow__d { font-size: 11.5px; color: var(--bd-t3); line-height: 1.6; padding-left: 24px; }
.bd-rulerow__cfg { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding-left: 24px; margin-top: 4px; }
.bd-form__hint { font-size: 11.5px; color: var(--bd-t3); line-height: 1.6; }
.bd-form__hint.bad { color: var(--bd-warning); }

/* 待批外部身份准入 */
.bd-admit { margin-top: 18px; }
.bd-admit__count { margin-left: 10px; font-size: 12px; font-weight: 400; color: var(--bd-t3); }
.bd-admit__hint { font-size: 12.5px; color: var(--bd-t3); line-height: 1.6; margin: 6px 0 10px; }
.bd-admit__row { display: flex; align-items: center; gap: 14px; padding: 12px 14px; margin-bottom: 8px; }
.bd-admit__who { display: flex; align-items: center; gap: 8px; font-size: 13.5px; min-width: 260px; }
.bd-admit__acct { color: var(--bd-t3); font-size: 12px; }
.bd-admit__meta { display: flex; flex-wrap: wrap; gap: 12px; font-size: 12px; color: var(--bd-t3); flex: 1; }
.bd-admit__sub { max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bd-admit__act { display: flex; gap: 8px; flex: none; }
</style>
