<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">用户与角色 · 访问者目录</div>
        <div class="bd-page__sub">多身份源统一纳管 · 组织树与用户组维护 · 实时在线态与账号生命周期就地处置</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        <button class="bd-btn bd-btn--ghost" @click="openIdle"><icon-clock-circle />闲置治理</button>
        <button class="bd-btn bd-btn--ghost" :disabled="exporting" @click="exportUsers">
          <icon-download />{{ exporting ? '导出中…' : '导出台账' }}
        </button>
        <button class="bd-btn bd-btn--ghost" @click="openImport"><icon-upload />批量导入</button>
        <button class="bd-btn" @click="openCreateUser"><icon-plus />新增用户</button>
      </div>
    </div>

    <!-- 身份源 tabs -->
    <div class="bd-tabs">
      <span v-for="d in directories" :key="d.key" class="bd-tab" :class="{ on: dir === d.key }" @click="dir = d.key">
        <icon-storage v-if="d.type === 'local'" /><icon-cloud v-else />
        {{ d.name }} <em>{{ d.users }}</em>
      </span>
    </div>

    <!-- 外部目录说明卡。★白帝不做目录周期同步，这里不许出现同步时间/进度/日志一类的字样：
         外部账号是首次登录时按 subject 绑定建号的。 -->
    <div v-if="curDir && curDir.type !== 'local'" class="bd-sync">
      <icon-info-circle class="bd-sync__ic" />
      <span>
        <b>{{ curDir.name }}</b> 已绑定 {{ curDir.users }} 个账号 ——
        白帝不做目录周期同步，外部账号在**首次登录**时按目录返回的 subject 绑定建号
      </span>
      <div style="flex: 1" />
      <router-link class="bd-link" to="/business/auth">认证源配置</router-link>
    </div>

    <!-- 聚合计数 -->
    <div class="bd-agg">
      <div v-for="s in agg" :key="s.label" class="bd-agg__c">
        <span class="bd-agg__dot" :style="{ background: s.color }" /><b>{{ s.n }}</b>{{ s.label }}
      </div>
    </div>

    <div class="bd-two">
      <!-- 左栏：组织架构 / 用户组 -->
      <div class="bd-card bd-otree">
        <div class="bd-seg">
          <button class="bd-seg__b" :class="{ on: mode === 'org' }" :aria-pressed="mode === 'org'"
            @click="mode = 'org'">组织架构</button>
          <button class="bd-seg__b" :class="{ on: mode === 'group' }" :aria-pressed="mode === 'group'"
            @click="mode = 'group'">用户组</button>
        </div>

        <!-- 常驻操作条：作用于当前选中的节点。★它是增删改的主暴露面，行内按钮只是熟手快捷方式——
             把入口收回 hover 上，触屏与键盘用户就完全够不着这三个操作。 -->
        <div class="bd-otree__bar">
          <span class="bd-otree__cur" :title="scopeTitle">{{ scopeTitle }}</span>
          <template v-if="mode === 'org'">
            <button type="button" class="bd-iconbtn" :disabled="!curOrgNode"
              :title="orgActHint('新建子部门')" :aria-label="orgActHint('新建子部门')"
              @click="newSubOrg"><icon-plus /></button>
            <button type="button" class="bd-iconbtn" :disabled="!curOrgNode"
              :title="orgActHint('重命名 / 改上级')" :aria-label="orgActHint('重命名 / 改上级')"
              @click="editCurOrg"><icon-edit /></button>
            <button type="button" class="bd-iconbtn bd-iconbtn--danger" :disabled="!curOrgNode"
              :title="orgActHint('删除')" :aria-label="orgActHint('删除')"
              @click="removeCurOrg"><icon-delete /></button>
          </template>
          <template v-else>
            <button type="button" class="bd-iconbtn" :disabled="curGroup?.kind !== 'static'"
              :title="memberActHint" :aria-label="memberActHint"
              @click="editCurMembers"><icon-user-add /></button>
            <button type="button" class="bd-iconbtn" :disabled="!curGroup"
              :title="groupActHint('编辑用户组')" :aria-label="groupActHint('编辑用户组')"
              @click="editCurGroup"><icon-edit /></button>
            <button type="button" class="bd-iconbtn bd-iconbtn--danger" :disabled="!curGroup"
              :title="groupActHint('删除')" :aria-label="groupActHint('删除')"
              @click="removeCurGroup"><icon-delete /></button>
          </template>
        </div>

        <!-- 组织树 -->
        <template v-if="mode === 'org'">
          <div v-if="!curOrgNode" class="bd-otree__tip">选中下方任一部门，上方按钮即作用于它。</div>
          <button class="bd-onode" :class="{ on: org === '' }" :aria-pressed="org === ''" @click="org = ''">
            <icon-apps class="bd-onode__ic" /><span class="bd-onode__t">全部用户</span>
            <span class="bd-onode__n">{{ users.length }}</span>
          </button>
          <div v-for="n in flatOrg" :key="n.key" class="bd-onode-row" :class="{ sel: org === n.key }">
            <button class="bd-onode" :class="{ on: org === n.key }" :aria-pressed="org === n.key"
              :style="{ paddingLeft: 10 + n.depth * 14 + 'px' }" @click="org = n.key">
              <icon-folder v-if="n.children && n.children.length" class="bd-onode__ic" />
              <icon-user-group v-else class="bd-onode__ic" />
              <span class="bd-onode__t">{{ n.title }}</span>
              <span class="bd-onode__n">{{ n.members }}</span>
            </button>
            <span class="bd-onode__acts">
              <button type="button" class="bd-onode__act" :title="`在「${n.title}」下新建子部门`"
                :aria-label="`在「${n.title}」下新建子部门`" @click.stop="openOrg(null, n.key)"><icon-plus /></button>
              <button type="button" class="bd-onode__act" :title="`重命名「${n.title}」/ 改上级`"
                :aria-label="`重命名「${n.title}」或修改上级`" @click.stop="openOrg(n.key)"><icon-edit /></button>
              <button type="button" class="bd-onode__act bd-onode__act--danger" :title="`删除「${n.title}」`"
                :aria-label="`删除组织「${n.title}」`" @click.stop="askRemoveOrg(n.key, n.title)"><icon-delete /></button>
            </span>
          </div>
          <button class="bd-onode bd-onode--add" @click="openOrg(null, '')"><icon-plus />新建顶级组织</button>
          <div v-if="!flatOrg.length" class="bd-otree__empty">尚无组织，先建一个。</div>
        </template>

        <!-- 用户组 -->
        <template v-else>
          <div v-if="!curGroup" class="bd-otree__tip">选中下方任一用户组，上方按钮即作用于它。</div>
          <button class="bd-onode" :class="{ on: groupSel === '' }" :aria-pressed="groupSel === ''"
            @click="groupSel = ''">
            <icon-apps class="bd-onode__ic" /><span class="bd-onode__t">全部用户</span>
            <span class="bd-onode__n">{{ users.length }}</span>
          </button>
          <div v-for="g in groups" :key="g.id" class="bd-onode-row" :class="{ sel: groupSel === g.id }">
            <button class="bd-onode" :class="{ on: groupSel === g.id }" :aria-pressed="groupSel === g.id"
              @click="groupSel = g.id">
              <icon-user-group class="bd-onode__ic" />
              <span class="bd-onode__t">{{ g.name }}<em v-if="g.kind === 'role'" class="bd-kindtag">角色派生</em><em v-else-if="g.kind === 'external'" class="bd-kindtag bd-kindtag--ext">外部目录</em></span>
              <span class="bd-onode__n">{{ g.members }}</span>
            </button>
            <span class="bd-onode__acts">
              <button v-if="g.kind === 'static'" type="button" class="bd-onode__act" :title="`编辑「${g.name}」的成员`"
                :aria-label="`编辑用户组「${g.name}」的成员`" @click.stop="openMembers(g)"><icon-user-add /></button>
              <button type="button" class="bd-onode__act" :title="`编辑用户组「${g.name}」`"
                :aria-label="`编辑用户组「${g.name}」`" @click.stop="openGroup(g)"><icon-edit /></button>
              <button type="button" class="bd-onode__act bd-onode__act--danger" :title="`删除「${g.name}」`"
                :aria-label="`删除用户组「${g.name}」`" @click.stop="askRemoveGroup(g)"><icon-delete /></button>
            </span>
          </div>
          <button class="bd-onode bd-onode--add" @click="openGroup(null)"><icon-plus />新建用户组</button>
          <div v-if="!groups.length" class="bd-otree__empty">尚无用户组。角色组的成员由用户的展示角色派生，不用手工维护。</div>
        </template>
      </div>

      <!-- 用户表 -->
      <div class="bd-tablecard" style="flex: 1; min-width: 0">
        <div class="bd-toolbar">
          <span class="bd-toolbar__c">{{ scopeTitle }} · {{ shown.length }} 人</span>
          <div style="flex: 1" />
          <div class="bd-searchbox" style="width: 240px">
            <icon-search />
            <input v-model="kw" class="bd-searchbox__in" placeholder="按用户名 / 账号 / IP 搜索" />
          </div>
        </div>
        <table class="bd-table">
          <thead>
            <tr><th>用户</th><th>所属组织</th><th>用户组</th><th>终端 / 接入</th><th>状态</th><th class="r">操作</th></tr>
          </thead>
          <tbody>
            <tr v-for="u in shown" :key="u.id" :class="{ sel: sel?.id === u.id }">
              <td>
                <div class="bd-cellname" @click="open(u)">
                  <span class="bd-avatar" :style="{ background: avBg(u) }">{{ u.name.slice(0, 1) }}</span>
                  <span><b>{{ u.name }}<span v-if="u.risk === 'high'" class="bd-rk">高危</span></b><i class="bd-mono">{{ u.account }}</i></span>
                </div>
              </td>
              <td>{{ u.org || '—' }}</td>
              <td>
                <span v-if="!u.groups.length" class="bd-t4">—</span>
                <span v-for="gid in u.groups" :key="gid" class="bd-tg bd-tg--sm" :style="tagStyle('#722ED1')">{{ groupName(gid) }}</span>
              </td>
              <td>
                <span class="bd-st"><span class="d" :style="{ background: u.online ? 'var(--bd-success)' : 'var(--bd-t4)' }" />{{ u.online ? '在线' : '离线' }}</span>
                <span class="bd-umono">{{ u.device }} · {{ u.ip }}</span>
              </td>
              <td><span class="bd-tg" :style="tagStyle(statusMeta(u.status).color)">{{ statusMeta(u.status).label }}</span></td>
              <td class="r"><span class="bd-link" @click="open(u)">详情</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 用户详情抽屉（P5 池化：列表 → 详情） -->
    <a-drawer v-model:visible="drawer" :width="460" :footer="false" unmount-on-close>
      <template #title>访问者详情</template>
      <div v-if="sel" class="bd-ud">
        <div class="bd-ud__head">
          <span class="bd-avatar" :style="{ background: avBg(sel), width: '46px', height: '46px', fontSize: '18px' }">{{ sel.name.slice(0, 1) }}</span>
          <div>
            <div class="bd-ud__name">{{ sel.name }}<span class="bd-st" style="margin-left: 8px"><span class="d" :style="{ background: sel.online ? 'var(--bd-success)' : 'var(--bd-t4)' }" />{{ sel.online ? '在线' : '离线' }}</span></div>
            <div class="bd-ud__acct bd-mono">{{ sel.account }} · {{ sel.org || '无组织归属' }}</div>
          </div>
        </div>

        <!-- 账号生命周期状态机 -->
        <div class="bd-ud__sec">账号生命周期</div>
        <div class="bd-life">
          <div v-for="(st, i) in LIFE" :key="st.key" class="bd-life__step" :class="{ on: st.key === sel.status }">
            <span class="bd-life__dot" />{{ st.label }}<icon-right v-if="i < LIFE.length - 1" class="bd-life__arr" />
          </div>
        </div>

        <!-- 组织归属与用户组（落库） -->
        <div class="bd-ud__sec">组织与用户组</div>
        <div class="bd-uform__f"><label>所属组织</label>
          <a-select v-model="memberForm.orgId" allow-clear placeholder="未归属任何组织">
            <a-option v-for="o in flatOrg" :key="o.key" :value="o.key">{{ '　'.repeat(o.depth) + o.title }}</a-option>
          </a-select>
        </div>
        <div class="bd-uform__f"><label>用户组（仅显式成员组可改）</label>
          <a-select v-model="memberForm.groups" multiple placeholder="未加入任何用户组">
            <a-option v-for="g in staticGroups" :key="g.id" :value="g.id">{{ g.name }}</a-option>
          </a-select>
          <div v-if="derivedGroups.length" class="bd-uform__hint" style="margin: 8px 0 0">
            按角色派生：<span v-for="g in derivedGroups" :key="g.id" class="bd-tg bd-tg--sm" :style="tagStyle('#722ED1')">{{ g.name }}</span>
            —— 由用户展示角色决定，改下面的「展示角色」才会变。
          </div>
        </div>
        <!-- ★展示角色是「按角色派生」用户组**唯一**的成员写入路径，别把这一项去掉：
             那类组一旦恒为 0 人，用它授权的资源会因空展开下发 DenyAllSubject 而对所有人拒绝，
             策略/基线侧则永不命中（fail-open）。 -->
        <div class="bd-uform__f"><label>展示角色（决定「按角色派生」用户组的成员）</label>
          <a-input-tag v-model="memberForm.roles" placeholder="回车添加，如：研发 / 销售 / 组长" allow-clear />
          <div class="bd-uform__hint" style="margin: 6px 0 0">
            组名与角色名相同的派生组会自动把该用户算作成员。空白与重复项保存时自动去掉。
          </div>
        </div>
        <button class="bd-btn" :disabled="savingMember" @click="saveMembership">保存归属</button>

        <div class="bd-ud__sec">接入信息</div>
        <div class="bd-kv"><span>终端</span><b>{{ sel.device }}</b></div>
        <div class="bd-kv"><span>接入 IP</span><b class="bd-mono">{{ sel.ip }}</b></div>
        <div class="bd-kv"><span>邮箱</span><b>{{ sel.email || '—' }}</b></div>
        <div class="bd-kv"><span>认证方式</span><b>{{ sel.auth }}</b></div>
        <div class="bd-kv"><span>最后登录</span><b>{{ sel.lastLogin }}</b></div>
        <div class="bd-kv"><span>风险评估</span><b>
          <span class="bd-tg" :style="tagStyle(riskColor(sel.risk))">{{ riskLabel(sel.risk) }}</span>
          <!-- 结论必须带依据：这一格是**账号级**的（跨该账号名下全部终端取最差判定）。 -->
          <span class="bd-riskwhy">{{ sel.risk === 'unknown'
            ? '该账号从未上报过终端环境（observe 准入模式下仍可接入）'
            : '来自终端合规判定，跨该账号名下全部终端取最差档' }}</span>
        </b></div>

        <div class="bd-ud__sec">角色</div>
        <div class="bd-roles"><span v-for="r in sel.roles" :key="r" class="bd-tg" :style="tagStyle('#165DFF')">{{ r }}</span></div>

        <div class="bd-ud__acts">
          <button v-if="sel.status === 'locked'" class="bd-btn" @click="setStatus('active', '已解锁账号')"><icon-unlock />解锁账号</button>
          <button v-if="sel.status === 'disabled'" class="bd-btn" @click="setStatus('active', '已启用账号')"><icon-check />启用账号</button>
          <button class="bd-btn bd-btn--ghost" @click="openReset"><icon-lock />重置密码</button>
          <button class="bd-btn bd-btn--ghost" @click="askResetMfa('totp')"><icon-mobile />重置 TOTP</button>
          <!-- ★passkey 必须留一个管理员出口：它没有恢复码、本人删不掉最后一个，而
               secondFactor 规定「已注册 passkey 即无条件强制断言」——去掉这个按钮，
               认证器一丢账号就永久登不进来，唯一出路是运维删库。 -->
          <button class="bd-btn bd-btn--ghost" @click="askResetMfa('passkey')"><icon-safe />重置 passkey</button>
          <button class="bd-btn bd-btn--ghost" @click="openEditProfile"><icon-edit />编辑资料</button>
          <button v-if="sel.status !== 'disabled'" class="bd-btn bd-btn--ghost bd-btn--danger" @click="setStatus('disabled', '已禁用账号')">禁用账号</button>
          <!-- ★删除是 License 席位的**唯一**释放路径（席位满时后端 409 文案与闲置治理弹窗
               都指向它）。点之前先问一次影响面：哪些资源还按账号名点着他。 -->
          <button class="bd-btn bd-btn--ghost bd-btn--danger" @click="openDeleteUser"><icon-delete />删除账号</button>
        </div>
      </div>
    </a-drawer>

    <!-- 组织编辑（落库） -->
    <a-modal v-model:visible="orgOpen" :title="orgForm.id ? '编辑组织' : '新建组织'" :width="460" :footer="false">
      <div class="bd-uform">
        <div class="bd-uform__f"><label>组织名称</label><a-input v-model="orgForm.name" placeholder="如：华东大区" /></div>
        <div class="bd-uform__f"><label>上级组织</label>
          <a-select v-model="orgForm.parentId" allow-clear placeholder="不选＝作为顶级组织">
            <a-option v-for="o in orgParentOptions" :key="o.key" :value="o.key">{{ '　'.repeat(o.depth) + o.title }}</a-option>
          </a-select>
        </div>
        <div class="bd-uform__f"><label>排序值</label><a-input-number v-model="orgForm.sort" :min="0" :max="9999" /></div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="orgOpen = false">取消</button>
          <button class="bd-btn" :disabled="orgSaving" @click="saveOrg">保存并落库</button>
        </div>
      </div>
    </a-modal>

    <!-- 用户组编辑（落库） -->
    <a-modal v-model:visible="groupOpen" :title="groupForm.id ? '编辑用户组' : '新建用户组'" :width="460" :footer="false">
      <div class="bd-uform">
        <div class="bd-uform__f"><label>组名称</label><a-input v-model="groupForm.name" placeholder="如：高敏访问组" /></div>
        <div class="bd-uform__f"><label>成员来源</label>
          <a-select v-model="groupForm.kind" :disabled="!!groupForm.id">
            <a-option value="static">显式成员（管理员维护）</a-option>
            <a-option value="role">按用户角色派生（成员只读）</a-option>
          </a-select>
          <div class="bd-uform__hint" style="margin: 8px 0 0">
            角色派生组的成员 = 展示角色里含该组名的用户；组名即角色名，改不了成员，只能改角色。
          </div>
        </div>
        <div class="bd-uform__f"><label>说明</label><a-input v-model="groupForm.description" placeholder="选填" /></div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="groupOpen = false">取消</button>
          <button class="bd-btn" :disabled="groupSaving" @click="saveGroup">保存并落库</button>
        </div>
      </div>
    </a-modal>

    <!-- 组成员编辑（落库） -->
    <a-modal v-model:visible="memberOpen" title="编辑用户组成员" :width="480" :footer="false">
      <div class="bd-uform">
        <div class="bd-uform__hint">「{{ memberGroupName }}」的成员按账号维护，保存即全量覆写。</div>
        <div class="bd-uform__f"><label>成员账号</label>
          <a-select v-model="memberAccounts" multiple placeholder="选择账号">
            <a-option v-for="u in users" :key="u.id" :value="u.account">{{ u.name }}（{{ u.account }}）</a-option>
          </a-select>
        </div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="memberOpen = false">取消</button>
          <button class="bd-btn" :disabled="memberSaving" @click="saveMembers">保存成员</button>
        </div>
      </div>
    </a-modal>

    <!-- 新增用户（写入 SQLite） -->
    <a-modal v-model:visible="createOpen" title="新增用户" :width="460" :footer="false">
      <div class="bd-uform">
        <div class="bd-uform__f"><label>姓名</label><a-input v-model="form.name" placeholder="如：钱七" /></div>
        <div class="bd-uform__f"><label>登录账号</label><a-input v-model="form.account" placeholder="如：qian.qi" /></div>
        <div class="bd-uform__f"><label>所属组织</label>
          <a-select v-model="form.orgId" allow-clear placeholder="不选＝暂不归属">
            <a-option v-for="o in flatOrg" :key="o.key" :value="o.key">{{ '　'.repeat(o.depth) + o.title }}</a-option>
          </a-select>
        </div>
        <div class="bd-uform__f"><label>用户组</label>
          <a-select v-model="form.groups" multiple placeholder="选填">
            <a-option v-for="g in staticGroups" :key="g.id" :value="g.id">{{ g.name }}</a-option>
          </a-select>
        </div>
        <!-- ★别在建号表单里加「认证方式」选项：认证方式由后端按实算下发（口令来源 +
             真注册过的 passkey / TOTP），在这里选只会落成一列零消费方的自由文本，
             却在用户详情里被当作事实展示。改认证要求去「认证策略」，加第二因子由本人注册。 -->
        <div class="bd-uform__note">
          <icon-info-circle />
          <span>
            新建的是**本地口令**账号。认证方式不在这里选：它由真实事实算出来
            （口令来源 + 是否注册过 passkey / TOTP），建号后在列表里可见。
          </span>
        </div>
        <div class="bd-uform__f"><label>初始登录口令</label>
          <a-input-password v-model="form.password" placeholder="留空则用默认 baidi@123（至少 6 位）" />
        </div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="createOpen = false">取消</button>
          <button class="bd-btn" :disabled="creating" @click="createUser">创建并落库</button>
        </div>
      </div>
    </a-modal>

    <!-- 编辑资料（FR-USER-02「本地新建与修改」）。★只有姓名与邮箱：
         账号名是令牌主体，也是 JIT 授予 / 封禁名单 / 终端报告 / 用户组成员 /
         认证源绑定的关联键，改它会让这些关系整段挂空且不报错，后端显式拒收。 -->
    <a-modal v-model:visible="prof.open" title="编辑用户资料" :width="420" :footer="false">
      <div class="bd-uform">
        <div class="bd-uform__f"><label>账号</label>
          <a-input :model-value="prof.account" disabled />
          <span class="bd-uform__d">账号名不可修改：它是令牌主体与多张表的关联键。需要换账号请新建并迁移授权。</span>
        </div>
        <div class="bd-uform__f"><label>姓名</label>
          <a-input v-model="prof.name" placeholder="显示名" allow-clear @keyup.enter="saveProfile" />
        </div>
        <div class="bd-uform__f"><label>邮箱</label>
          <a-input v-model="prof.email" placeholder="留空即清除" allow-clear @keyup.enter="saveProfile" />
        </div>
        <div v-if="prof.err" class="bd-uform__err"><icon-close-circle-fill />{{ prof.err }}</div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="prof.open = false">取消</button>
          <button class="bd-btn" :disabled="prof.busy" @click="saveProfile">{{ prof.busy ? '保存中…' : '保存' }}</button>
        </div>
      </div>
    </a-modal>

    <!-- 删除账号：先给影响面，再让人点 -->
    <a-modal v-model:visible="del.open" title="删除账号" :width="480" :footer="false">
      <div class="bd-uform">
        <div class="bd-delwarn">
          <icon-exclamation-circle-fill />
          <div>
            将永久删除账号 <b>{{ del.name }}</b>（<span class="bd-mono">{{ del.account }}</span>）。
            此操作<b>不可撤销</b>，并会释放一个 License 用户席位。
          </div>
        </div>
        <div v-if="del.loading" class="bd-uform__d">正在核算影响面…</div>
        <div v-else class="bd-delnote">{{ del.note || '（影响面未取到）' }}</div>
        <div v-if="del.resources.length" class="bd-uform__d">
          仍点名授权他的资源：<b class="bd-mono">{{ del.resources.join('、') }}</b>
        </div>
        <div v-if="del.err" class="bd-uform__err"><icon-close-circle-fill />{{ del.err }}</div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="del.open = false">取消</button>
          <button class="bd-btn bd-btn--danger2" :disabled="del.busy" @click="doDeleteUser">
            {{ del.busy ? '删除中…' : '确认删除' }}
          </button>
        </div>
      </div>
    </a-modal>

    <!-- 闲置账号治理：按 last_login 识别 + 批量锁定。判据是真实登录记录；
         ★「无记录」按建号时间估算并单独标注，绝不混同「从未登录」。 -->
    <a-modal v-model:visible="idleOpen" title="闲置账号治理" :width="640" :footer="false">
      <div class="bd-uform">
        <div class="bd-uform__hint">
          按最后登录时间识别闲置账号（仅 active 状态）。僵尸账号是最便宜的攻击面；
          锁定后可随时在用户详情里解锁，license 席位则需删除账号才释放。
        </div>
        <!-- 闲置治理**策略**（阈值 + 是否自动锁定）会落库并长期生效。
             ★它与下面那个"超过 N 天"的预览输入框是两回事：后者只影响这一次识别。 -->
        <div class="bd-idlepol">
          <div class="bd-idlepol__h"><icon-settings />闲置治理策略<span>（保存后长期生效）</span></div>
          <div class="bd-idlepol__row">
            <span>判定为闲置：超过</span>
            <a-input-number v-model="idlePolicy.thresholdDays" :min="idleMinDays" :max="idleMaxDays"
                            style="width: 110px" size="small" />
            <span>天未登录</span>
            <div style="flex:1" />
            <span v-if="idleDirty" class="bd-idlepol__dirty">有未保存的改动</span>
            <button class="bd-btn" :class="{ 'bd-btn--ghost': !idleDirty }" :disabled="idleSaving" @click="saveIdlePolicy">
              {{ idleSaving ? '保存中…' : '保存策略' }}
            </button>
          </div>
          <label class="bd-idlepol__row bd-idlepol__auto">
            <a-switch v-model="idlePolicy.autoLock" size="small" />
            <span>
              <b>自动锁定闲置账号</b>
              <i>后台每 {{ idleLoopHint }} 检查一轮；锁定与手工批量走同一条路径（含防自锁与数据面撤窗），
                 并<b>永不处置管理员账号</b>——那条路径上没有调用方可以比对权限。</i>
            </span>
          </label>
          <!-- 开着自动锁定就是一件会在没人看着的时候动别人账号的事，必须当面说清。
               ★判据用**已落库**的那份：勾上开关还没保存时，后台并没有在锁人。 -->
          <div v-if="idleSaved.autoLock" class="bd-idlepol__warn">
            <icon-exclamation-circle-fill />
            自动锁定<b>已在生效</b>：后台按 {{ idleSaved.thresholdDays }} 天的阈值<b>自行锁定</b>
            符合条件的普通账号，并同步撤窗断隧道。每一次锁定都以 <code>system</code> 为行为人落审计。
          </div>
          <div v-if="!idleStoreReady" class="bd-idlepol__warn">
            <icon-exclamation-circle-fill />
            当前后端没有登录记录判据（内存种子模式），自动锁定不会有任何动作。
          </div>
        </div>

        <div class="bd-idle__bar">
          <span>本次识别按</span>
          <a-input-number v-model="idleDays" :min="idleMinDays" :max="idleMaxDays" style="width: 110px" size="small" />
          <span>天预览</span>
          <button class="bd-btn" :disabled="idleLoading" @click="loadIdle">{{ idleLoading ? '识别中…' : '识别' }}</button>
          <div style="flex:1" />
          <span v-if="idleList.length" class="bd-idle__cnt">命中 {{ idleList.length }} 个，已选 {{ idleSel.length }} 个</span>
        </div>
        <!-- 预览天数与落库阈值不一致时必须说破：否则管理员会以为自己刚才配的就是这个数 -->
        <div v-if="idleDays !== idleSaved.thresholdDays" class="bd-idle__preview">
          当前预览的是 {{ idleDays }} 天，而<b>已落库的策略阈值是 {{ idleSaved.thresholdDays }} 天</b>——
          <template v-if="idleSaved.autoLock">后台自动锁定按后者执行。</template>
          <template v-else>下面这份名单只是按预览天数算的，不代表策略。</template>
          要改策略请在上方修改并保存。
        </div>
        <div v-if="idleQueried && !idleList.length" class="bd-idle__empty">没有超过 {{ idleDays }} 天未登录的活跃账号。</div>
        <div v-else-if="idleList.length" class="bd-idle__list">
          <label v-for="a in idleList" :key="a.id" class="bd-idle__row">
            <input type="checkbox" :value="a.id" v-model="idleSel" />
            <span class="bd-idle__acct bd-mono">{{ a.account }}</span>
            <span class="bd-idle__name">{{ a.name }}</span>
            <span v-if="a.isAdmin" class="bd-tg" :style="tagStyle('#F53F3F')">管理员</span>
            <span class="bd-idle__days">
              <template v-if="a.neverRecorded">无登录记录 · 建号 {{ a.idleDays }} 天</template>
              <template v-else>{{ a.idleDays }} 天未登录</template>
            </span>
          </label>
        </div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="idleOpen = false">关闭</button>
          <button class="bd-btn bd-btn--danger2" :disabled="!idleSel.length || idleLocking" @click="lockIdle">
            {{ idleLocking ? '锁定中…' : `批量锁定（${idleSel.length}）` }}
          </button>
        </div>
      </div>
    </a-modal>

    <!-- 批量导入：CSV → 逐行建普通用户。★两条边界必须说在人点「开始导入」之前：
         ① 只能建普通用户（含角色列的文件整份拒收）；② 有行数与文件大小上限。 -->
    <a-modal v-model:visible="impOpen" title="批量导入用户" :width="680" :footer="false">
      <div class="bd-uform">
        <div class="bd-uform__hint">
          CSV 逐行创建<b>普通用户</b>：必填列「账号」「姓名」，可选列「组织」「组织ID」「用户组」「邮箱」「初始口令」。
          初始口令留空则用默认 {{ DEFAULT_PW }}，<b>所有导入账号一律置首登强制改密</b>。
          单次上限 {{ IMP_MAX_ROWS }} 行 / {{ IMP_MAX_KB }} KiB，超出请分批。
        </div>
        <div class="bd-imp__warn">
          <icon-exclamation-circle-fill class="bd-imp__warnic" />
          <span>
            含「角色 / role / 管理员角色 / 状态」等列的文件会被<b>整份拒收</b>——导入不能创建管理员，
            管理员账号请在「系统管理 → 管理员」页单独创建。导出的台账文件带这些列，
            回传前需先删掉（或直接用下方模板）。
          </span>
        </div>
        <div class="bd-imp__bar">
          <input ref="impFileEl" type="file" accept=".csv,text/csv" @change="onPickImportFile" />
          <div style="flex:1" />
          <span class="bd-link" @click="downloadTemplate">下载导入模板</span>
        </div>
        <div v-if="impFileName" class="bd-imp__file">
          已选择 <b>{{ impFileName }}</b>（{{ (impFileSize / 1024).toFixed(1) }} KiB）
        </div>

        <!-- 逐行结果：成功多少、失败多少、每一行为什么失败 -->
        <div v-if="impResult" class="bd-imp__res">
          <div class="bd-imp__sum">
            <span class="bd-tg" :style="tagStyle('#00B42A')">成功 {{ impResult.created.length }} 条</span>
            <span class="bd-tg" :style="tagStyle(impResult.failed.length ? '#F53F3F' : '#86909C')">
              失败 {{ impResult.failed.length }} 条
            </span>
            <span class="bd-imp__total">共 {{ impResult.total }} 行</span>
          </div>
          <div v-if="impResult.ignoredColumns?.length" class="bd-imp__ign">
            未识别的列（其内容未被导入）：{{ impResult.ignoredColumns.join('、') }}
          </div>
          <div v-if="impResult.failed.length" class="bd-imp__list">
            <div v-for="f in impResult.failed" :key="f.row" class="bd-imp__row">
              <span class="bd-imp__rowno">第 {{ f.row }} 行</span>
              <span class="bd-mono">{{ f.account || '—' }}</span>
              <span class="bd-imp__reason">{{ f.reason }}</span>
            </div>
          </div>
          <div v-if="impResult.created.length" class="bd-imp__ok">
            已创建：{{ impResult.created.map((c) => c.account).join('、') }}
          </div>
        </div>

        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="impOpen = false">关闭</button>
          <button class="bd-btn" :disabled="!impFileName || importing" @click="doImport">
            {{ importing ? '导入中…' : '开始导入' }}
          </button>
        </div>
      </div>
    </a-modal>

    <!-- 重置口令（管理员，落库改 bcrypt 哈希） -->
    <a-modal v-model:visible="resetOpen" title="重置登录口令" :width="420" :footer="false">
      <div class="bd-uform">
        <div class="bd-uform__hint">为「{{ sel?.name }}」({{ sel?.account }}) 设置新的登录口令，立即生效、旧口令失效。</div>
        <div class="bd-uform__f"><label>新口令</label>
          <a-input-password v-model="newPw" placeholder="至少 6 位" @keyup.enter="doReset" />
        </div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="resetOpen = false">取消</button>
          <button class="bd-btn" :disabled="resetting" @click="doReset">重置口令</button>
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { Message, Modal } from '@arco-design/web-vue';
import { api, getToken, type UserDirBundle, type Directory, type OrgUnit, type DirUser, type Org, type GroupWithMembers, type UserImportResp, failReason } from '@/lib/api';

const live = ref(false);
const directories = ref<Directory[]>([{ key: 'local', name: '本地目录', type: 'local', users: 0 }]);
const orgTree = ref<OrgUnit[]>([]);
const orgs = ref<Org[]>([]);
const groups = ref<GroupWithMembers[]>([]);
const users = ref<DirUser[]>([]);
const dir = ref('local');
const mode = ref<'org' | 'group'>('org');
const org = ref('');       // '' = 全部用户
const groupSel = ref('');  // '' = 全部用户
const sel = ref<DirUser | null>(null);
const drawer = ref(false);

const curDir = computed(() => directories.value.find((d) => d.key === dir.value));
const staticGroups = computed(() => groups.value.filter((g) => g.kind === 'static'));

interface FlatOrg extends OrgUnit { depth: number }
const flatOrg = computed<FlatOrg[]>(() => {
  const out: FlatOrg[] = [];
  const walk = (ns: OrgUnit[], d: number) => ns.forEach((n) => { out.push({ ...n, depth: d }); n.children && walk(n.children, d + 1); });
  walk(orgTree.value, 0);
  return out;
});
// 编辑某节点时，它自己与它的后代不能当上级——环形父子后端会拒（400），前端先不给选。
const orgParentOptions = computed(() => {
  if (!orgForm.id) return flatOrg.value;
  const banned = subtreeKeys(orgForm.id);
  return flatOrg.value.filter((o) => !banned.has(o.key));
});

/** 某组织节点的子树 key 集合（含自身）。按子树过滤而不是只看直属，父节点点开才看得到下面的人。 */
function subtreeKeys(key: string): Set<string> {
  const out = new Set<string>();
  const collect = (n: OrgUnit) => { out.add(n.key); n.children?.forEach(collect); };
  const find = (ns: OrgUnit[]): boolean => ns.some((n) => {
    if (n.key === key) { collect(n); return true; }
    return n.children ? find(n.children) : false;
  });
  find(orgTree.value);
  return out;
}

const scopeTitle = computed(() => {
  if (mode.value === 'group') return groups.value.find((g) => g.id === groupSel.value)?.name ?? '全部用户';
  return flatOrg.value.find((n) => n.key === org.value)?.title ?? '全部用户';
});
/** 关键词。★过滤字段必须与占位文案逐字对应（用户名 / 账号 / IP）：
 *  搜得比说的少 = 管理员以为「库里没有」；搜得比说的多 = 搜出一堆解释不了的命中。 */
/** 关键词。从别的页面带条件跳进来时（如「用户状态 → 查看用户」的 ?q=账号）先接住，
 *  否则那个入口落到的是一张未筛选的全量目录——它存在的意义正是省掉手抄账号名。 */
const kw = ref(String(useRoute().query.q ?? '').trim());
/**
 * 当前身份源下的账号。★选项卡必须真过滤：本地与各外部目录的账号混在一张表里，
 * 会让人相信自己正在看某一个目录（FR-USER-01「目录间相互独立」）。
 * 旧后端不下发 `sourceId` → undefined → **不过滤**，否则升级那一刻每个选项卡都是空表。
 */
const inDir = computed(() =>
  users.value.filter((u) => u.sourceId === undefined || u.sourceId === dir.value));

const shown = computed(() => {
  let list = inDir.value;
  if (mode.value === 'group') {
    if (groupSel.value) list = list.filter((u) => u.groups.includes(groupSel.value));
  } else if (org.value) {
    const keys = subtreeKeys(org.value);
    list = list.filter((u) => keys.has(u.orgKey));
  }
  const k = kw.value.trim().toLowerCase();
  if (!k) return list;
  return list.filter((u) => `${u.name} ${u.account} ${u.ip}`.toLowerCase().includes(k));
});
function groupName(id: string) { return groups.value.find((g) => g.id === id)?.name ?? id; }

// ── 常驻操作条：当前选中的节点 + 三个操作的可达入口 ──
const curOrgNode = computed(() => flatOrg.value.find((n) => n.key === org.value) ?? null);
const curGroup = computed(() => groups.value.find((g) => g.id === groupSel.value) ?? null);
/** 按钮的 title/aria-label：选中了就说清作用在谁身上，没选中就说清怎么才能用（禁用态必须自解释）。 */
function orgActHint(act: string) {
  return curOrgNode.value ? `${act}：${curOrgNode.value.title}` : `${act}（先在下方选中一个部门）`;
}
function groupActHint(act: string) {
  return curGroup.value ? `${act}：${curGroup.value.name}` : `${act}（先在下方选中一个用户组）`;
}
const memberActHint = computed(() => {
  const g = curGroup.value;
  if (!g) return '编辑成员（先在下方选中一个用户组）';
  if (g.kind === 'role') return `「${g.name}」是角色派生组，成员由用户角色决定，不能直接编辑`;
  if (g.kind === 'external') return `「${g.name}」来自外部目录（LDAP/OIDC），成员在每次外部登录时由认证源刷新——手工改动会被下次登录冲掉，故不可编辑`;
  return `编辑成员：${g.name}`;
});
function newSubOrg() { if (curOrgNode.value) openOrg(null, curOrgNode.value.key); }
function editCurOrg() { if (curOrgNode.value) openOrg(curOrgNode.value.key); }
function removeCurOrg() { if (curOrgNode.value) askRemoveOrg(curOrgNode.value.key, curOrgNode.value.title); }
function editCurMembers() { if (curGroup.value?.kind === 'static') openMembers(curGroup.value); }
function editCurGroup() { if (curGroup.value) openGroup(curGroup.value); }
function removeCurGroup() { if (curGroup.value) askRemoveGroup(curGroup.value); }

// ★顶部四个聚合数跟随当前身份源：用全库口径的话，它与刚点中的那个目录对不上。
const agg = computed(() => {
  const u = inDir.value;
  return [
    { label: '在线', n: u.filter((x) => x.online).length, color: 'var(--bd-success)' },
    { label: '离线', n: u.filter((x) => !x.online).length, color: 'var(--bd-t4)' },
    { label: '锁定', n: u.filter((x) => x.status === 'locked').length, color: 'var(--bd-danger)' },
    { label: '禁用', n: u.filter((x) => x.status === 'disabled').length, color: 'var(--bd-t3)' }
  ];
});

const LIFE = [
  { key: 'active', label: '正常' }, { key: 'idle', label: '闲置' },
  { key: 'locked', label: '锁定' }, { key: 'disabled', label: '禁用' }
];
function statusMeta(s: string) {
  return { active: { label: '正常', color: '#00B42A' }, idle: { label: '闲置', color: '#86909C' }, locked: { label: '锁定', color: '#F53F3F' }, disabled: { label: '禁用', color: '#86909C' } }[s] ?? { label: s, color: '#86909C' };
}
const AV = ['#165DFF', '#722ED1', '#00B42A', '#FF7D00', '#0FC6C2'];
function avBg(u: DirUser) { return AV[(u.account.charCodeAt(0) + u.account.length) % AV.length]; }
function tagStyle(color: string) { return { color, background: color + '14' }; }
/** ★unknown 必须单列成灰色的「不可判定」，绝不落进绿色的 else 那一支：从未上报过终端环境的
 *  账号在 observe 模式下照样能接入，把它显示成「正常」是替一台完全未知的机器打包票。 */
function riskColor(r: string) {
  return r === 'high' ? '#F53F3F' : r === 'low' ? '#FF7D00' : r === 'unknown' ? '#86909C' : '#00B42A';
}
function riskLabel(r: string) {
  return r === 'high' ? '高风险' : r === 'low' ? '低风险' : r === 'unknown' ? '不可判定' : '正常';
}

// ── 用户详情 + 归属编辑 ──
const memberForm = reactive<{ orgId: string; groups: string[]; roles: string[] }>({ orgId: '', groups: [], roles: [] });
const savingMember = ref(false);
// 角色派生的归属在这里是只读展示：它由 users.roles 决定，混进可编辑的多选框会让人
// 以为取消勾选就能移出组，而后端会拒。
const derivedGroups = computed(() => {
  const ids = sel.value?.groups ?? [];
  return groups.value.filter((g) => g.kind === 'role' && ids.includes(g.id));
});
function open(u: DirUser) {
  sel.value = u;
  memberForm.orgId = u.orgId;
  memberForm.groups = u.groups.filter((id) => staticGroups.value.some((g) => g.id === id));
  memberForm.roles = [...(u.roles ?? [])];
  drawer.value = true;
}
async function saveMembership() {
  if (!sel.value) return;
  savingMember.value = true;
  try {
    await api(`/users/${sel.value.id}/membership`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ orgId: memberForm.orgId ?? '', groups: memberForm.groups, roles: memberForm.roles })
    });
    Message.success('已更新组织归属、用户组与展示角色');
    await load();
    const again = users.value.find((u) => u.id === sel.value?.id);
    if (again) open(again);
  } catch (e) { Message.error(`归属保存失败：${failReason(e)}`); }
  finally { savingMember.value = false; }
}

// ── 组织增删改 ──
const orgOpen = ref(false);
const orgSaving = ref(false);
const orgForm = reactive({ id: '', name: '', parentId: '', sort: 0 });
function openOrg(key: string | null, parent = '') {
  if (key) {
    const row = orgs.value.find((o) => o.id === key);
    orgForm.id = key;
    orgForm.name = row?.name ?? flatOrg.value.find((n) => n.key === key)?.title ?? '';
    orgForm.parentId = row?.parentId ?? '';
    orgForm.sort = row?.sort ?? 0;
  } else {
    orgForm.id = ''; orgForm.name = ''; orgForm.parentId = parent; orgForm.sort = 0;
  }
  orgOpen.value = true;
}
async function saveOrg() {
  if (!orgForm.name.trim()) { Message.warning('请填写组织名称'); return; }
  orgSaving.value = true;
  try {
    await api('/orgs', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: orgForm.id, name: orgForm.name, parentId: orgForm.parentId ?? '', sort: orgForm.sort })
    });
    Message.success(orgForm.id ? '组织已更新' : '组织已创建');
    orgOpen.value = false;
    await load();
  } catch (e) { Message.error(`保存组织失败：${failReason(e)}`); }
  finally { orgSaving.value = false; }
}
// 删除入口常驻可见，误触代价高，故必须有这道确认。
function askRemoveOrg(key: string, title: string) {
  Modal.confirm({
    title: '删除组织',
    content: `确认删除组织「${title}」？若它下面还有子部门或成员，后端会拒绝删除并说明原因。`,
    okText: '删除', cancelText: '取消', okButtonProps: { status: 'danger' },
    onOk: () => removeOrg(key, title)
  });
}
async function removeOrg(key: string, title: string) {
  try {
    await api(`/orgs/${key}`, { method: 'DELETE' });
    Message.success(`已删除组织「${title}」`);
    if (org.value === key) org.value = '';
    await load();
  } catch (e) {
    // 后端守卫的原话（"该组织下还有用户，请先把用户移到其他组织"）是唯一能指导下一步动作的
    // 信息，用 Modal 留在屏幕上，别被 3 秒的 toast 带走。
    Modal.warning({ title: '组织未删除', content: failReason(e) });
  }
}

// ── 用户组增删改 + 成员 ──
const groupOpen = ref(false);
const groupSaving = ref(false);
const groupForm = reactive<{ id: string; name: string; kind: 'static' | 'role'; description: string }>(
  { id: '', name: '', kind: 'static', description: '' });
function openGroup(g: GroupWithMembers | null) {
  // 外部目录组连编辑抽屉都不该打开：后端两条写路径都会拒（改了也会被下次登录冲掉），
  // 这里在入口就说清，而不是让人填完表单吃一个 409。
  if (g?.kind === 'external') {
    Message.info(`「${g.name}」来自外部目录，由认证源按登录刷新，不可编辑`);
    return;
  }
  if (g) { groupForm.id = g.id; groupForm.name = g.name; groupForm.kind = g.kind; groupForm.description = g.description; }
  else { groupForm.id = ''; groupForm.name = ''; groupForm.kind = 'static'; groupForm.description = ''; }
  groupOpen.value = true;
}
async function saveGroup() {
  if (!groupForm.name.trim()) { Message.warning('请填写组名称'); return; }
  groupSaving.value = true;
  try {
    await api('/groups', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...groupForm })
    });
    Message.success(groupForm.id ? '用户组已更新' : '用户组已创建');
    groupOpen.value = false;
    await load();
  } catch (e) { Message.error(`用户组保存失败：${failReason(e)}`); }
  finally { groupSaving.value = false; }
}
function askRemoveGroup(g: GroupWithMembers) {
  Modal.confirm({
    title: '删除用户组',
    content: `确认删除用户组「${g.name}」？该组的成员关系会一并清除（用户账号本身不受影响）。`,
    okText: '删除', cancelText: '取消', okButtonProps: { status: 'danger' },
    onOk: () => removeGroup(g)
  });
}
async function removeGroup(g: GroupWithMembers) {
  try {
    await api(`/groups/${g.id}`, { method: 'DELETE' });
    Message.success(`已删除用户组「${g.name}」`);
    if (groupSel.value === g.id) groupSel.value = '';
    await load();
  } catch (e) {
    Modal.warning({ title: '用户组未删除', content: failReason(e) });
  }
}

const memberOpen = ref(false);
const memberSaving = ref(false);
const memberGroupID = ref('');
const memberGroupName = ref('');
const memberAccounts = ref<string[]>([]);
function openMembers(g: GroupWithMembers) {
  memberGroupID.value = g.id; memberGroupName.value = g.name;
  memberAccounts.value = [...g.memberAccounts];
  memberOpen.value = true;
}
async function saveMembers() {
  memberSaving.value = true;
  try {
    await api(`/groups/${memberGroupID.value}/members`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accounts: memberAccounts.value })
    });
    Message.success('成员已更新');
    memberOpen.value = false;
    await load();
  } catch (e) { Message.error(`保存成员失败：${failReason(e)}`); }
  finally { memberSaving.value = false; }
}

async function load() {
  try {
    const b = await api<UserDirBundle>('/users');
    directories.value = b.directories;
    orgTree.value = b.orgTree ?? [];
    users.value = (b.users ?? []).map((u) => ({ ...u, groups: u.groups ?? [] }));
    live.value = true;
  } catch { live.value = false; return; }
  // 组织扁平清单（带 parentId/sort，编辑用）与用户组清单（带成员账号）都只有 admin 能读；
  // 拉不到就退化成"只能看树、不能改"，不把整页打成未连状态。
  try { orgs.value = (await api<{ orgs: Org[] }>('/orgs')).orgs ?? []; } catch { orgs.value = []; }
  try { groups.value = (await api<{ groups: GroupWithMembers[] }>('/groups')).groups ?? []; } catch { groups.value = []; }
}

// 改账号状态（禁用/启用/解锁）→ 落库
async function setStatus(status: string, label: string) {
  if (!sel.value) return;
  try {
    await api(`/users/${sel.value.id}/status`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
    Message.success(`${sel.value.name}：${label}`);
    drawer.value = false;
    await load();
  } catch (e) {
    // ★必须原样转述后端：这里回的是防自锁与越权两道守卫的原话（如「最后一名可登录的
    //   超级管理员不可禁用」），换成自拟归因就看不出撞的是哪一条、该找谁。
    Message.error(`操作失败：${failReason(e)}`);
  }
}

// 新增用户 → 落库
const createOpen = ref(false);
const creating = ref(false);
const form = reactive<{ name: string; account: string; orgId: string; groups: string[]; password: string }>(
  { name: '', account: '', orgId: '', groups: [], password: '' });
function openCreateUser() {
  form.orgId = mode.value === 'org' ? org.value : '';
  form.groups = mode.value === 'group' && groupSel.value && staticGroups.value.some((g) => g.id === groupSel.value)
    ? [groupSel.value] : [];
  createOpen.value = true;
}
async function createUser() {
  if (!form.name || !form.account) { Message.warning('请填写姓名与账号'); return; }
  if (form.password && form.password.length < 6) { Message.warning('初始口令至少 6 位'); return; }
  creating.value = true;
  try {
    await api('/users', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...form, orgId: form.orgId ?? '', device: '未登记', ip: '—', roles: [] })
    });
    Message.success(`已新增用户「${form.name}」并落库`);
    createOpen.value = false;
    form.name = ''; form.account = ''; form.password = '';
    await load();
  } catch (e) {
    Message.error(`新增失败：${failReason(e)}`);
  } finally {
    creating.value = false;
  }
}

// 重置口令 → 落库改哈希
const resetOpen = ref(false);
const resetting = ref(false);
const newPw = ref('');
function openReset() { newPw.value = ''; resetOpen.value = true; }
async function doReset() {
  if (!sel.value) return;
  if (newPw.value.length < 6) { Message.warning('口令至少 6 位'); return; }
  resetting.value = true;
  try {
    await api(`/users/${sel.value.id}/password`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: newPw.value })
    });
    Message.success(`已重置「${sel.value.name}」的登录口令`);
    resetOpen.value = false;
  } catch (e) { Message.error(`口令重置失败：${failReason(e)}`); }
  finally { resetting.value = false; }
}

/* ── 编辑资料 / 删除账号（FR-USER-02 / FR-USER-15）── */
const prof = reactive({ open: false, busy: false, id: '', account: '', name: '', email: '', err: '' });

function openEditProfile() {
  if (!sel.value) return;
  Object.assign(prof, {
    open: true, busy: false, err: '',
    id: sel.value.id, account: sel.value.account,
    name: sel.value.name, email: sel.value.email ?? ''
  });
}

async function saveProfile() {
  if (!prof.name.trim()) { prof.err = '姓名不能为空'; return; }
  prof.busy = true; prof.err = '';
  try {
    await api(`/users/${prof.id}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: prof.name.trim(), email: prof.email.trim() })
    });
    Message.success(`已更新「${prof.name.trim()}」的资料`);
    prof.open = false;
    await load();
    // 抽屉里那份是快照，刷新后要跟着换，否则页面上还是旧名字。
    if (sel.value) sel.value = users.value.find((u) => u.id === prof.id) ?? sel.value;
  } catch (e) {
    prof.err = failReason(e);
  } finally { prof.busy = false; }
}

const del = reactive({
  open: false, busy: false, loading: false, id: '', account: '', name: '',
  note: '', resources: [] as string[], err: ''
});

/** ★先问影响面再让人点：删账号**不会**把他从资源的 allow_users 里摘掉，
 *  那是一串悬空的账号名，日后若有人建了同名账号会**直接继承**这些授权。
 *  不说的话，管理员会以为删账号顺手把权限一起收了。 */
async function openDeleteUser() {
  if (!sel.value) return;
  Object.assign(del, {
    open: true, busy: false, loading: true, err: '',
    id: sel.value.id, account: sel.value.account, name: sel.value.name,
    note: '', resources: []
  });
  try {
    const r = await api<{ note: string; resources: string[] }>(`/users/${del.id}/delete-preview`);
    del.note = r.note;
    del.resources = r.resources ?? [];
  } catch (e) {
    del.note = '';
    del.err = `影响面读取失败：${failReason(e)}`;
  } finally { del.loading = false; }
}

async function doDeleteUser() {
  del.busy = true; del.err = '';
  try {
    const r = await api<{ note: string }>(`/users/${del.id}`, { method: 'DELETE' });
    del.open = false;
    drawer.value = false;
    // 用不会自动消失的弹窗给影响面：那是要照着去补救的，不是通知。
    Modal.info({ title: `账号「${del.name}」已删除`, content: r.note || '已释放 1 个 License 用户席位。', okText: '知道了' });
    await load();
  } catch (e) {
    del.err = failReason(e);
  } finally { del.busy = false; }
}

/* ── 闲置账号治理 ── */
interface IdleAccount { id: string; name: string; account: string; lastLogin: string; idleDays: number; neverRecorded: boolean; isAdmin: boolean }
const idleOpen = ref(false);
const idleDays = ref(90);
/** 编辑中的闲置治理策略（PRD FR-MON-19）。与上面那个"预览天数"是两回事：
 *  预览只影响这一次识别，策略才是后台自动锁定真正读的那份。 */
const idlePolicy = reactive({ thresholdDays: 90, autoLock: false });
/** **服务端上已落库**的那一份。★必须与编辑草稿分开存：合成一份的话，输入框里刚敲下的、
 *  还没保存的数字会被页面说成"正在生效的阈值"，而这一屏最该说准的正是这句。 */
const idleSaved = reactive({ thresholdDays: 90, autoLock: false });
/** 有未保存的改动（页面据此提示"改了还没保存"）。 */
const idleDirty = computed(() =>
  idlePolicy.thresholdDays !== idleSaved.thresholdDays || idlePolicy.autoLock !== idleSaved.autoLock);
const idleSaving = ref(false);
const idleStoreReady = ref(true);
/** 阈值区间由后端下发，前端不另抄一份（抄一份就会出现"页面让填、后端拒收"）。 */
const idleMinDays = ref(7);
const idleMaxDays = ref(3650);
/** 后台检查周期只是提示文案；真正的间隔在控制面 BAIDI_IDLE_LOCK_INTERVAL。 */
const idleLoopHint = '一小时';
const idleList = ref<IdleAccount[]>([]);
const idleSel = ref<string[]>([]);
const idleLoading = ref(false);
const idleLocking = ref(false);
const idleQueried = ref(false);

function openIdle() {
  idleOpen.value = true;
  idleList.value = [];
  idleSel.value = [];
  idleQueried.value = false;
  void loadIdlePolicy();
}

interface IdlePolicyResp {
  policy: { thresholdDays: number; autoLock: boolean };
  minDays: number; maxDays: number; storeReady: boolean;
}

async function loadIdlePolicy() {
  try {
    const r = await api<IdlePolicyResp>('/users/idle/policy');
    idlePolicy.thresholdDays = r.policy.thresholdDays;
    idlePolicy.autoLock = r.policy.autoLock;
    idleSaved.thresholdDays = r.policy.thresholdDays;
    idleSaved.autoLock = r.policy.autoLock;
    idleMinDays.value = r.minDays;
    idleMaxDays.value = r.maxDays;
    idleStoreReady.value = r.storeReady;
    // 预览天数默认跟随策略：一打开就看到"按当前策略会命中谁"。
    idleDays.value = r.policy.thresholdDays;
  } catch (e) {
    Message.error(`闲置治理策略读取失败：${failReason(e)}`);
  }
}

async function saveIdlePolicy() {
  idleSaving.value = true;
  try {
    await api('/users/idle/policy', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ thresholdDays: idlePolicy.thresholdDays, autoLock: idlePolicy.autoLock })
    });
    Message.success(idlePolicy.autoLock
      ? `策略已保存：超过 ${idlePolicy.thresholdDays} 天未登录即判闲置，后台将自动锁定（不含管理员账号）`
      : `策略已保存：超过 ${idlePolicy.thresholdDays} 天未登录即判闲置，仅识别不自动锁定`);
    await loadIdlePolicy();
  } catch (e) {
    Message.error(`闲置治理策略保存失败：${failReason(e)}`);
    await loadIdlePolicy(); // 回读，避免界面上留着一个其实没保存成功的值
  } finally { idleSaving.value = false; }
}

async function loadIdle() {
  idleLoading.value = true;
  try {
    const r = await api<{ days: number; accounts: IdleAccount[] }>(`/users/idle?days=${idleDays.value}`);
    idleList.value = r.accounts ?? [];
    // 默认勾选非管理员（管理员目标需要更高权限且更该逐个斟酌，不进默认选集）
    idleSel.value = idleList.value.filter((a) => !a.isAdmin).map((a) => a.id);
    idleQueried.value = true;
  } catch (e) { Message.error(`闲置账号识别失败：${failReason(e)}`); }
  finally { idleLoading.value = false; }
}

async function lockIdle() {
  idleLocking.value = true;
  try {
    const r = await api<{ locked: string[]; skipped: { account?: string; reason: string }[] }>(
      '/users/idle/lock', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: idleSel.value })
      });
    const n = r.locked?.length ?? 0;
    if (r.skipped?.length) {
      Message.warning(`已锁定 ${n} 个；${r.skipped.length} 个跳过：${r.skipped.map((s2) => `${s2.account ?? '?'}（${s2.reason}）`).join('、')}`);
    } else {
      Message.success(`已锁定 ${n} 个闲置账号（数据面同步撤窗断隧道）`);
    }
    await loadIdle();
    await load(); // 目录列表状态同步刷新
  } catch (e) { Message.error(`批量锁定失败：${failReason(e)}`); }
  finally { idleLocking.value = false; }
}

/* ── 批量导入导出 ──
 * 导出走原生 fetch 拿 blob：后端回的是 CSV 附件，而 api() 封装只吃 JSON（与 Audit.vue 同款）。
 * 导入把文件读成文本直接 POST（请求体就是 CSV 原文），响应是逐行结果 JSON，可以走 api()。
 */
const DEFAULT_PW = 'baidi@123';
// 与后端 userImportMaxRows / userImportMaxBytes 对齐。写在这里只为**提前**告知用户，
// 真正的闸在服务端——前端这份对不上也只是提示文案不准，不会放大导入量。
const IMP_MAX_ROWS = 500;
const IMP_MAX_KB = 1024;

const exporting = ref(false);
async function exportUsers() {
  exporting.value = true;
  try {
    const res = await fetch('/api/v1/users/export', { headers: { Authorization: `Bearer ${getToken()}` } });
    if (!res.ok) throw new Error(String(res.status));
    const blob = await res.blob();
    // 文件名跟随后端 Content-Disposition（带导出日期），解析不到才兜底
    const cd = res.headers.get('Content-Disposition') ?? '';
    const name = /filename="([^"]+)"/.exec(cd)?.[1] ?? `baidi-users-${new Date().toISOString().slice(0, 10)}.csv`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
    Message.success(`已导出 ${name}（不含口令哈希）`);
  } catch (e) {
    const msg = String((e as Error)?.message ?? '');
    Message.error(msg === '403'
      ? '权限不足：导出用户台账需要「安全策略」权限'
      : '导出失败：请检查权限或后端连接');
  } finally { exporting.value = false; }
}

const impOpen = ref(false);
const importing = ref(false);
const impFileEl = ref<HTMLInputElement | null>(null);
const impFileName = ref('');
const impFileSize = ref(0);
const impText = ref('');
const impResult = ref<UserImportResp | null>(null);

function openImport() {
  impOpen.value = true;
  impFileName.value = ''; impFileSize.value = 0; impText.value = '';
  impResult.value = null;
  if (impFileEl.value) impFileEl.value.value = '';
}

async function onPickImportFile(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0];
  impResult.value = null;
  if (!f) { impFileName.value = ''; impText.value = ''; return; }
  impFileName.value = f.name;
  impFileSize.value = f.size;
  // 读成文本即可：后端按 UTF-8 解析并自己剥 BOM（Excel 存的 CSV 一定带 BOM）。
  impText.value = await f.text();
}

/** 下载导入模板：只含后端认得的列。
 *  导出的台账带「角色/管理员角色/状态」三列会被导入侧整份拒收，所以模板必须单独给一份，
 *  而不是让人拿导出件去试错。 */
function downloadTemplate() {
  // ★必须带「组织ID」列：组织树里同名部门是常态（不同上级下各有一个「研发部」），
  // 后端遇到重名会如实报「有 2 个同名部门，请改用组织ID列指明」——而模板里没有这列的话，
  // 管理员拿着一句正确的错误提示却不知道该往哪填。留空即按名字解析。
  const csv = '﻿账号,姓名,组织,组织ID,用户组,邮箱,初始口令\n'
    + 'qian.qi,钱七,研发部,,,qian.qi@example.com,\n';
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
  const a = document.createElement('a');
  a.href = url; a.download = 'baidi-users-import-template.csv'; a.click();
  URL.revokeObjectURL(url);
}

async function doImport() {
  if (!impText.value) { Message.warning('请先选择 CSV 文件'); return; }
  importing.value = true;
  try {
    const r = await api<UserImportResp>('/users/import', {
      method: 'POST', headers: { 'Content-Type': 'text/csv; charset=utf-8' }, body: impText.value
    });
    impResult.value = r;
    if (r.failed.length) {
      Message.warning(`导入完成：成功 ${r.created.length} 条、失败 ${r.failed.length} 条（逐行原因见下方）`);
    } else {
      Message.success(`导入完成：${r.created.length} 条账号已创建，均已置首登强制改密`);
    }
    await load(); // 成功的那些立刻出现在目录里
  } catch (e) {
    // 后端的拒收理由（含角色列 / 超上限 / 缺必填列）是唯一能指导下一步的信息，
    // 用 Modal 留在屏幕上，别被 3 秒的 toast 带走。
    Modal.warning({ title: '导入未执行', content: failReason(e) });
  } finally { importing.value = false; }
}

/** 管理员清除用户的第二因子（丢认证器的 helpdesk 通道）：下次登录回到口令单因素，
 *  须本人重新注册。目标是管理员时后端把门槛抬到 admins 权（与重置口令同一道收口）。 */
const MFA_KINDS = {
  totp: { label: 'TOTP', path: 'totp', note: '该用户的动态口令认证器绑定会被清除。' },
  passkey: { label: 'passkey', path: 'passkeys', note: '该用户已注册的**全部** passkey 都会被清除。' }
} as const;

/** ★清二因子是**削弱**目标账号防护的方向，且不可撤销（绑定没了就得本人重新注册），
 *  必须二次确认——同一屏的「禁用账号」都要确认，这两个更该。 */
function askResetMfa(kind: keyof typeof MFA_KINDS) {
  if (!sel.value) return;
  const k = MFA_KINDS[kind];
  const name = sel.value.name;
  Modal.confirm({
    title: `重置 ${k.label} 二次认证`,
    content: `确认清除「${name}」的 ${k.label} 绑定？${k.note}` +
      `该账号下次登录将回到**口令单因素**，直到本人重新注册。此操作不可撤销。`,
    okText: '确认重置', cancelText: '取消', okButtonProps: { status: 'danger' },
    onOk: () => resetMfa(kind)
  });
}

async function resetMfa(kind: keyof typeof MFA_KINDS) {
  if (!sel.value) return;
  const k = MFA_KINDS[kind];
  try {
    // 两个端点的应答形状不同：TOTP 回 bool，passkey 回清掉的条数。
    const r = await api<{ ok: boolean; removed: boolean | number }>(
      `/users/${sel.value.id}/${k.path}`, { method: 'DELETE' });
    const n = typeof r.removed === 'number' ? r.removed : (r.removed ? 1 : 0);
    if (n > 0) Message.success(`已清除「${sel.value.name}」的 ${k.label}（${n} 项），下次登录回到口令单因素`);
    else Message.info(`「${sel.value.name}」未注册 ${k.label}，无需重置`);
  } catch (e) {
    Message.error(`${k.label} 重置失败：${failReason(e)}`);
  }
}

onMounted(load);
</script>

<style scoped>
/* 闲置治理策略区 */
.bd-idlepol { border: 1px solid var(--bd-border); border-radius: 9px; padding: 12px 14px; margin-bottom: 14px; background: var(--bd-fill-1); }
.bd-idlepol__h { display: flex; align-items: center; gap: 7px; font-size: 13px; font-weight: 600; color: var(--bd-t1); margin-bottom: 10px; }
.bd-idlepol__h span { font-weight: 400; font-size: 11.5px; color: var(--bd-t3); }
.bd-idlepol__row { display: flex; align-items: center; gap: 9px; font-size: 12.5px; color: var(--bd-t2); }
.bd-idlepol__auto { align-items: flex-start; margin-top: 11px; cursor: pointer; }
.bd-idlepol__auto b { display: block; color: var(--bd-t1); font-weight: 500; }
.bd-idlepol__auto i { display: block; font-style: normal; font-size: 11.5px; color: var(--bd-t3); line-height: 1.75; margin-top: 3px; }
.bd-idlepol__warn {
  display: flex; gap: 7px; align-items: flex-start; margin-top: 10px; padding: 8px 10px;
  background: var(--bd-tag-gold-bg); border-radius: 7px; font-size: 11.5px; color: var(--bd-t2); line-height: 1.75;
}
.bd-idlepol__warn > :first-child { color: var(--bd-warning); flex: none; margin-top: 2px; }
.bd-idlepol__dirty { font-size: 11.5px; color: var(--bd-warning); }
.bd-idle__preview { margin-top: 8px; font-size: 11.5px; color: var(--bd-warning); line-height: 1.7; }

.bd-tabs { display: flex; gap: 4px; margin-bottom: 14px; }
.bd-tab { display: flex; align-items: center; gap: 7px; font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }
.bd-tab em { font-style: normal; font-size: 11px; color: var(--bd-t3); }
.bd-tab.on em { color: var(--bd-primary); }

.bd-sync { display: flex; align-items: center; gap: 10px; font-size: 12.5px; color: var(--bd-t2); background: var(--bd-tag-blue-bg); border: 1px solid var(--bd-primary-b); border-radius: 8px; padding: 10px 14px; margin-bottom: 14px; }
.bd-sync__ic { color: var(--bd-primary); font-size: 16px; }

.bd-agg { display: flex; gap: 24px; padding: 0 2px 16px; }
.bd-agg__c { display: flex; align-items: center; gap: 7px; font-size: 13px; color: var(--bd-t3); }
.bd-agg__c b { font-size: 20px; font-weight: 700; color: var(--bd-t1); }
.bd-agg__dot { width: 8px; height: 8px; border-radius: 50%; }

.bd-two { display: flex; gap: 16px; align-items: flex-start; }
.bd-otree { width: 246px; flex: none; padding: 10px; }
.bd-otree__empty { font-size: 12px; color: var(--bd-t3); line-height: 1.7; padding: 8px; }
.bd-seg { display: flex; gap: 4px; padding: 2px; margin-bottom: 8px; background: var(--bd-fill-1); border-radius: 7px; }
.bd-seg__b { flex: 1; height: 28px; border: none; background: transparent; border-radius: 5px; cursor: pointer; font-size: 12.5px; color: var(--bd-t2); }
.bd-seg__b.on { background: var(--bd-bg-1, #fff); color: var(--bd-primary); font-weight: 600; box-shadow: 0 1px 3px rgba(0, 0, 0, .07); }

.bd-onode-row { position: relative; }
/* hover 只是增强：选中行常驻显示，键盘 Tab 到行内任一按钮（含节点本身）也显示。
   少了后两条，触屏与键盘用户就永远看不到这三个操作。 */
.bd-onode-row:hover .bd-onode__acts,
.bd-onode-row:focus-within .bd-onode__acts,
.bd-onode-row.sel .bd-onode__acts { display: flex; }
.bd-onode { width: 100%; display: flex; align-items: center; gap: 8px; height: 36px; padding-right: 10px; border: none; background: transparent; border-radius: 7px; cursor: pointer; font-size: 13px; color: var(--bd-t2); }
.bd-onode:hover { background: var(--bd-fill-2); }
.bd-onode.on { background: var(--bd-primary-1); color: var(--bd-primary); font-weight: 500; }
.bd-onode--add { color: var(--bd-primary); padding-left: 10px; gap: 6px; margin-top: 4px; }
.bd-onode__ic { font-size: 15px; flex: none; }
.bd-onode__t { flex: 1; text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bd-onode__n { font-size: 11px; color: var(--bd-t3); }
.bd-onode__acts { display: none; position: absolute; right: 6px; top: 0; height: 36px; align-items: center; gap: 2px; background: var(--bd-fill-2); padding-left: 8px; border-radius: 0 7px 7px 0; }
.bd-onode-row.sel .bd-onode__acts { background: var(--bd-primary-1); }
/* 选中行的操作面板是**常驻**的（.sel），而它绝对定位、背景不透明，正好压在行尾的成员数上：
   被选中的那个部门/用户组的人数会从此永远看不见。给节点按钮让出面板那点宽度
   （8 + 22×3 + 2×2 + right 6 ≈ 84px），计数就落在面板左侧仍然可读。
   hover / focus-within 不加这段：那两种是瞬时状态，加上去反而让计数左右跳。 */
.bd-onode-row.sel .bd-onode { padding-right: 86px; }
.bd-onode__act { display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; padding: 0; border: none; background: transparent; border-radius: 4px; font-size: 13px; color: var(--bd-t3); cursor: pointer; }
.bd-onode__act:hover { color: var(--bd-primary); background: var(--bd-bg-1, #fff); }
.bd-onode__act--danger:hover { color: var(--bd-danger); }
.bd-onode__act:focus-visible, .bd-iconbtn:focus-visible, .bd-onode:focus-visible, .bd-seg__b:focus-visible { outline: 2px solid var(--bd-primary); outline-offset: 1px; }

/* 常驻操作条 */
.bd-otree__bar { display: flex; align-items: center; gap: 2px; padding: 3px 4px 3px 9px; margin-bottom: 6px; background: var(--bd-fill-1); border-radius: 7px; }
.bd-otree__cur { flex: 1; min-width: 0; font-size: 12px; color: var(--bd-t2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bd-otree__tip { font-size: 11.5px; color: var(--bd-t4); line-height: 1.6; padding: 0 4px 6px; }
.bd-iconbtn { display: inline-flex; align-items: center; justify-content: center; width: 24px; height: 24px; padding: 0; border: none; background: transparent; border-radius: 5px; font-size: 14px; color: var(--bd-t2); cursor: pointer; }
.bd-iconbtn:hover:not([disabled]) { background: var(--bd-bg-1, #fff); color: var(--bd-primary); }
.bd-iconbtn--danger:hover:not([disabled]) { color: var(--bd-danger); }
.bd-iconbtn[disabled] { color: var(--bd-t4); cursor: not-allowed; }
.bd-kindtag { font-style: normal; font-size: 10px; color: #722ED1; background: #722ED114; padding: 1px 5px; border-radius: 3px; margin-left: 6px; }

.bd-toolbar__c { font-size: 12.5px; color: var(--bd-t3); }
.bd-table tr.sel { background: var(--bd-primary-1); }
.bd-rk { font-size: 10px; color: var(--bd-danger); background: var(--bd-tag-red-bg); padding: 1px 5px; border-radius: 3px; margin-left: 6px; font-weight: 600; }
.bd-umono { display: block; font-size: 11px; color: var(--bd-t3); margin-top: 3px; font-family: ui-monospace, monospace; }
.bd-tg--sm { font-size: 11px; padding: 1px 6px; margin-right: 4px; }
.bd-t4 { color: var(--bd-t4); }

/* 抽屉 */
.bd-ud__head { display: flex; align-items: center; gap: 14px; padding-bottom: 18px; border-bottom: 1px solid var(--bd-fill-2); }
.bd-ud__name { font-size: 17px; font-weight: 700; display: flex; align-items: center; }
.bd-ud__acct { font-size: 12px; color: var(--bd-t3); margin-top: 3px; }
.bd-riskwhy { display: block; font-size: 11px; color: var(--bd-t3); margin-top: 4px; line-height: 1.6; font-weight: 400; }
.bd-ud__sec { font-size: 13px; font-weight: 600; margin: 20px 0 12px; }
.bd-life { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
.bd-life__step { display: flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--bd-t4); }
.bd-life__dot { width: 8px; height: 8px; border-radius: 50%; background: var(--bd-t4); }
.bd-life__step.on { color: var(--bd-t1); font-weight: 600; }
.bd-life__step.on .bd-life__dot { background: var(--bd-primary); box-shadow: 0 0 0 3px var(--bd-primary-1); }
.bd-life__arr { color: var(--bd-t4); font-size: 13px; margin: 0 4px; }
.bd-kv { display: flex; align-items: center; justify-content: space-between; padding: 9px 0; border-bottom: 1px solid var(--bd-fill-1); font-size: 13px; }
.bd-kv span { color: var(--bd-t3); }
.bd-kv b { font-weight: 500; color: var(--bd-t1); }
.bd-roles { display: flex; gap: 8px; flex-wrap: wrap; }
.bd-ud__acts { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 24px; }

.bd-uform__hint { font-size: 12.5px; color: var(--bd-t3); line-height: 1.6; margin-bottom: 16px; }
.bd-uform__note {
  display: flex; gap: 8px; align-items: flex-start; padding: 9px 11px; margin-bottom: 16px;
  background: var(--bd-fill-1); border-radius: 7px; font-size: 12px; color: var(--bd-t2); line-height: 1.7;
}
.bd-uform__d { display: block; font-size: 11px; color: var(--bd-t3); margin-top: 5px; line-height: 1.7; }
.bd-uform__err {
  display: flex; gap: 6px; align-items: flex-start; margin-top: 12px; padding: 8px 10px;
  background: var(--bd-tag-red-bg); color: var(--bd-danger); border-radius: 7px; font-size: 12px; line-height: 1.65;
}
.bd-delwarn {
  display: flex; gap: 9px; align-items: flex-start; padding: 11px 13px; margin-bottom: 12px;
  background: var(--bd-tag-red-bg); border: 1px solid #FFCDC7; border-radius: 8px;
  font-size: 12.5px; color: var(--bd-t1); line-height: 1.8;
}
.bd-delwarn > :first-child { color: var(--bd-danger); flex: none; margin-top: 2px; }
.bd-delnote { font-size: 12.5px; color: var(--bd-t2); line-height: 1.85; }
.bd-uform__f { margin-bottom: 16px; }
.bd-uform__f > label { display: block; font-size: 13px; font-weight: 500; color: var(--bd-t1); margin-bottom: 7px; }
.bd-uform__f :deep(.arco-input-wrapper), .bd-uform__f :deep(.arco-select-view) { width: 100%; }
.bd-uform__foot { display: flex; justify-content: flex-end; gap: 10px; margin-top: 22px; }
.bd-uform__foot .bd-btn[disabled] { opacity: .6; cursor: not-allowed; }
.bd-kindtag--ext { color: #0FC6C2; background: #0FC6C214; }

/* 闲置治理弹窗 */
.bd-idle__bar { display: flex; align-items: center; gap: 8px; margin: 12px 0; font-size: 13px; color: var(--color-text-2); }
.bd-idle__cnt { font-size: 12px; color: var(--color-text-3); }
.bd-idle__empty { padding: 22px 0; text-align: center; font-size: 13px; color: var(--color-text-3); }
.bd-idle__list { max-height: 320px; overflow: auto; border: 1px solid var(--color-border-2); border-radius: 8px; padding: 4px 0; }
.bd-idle__row { display: flex; align-items: center; gap: 10px; padding: 7px 12px; cursor: pointer; font-size: 13px; }
.bd-idle__row:hover { background: var(--color-fill-1); }
.bd-idle__acct { font-weight: 600; color: var(--color-text-1); }
.bd-idle__name { color: var(--color-text-2); }
.bd-idle__days { margin-left: auto; font-size: 12px; color: var(--color-text-3); white-space: nowrap; }
/* 批量导入弹窗 */
.bd-imp__warn { display: flex; gap: 8px; align-items: flex-start; font-size: 12.5px; line-height: 1.7; color: var(--bd-t2); background: var(--bd-tag-gold-bg); border: 1px solid var(--bd-warning); border-radius: 8px; padding: 10px 12px; margin-bottom: 14px; }
.bd-imp__warnic { color: var(--bd-warning); font-size: 15px; flex: none; margin-top: 2px; }
.bd-imp__bar { display: flex; align-items: center; gap: 10px; font-size: 13px; }
.bd-imp__file { margin-top: 8px; font-size: 12.5px; color: var(--bd-t3); }
.bd-imp__res { margin-top: 16px; border-top: 1px solid var(--bd-fill-2); padding-top: 14px; }
.bd-imp__sum { display: flex; align-items: center; gap: 8px; }
.bd-imp__total { font-size: 12px; color: var(--bd-t3); }
.bd-imp__ign { margin-top: 10px; font-size: 12.5px; color: var(--bd-warning); }
.bd-imp__list { margin-top: 10px; max-height: 240px; overflow: auto; border: 1px solid var(--bd-fill-2); border-radius: 8px; }
.bd-imp__row { display: flex; align-items: baseline; gap: 10px; padding: 7px 12px; font-size: 12.5px; border-bottom: 1px solid var(--bd-fill-1); }
.bd-imp__row:last-child { border-bottom: none; }
.bd-imp__rowno { flex: none; width: 66px; color: var(--bd-t3); }
.bd-imp__reason { margin-left: auto; color: var(--bd-danger, #F53F3F); text-align: right; }
.bd-imp__ok { margin-top: 10px; font-size: 12.5px; color: var(--bd-t3); line-height: 1.7; word-break: break-all; }

.bd-btn--danger2 { background: var(--bd-danger, #F53F3F); }
.bd-btn--danger2:hover:not(:disabled) { background: #d92b2b; }
.bd-btn--danger2:disabled { opacity: .5; cursor: not-allowed; }
</style>
