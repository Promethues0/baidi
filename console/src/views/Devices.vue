<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">终端管理</div>
        <div class="bd-page__sub">授信终端台账 · 硬件指纹准入 · 设备生命周期</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '未连控制中心' }}</a-tag>
        <button class="bd-btn bd-btn--ghost" @click="openSettings"><icon-settings />准入设置</button>
      </div>
    </div>

    <!-- 未连后端：如实说，不编造设备。
         「哪些终端被允许接入」是安全声明，不是装饰性数据——降级演示会让人以为设备纳管正在运行。 -->
    <div v-if="!live" class="bd-card bd-offline">
      <icon-exclamation-circle-fill />
      <div>
        <div class="bd-offline__t">未连接控制中心，本页不展示任何演示数据</div>
        <div class="bd-offline__d">
          终端授信台账决定谁的哪台设备能接入，编造的清单会让人以为设备纳管正在运行。
          请确认 baidi-control 已启动（默认 :8090）后重试。
          <span v-if="loadErr" class="bd-mono">（{{ loadErr }}）</span>
        </div>
      </div>
      <button class="bd-btn bd-btn--ghost" @click="load">重试</button>
    </div>

    <template v-else>
      <!-- 准入模式横幅：观察模式下这一页的"吊销/待批准"对接入意味着什么，必须写在脸上 -->
      <div class="bd-mode" :class="settings.mode === 'strict' ? 'bd-mode--strict' : 'bd-mode--observe'">
        <icon-safe />
        <div v-if="settings.mode === 'strict'">
          <b>严格准入</b>：只有 <b>已授信</b> 的终端能取得敲门令牌。待批准 / 未登记 / 不上报指纹的终端一律拒绝接入。
        </div>
        <div v-else>
          <b>观察准入</b>（默认）：待批准与未登记的终端<b>照常接入</b>，仅记录审计；
          <b>已吊销</b>的终端两种模式下都会被拒。切到严格模式前请先把在用终端批准完。
        </div>
      </div>

      <!-- 个人资产策略横幅：只在它真的会改变判定时才出现（inherit 什么都不做，
           画一条"当前无影响"的横幅只会挤占注意力）。 -->
      <div v-if="settings.personalPolicy !== 'inherit'" class="bd-mode bd-mode--asset">
        <icon-user />
        <div>
          <b>个人资产策略：{{ personalPolicyMeta(settings.personalPolicy).label }}</b>
          —— {{ personalPolicyMeta(settings.personalPolicy).desc }}
          判定粒度是<b>（账号，设备指纹）</b>：同一个人的<b>企业资产</b>终端不受影响；
          「企业纳管个人」按企业资产处理。
        </div>
      </div>

      <!-- Tab 切换 -->
      <div class="bd-tabs">
        <span class="bd-tab" :class="{ on: tab === 'list' }" @click="tab = 'list'">设备清单 <em>{{ devices.length }}</em></span>
        <span class="bd-tab" :class="{ on: tab === 'approval' }" @click="tab = 'approval'">
          绑定审批
          <span v-if="pendingCount" class="bd-badge">{{ pendingCount }}</span>
        </span>
      </div>

      <!-- ============ 设备清单 ============ -->
      <div v-show="tab === 'list'" class="bd-tablecard">
        <div class="bd-toolbar">
          <span class="bd-toolbar__c">
            共 {{ devices.length }} 台 · 已授信 {{ countBy('trusted') }} · 待批准 {{ countBy('pending') }} · 已吊销 {{ countBy('revoked') }}
            <template v-if="staleCount"> · 陈旧 {{ staleCount }}</template>
          </span>
          <div style="flex: 1" />
          <a-input v-model="kw" allow-clear size="small" style="width: 260px" placeholder="按账号 / 设备名 / 指纹 / 标签搜索">
            <template #prefix><icon-search /></template>
          </a-input>
          <a-select v-model="classFilter" size="small" style="width: 150px">
            <a-option value="">全部资产分类</a-option>
            <a-option value="enterprise">企业资产</a-option>
            <a-option value="personal">个人资产</a-option>
            <a-option value="managed">企业纳管个人</a-option>
          </a-select>
          <button class="bd-btn bd-btn--ghost" :disabled="exp.busy" @click="doExport">
            <icon-download />{{ exp.busy ? '导出中…' : '导出 CSV' }}
          </button>
          <button class="bd-btn bd-btn--ghost" @click="openImport"><icon-upload />批量预登记</button>
          <button class="bd-btn bd-btn--ghost" :disabled="!staleCount" @click="cleanupOpen = true">
            <icon-delete />清理陈旧（{{ staleCount }}）
          </button>
        </div>
        <table class="bd-table">
          <thead>
            <tr>
              <th>设备</th><th>归属账号</th><th>资产分类 / 标签</th><th>状态</th><th>最近合规判定</th><th>最近上报</th><th class="r">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in shown" :key="d.id">
              <td>
                <div class="bd-cellname">
                  <span>
                    <b>{{ d.name }}</b>
                    <i class="bd-mono">{{ d.fingerprint }}</i>
                  </span>
                  <span class="bd-tg bd-tg--grey">{{ d.platform || '平台未知' }}</span>
                  <span v-if="d.stale" class="bd-tg" :style="tagStyle('var(--bd-warning)')">陈旧</span>
                </div>
                <div v-if="d.os || d.clientVersion" class="bd-dmono">{{ d.os }} · 客户端 {{ d.clientVersion || '—' }}</div>
              </td>
              <td>{{ d.account }}</td>
              <td>
                <span class="bd-tg" :style="tagStyle(classMeta(d.assetClass).color)">{{ classMeta(d.assetClass).label }}</span>
                <!-- 当前策略下这台机器会被怎么处置，写在它旁边。分类本身不说明后果：
                     同一个「个人资产」在 inherit 下什么都没发生、在 deny 下等于连不上。 -->
                <div v-if="assetEffect(d)" class="bd-sub bd-sub--warn">{{ assetEffect(d) }}</div>
                <div v-if="d.tags?.length" class="bd-tagrow">
                  <span v-for="t in d.tags" :key="t" class="bd-tg bd-tg--grey">{{ t }}</span>
                </div>
              </td>
              <td>
                <span class="bd-tg" :style="tagStyle(statusMeta(d.status).color)">{{ statusMeta(d.status).label }}</span>
                <div v-if="d.status === 'trusted'" class="bd-sub">{{ approverText(d) }}</div>
                <div v-else-if="d.status === 'revoked' && d.revokeReason" class="bd-sub">{{ d.revokeReason }}</div>
              </td>
              <td>
                <!-- ★空判定必须显示「从未上报」而不是绿色的"合规"：
                     把缺报画成合规是本项目在 posture 三态上早就写死的纪律。 -->
                <span v-if="!d.verdict" class="bd-sub">从未上报</span>
                <span v-else class="bd-tg" :style="tagStyle(verdictMeta(d.verdict).color)">{{ verdictMeta(d.verdict).label }}</span>
              </td>
              <td class="bd-mono bd-sub">{{ fmtTime(d.lastSeen) }}</td>
              <td class="r">
                <span v-if="d.status !== 'trusted'" class="bd-link" @click="doApprove(d)">批准</span>
                <span v-if="d.status !== 'revoked'" class="bd-link bd-link--danger" style="margin-left: 14px" @click="askRevoke(d)">吊销</span>
                <span class="bd-link bd-link--grey" style="margin-left: 14px" @click="askAsset(d)">分类/标签</span>
                <span class="bd-link bd-link--grey" style="margin-left: 14px" @click="askRename(d)">重命名</span>
                <span class="bd-link bd-link--grey" style="margin-left: 14px" @click="askDelete(d)">删除</span>
              </td>
            </tr>
            <tr v-if="!shown.length">
              <td colspan="7" class="bd-sub" style="padding: 28px; text-align: center">
                {{ devices.length ? '没有匹配的设备' : '尚无终端登记：终端首次上报环境报告（posture）时自动入账' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- ============ 绑定审批（P9 时间线）============ -->
      <div v-show="tab === 'approval'" class="bd-two">
        <div class="bd-card bd-aplist">
          <div class="bd-aplist__h">待审批申请 <em>{{ approvals.length }}</em></div>
          <div v-if="!approvals.length" class="bd-empty">
            <icon-check-circle-fill />当前没有待处理的绑定申请
          </div>
          <button v-for="a in approvals" :key="a.id" class="bd-apitem" :class="{ on: a.id === selId }" @click="selId = a.id">
            <div class="bd-apitem__row">
              <span class="bd-apitem__user">{{ a.user }}</span>
              <span class="bd-apitem__time">{{ a.submittedAt }}</span>
            </div>
            <div class="bd-apitem__dev">{{ a.device }}</div>
          </button>
        </div>

        <div class="bd-card bd-apdetail">
          <template v-if="cur">
            <div class="bd-apd__head">
              <div>
                <div class="bd-apd__dev">{{ cur.device }}</div>
                <div class="bd-apd__fp bd-mono">{{ cur.fingerprint }}</div>
              </div>
              <span class="bd-tg" :style="tagStyle('var(--bd-warning)')">待审批</span>
            </div>

            <div class="bd-apd__meta">
              <div class="bd-kv"><span>申请账号</span><b>{{ cur.user }}</b></div>
              <div class="bd-kv"><span>提交时间</span><b class="bd-mono">{{ cur.submittedAt }}</b></div>
              <div class="bd-kv"><span>说明</span><b>{{ cur.reason }}</b></div>
            </div>

            <div class="bd-apd__sec">绑定与风险时间线</div>
            <a-timeline class="bd-tl">
              <a-timeline-item
                v-for="(e, i) in cur.timeline"
                :key="i"
                :dot-color="dotColor(e.kind)"
                :line-type="i === cur.timeline.length - 1 ? 'dotted' : 'solid'"
              >
                <div class="bd-tl__row">
                  <span class="bd-tl__title">{{ e.title }}</span>
                  <span class="bd-tl__time bd-mono">{{ e.time }}</span>
                </div>
                <div class="bd-tl__detail">{{ e.detail }}</div>
              </a-timeline-item>
            </a-timeline>

            <div class="bd-apd__acts">
              <button class="bd-btn" @click="decide('approved', '')"><icon-check />通过绑定（置为授信）</button>
              <button class="bd-btn bd-btn--ghost bd-btn--danger" @click="rejectOpen = true"><icon-close />驳回</button>
            </div>
          </template>
          <div v-else class="bd-empty bd-empty--lg">
            <icon-info-circle />请从左侧选择一条待审批申请查看详情
          </div>
        </div>
      </div>
    </template>

    <!-- 准入设置 -->
    <a-modal v-model:visible="setOpen" title="授信终端准入设置" :width="540" @ok="saveSettings" ok-text="保存" cancel-text="取消">
      <div class="bd-setrow">
        <div class="bd-setrow__main">
          <div class="bd-setrow__label">准入模式</div>
          <div class="bd-setrow__desc">
            严格模式下，非授信终端取不到敲门令牌，因而**连不进数据面**。切换前请确认在用终端都已批准。
          </div>
        </div>
        <a-radio-group v-model="form.mode" type="button" size="small">
          <a-radio value="observe">观察</a-radio>
          <a-radio value="strict">严格</a-radio>
        </a-radio-group>
      </div>
      <div class="bd-setrow">
        <div class="bd-setrow__main">
          <div class="bd-setrow__label">个人资产准入策略</div>
          <div class="bd-setrow__desc">
            只约束标为<b>个人资产</b>的终端（「企业纳管个人」按企业资产处理）。
            判定落在敲门令牌闸上，粒度是<b>（账号，设备指纹）</b>——
            同一个人的企业机<b>不受影响</b>，不会因为他有一台个人机而被一起限制。
            <br><b>跟随全局</b>：与企业资产一视同仁（默认，不改变任何现有行为）；
            <b>按严格判</b>：个人资产未批准即拒，即使全局是观察模式；
            <b>一律拒绝</b>：个人资产全部拒绝接入，<b>含已批准的</b>。
          </div>
        </div>
        <a-radio-group v-model="form.personalPolicy" type="button" size="small">
          <a-radio value="inherit">跟随全局</a-radio>
          <a-radio value="strict">按严格判</a-radio>
          <a-radio value="deny">一律拒绝</a-radio>
        </a-radio-group>
      </div>
      <div class="bd-setrow">
        <div class="bd-setrow__main">
          <div class="bd-setrow__label">绑定方式</div>
          <div class="bd-setrow__desc">终端首次上报环境报告时，自动置为授信，或先入待批准队列由管理员核验。</div>
        </div>
        <a-radio-group v-model="form.bindMethod" type="button" size="small">
          <a-radio value="auto">自动绑定</a-radio>
          <a-radio value="approval">审批绑定</a-radio>
        </a-radio-group>
      </div>
      <div class="bd-setrow">
        <div class="bd-setrow__main">
          <div class="bd-setrow__label">陈旧阈值（天）</div>
          <div class="bd-setrow__desc">超过这么多天没有上报终端环境即标记为陈旧，可批量清理（已吊销设备不在清理范围内）。</div>
        </div>
        <a-input-number v-model="form.staleDays" :min="1" :max="3650" size="small" style="width: 110px" />
      </div>
      <div class="bd-setrow">
        <div class="bd-setrow__main">
          <div class="bd-setrow__label">每账号设备上限</div>
          <!-- 置灰而不是给一个改了不生效的输入框：上限判定写死在原子 SQL 里。 -->
          <div class="bd-setrow__desc">内置上限，本版本不可配置（判定与写入在同一条原子语句内完成）。</div>
        </div>
        <a-input-number :model-value="settings.perUserQuota" disabled size="small" style="width: 110px" />
      </div>
    </a-modal>

    <!-- 吊销确认：影响面用后端下发的同一份文本，界面与实际行为不许各写一套 -->
    <a-modal v-model:visible="revokeOpen" title="吊销授信终端" :width="560" @ok="doRevoke" ok-text="确认吊销" cancel-text="取消">
      <div class="bd-reject">
        <icon-exclamation-circle-fill class="bd-reject__ic" />
        <div>
          将吊销 <b>{{ target?.account }}</b> 的终端 <b>「{{ target?.name }}」</b>
          （<span class="bd-mono">{{ target?.fingerprint }}</span>）。
        </div>
      </div>
      <div class="bd-blast">
        <div class="bd-blast__t">影响面（请读完再确认）</div>
        <div class="bd-blast__d">{{ blastRadius }}</div>
      </div>
      <a-textarea v-model="revokeReason" placeholder="吊销理由（会落审计，并在该终端再次尝试接入时作为拒绝原因）" :max-length="200" allow-clear :auto-size="{ minRows: 2, maxRows: 4 }" />
    </a-modal>

    <!-- 驳回理由 -->
    <a-modal v-model:visible="rejectOpen" title="驳回绑定申请" :width="560" @ok="reject" ok-text="确认驳回" cancel-text="取消">
      <div class="bd-reject">
        <icon-exclamation-circle-fill class="bd-reject__ic" />
        <div>将驳回 <b>{{ cur?.user }}</b> 对 <b>「{{ cur?.device }}」</b> 的绑定申请，该终端会被置为<b>已吊销</b>。</div>
      </div>
      <div class="bd-blast">
        <div class="bd-blast__t">影响面（请读完再确认）</div>
        <div class="bd-blast__d">{{ blastRadius }}</div>
      </div>
      <a-textarea v-model="rejectReason" placeholder="例如：指纹与历史记录不符，疑似设备克隆，请联系 IT 现场核验" :max-length="200" allow-clear :auto-size="{ minRows: 2, maxRows: 4 }" />
    </a-modal>

    <!-- 重命名 -->
    <a-modal v-model:visible="renameOpen" title="重命名终端" :width="460" @ok="doRename" ok-text="保存" cancel-text="取消">
      <a-input v-model="renameVal" :max-length="64" allow-clear placeholder="例如：财务-王芳-MBP" />
    </a-modal>

    <!-- 资产分类与标签 -->
    <a-modal v-model:visible="assetOpen" title="终端资产分类与标签" :width="580" @ok="doSetAsset" ok-text="保存" cancel-text="取消">
      <div class="bd-reject" style="margin-bottom: 10px">
        <div>
          <b>{{ target?.account }}</b> 的终端 <b>「{{ target?.name }}」</b>
          （<span class="bd-mono">{{ target?.fingerprint }}</span>）
        </div>
      </div>
      <div class="bd-setrow">
        <div class="bd-setrow__main">
          <div class="bd-setrow__label">资产分类<span class="bd-real">真实判据</span></div>
          <div class="bd-setrow__desc">
            分类由<b>管理员标注</b>——白帝不自动识别设备归属（没有 MDM / 资产系统对接，
            硬件指纹只能说明"是同一台机器"）。标错就是标错。
            <br>「企业纳管个人」= 自带但已纳管，<b>按企业资产处理</b>，不受个人资产策略约束。
          </div>
        </div>
        <a-radio-group v-model="assetForm.assetClass" direction="vertical" size="small">
          <a-radio value="enterprise">企业资产</a-radio>
          <a-radio value="personal">个人资产</a-radio>
          <a-radio value="managed">企业纳管个人</a-radio>
        </a-radio-group>
      </div>
      <!-- 改成个人资产时，当前策略下的**实际后果**要在保存之前就说清楚。 -->
      <div v-if="assetWarn" class="bd-warnbox" :class="{ 'bd-warnbox--red': settings.personalPolicy === 'deny' }">
        <icon-exclamation-circle-fill />
        <div>{{ assetWarn }}</div>
      </div>
      <div class="bd-setrow" style="display: block">
        <div class="bd-setrow__label">标签<span class="bd-fake">仅台账属性，不参与判定</span></div>
        <div class="bd-setrow__desc" style="margin-bottom: 8px">
          用于筛选、导出与资产盘点。<b>标签没有任何执行方</b>：不影响准入、不影响授权、
          不影响风险评分——给一台机器打上「禁止外网」不会限制它任何东西。
          要让某个维度真能控制访问，得给它做一个执行点（像资产分类那样落在准入闸上）。
          <br>单台最多 {{ MAX_TAGS }} 个、每个 ≤{{ MAX_TAG_LEN }} 字，超出部分保存时会被截掉。
        </div>
        <a-input-tag v-model="assetForm.tags" allow-clear :max-tag-count="MAX_TAGS" placeholder="回车添加，例如：研发部、外包、试点" />
      </div>
    </a-modal>

    <!-- 删除确认 -->
    <a-modal v-model:visible="deleteOpen" title="删除终端登记" :width="540" @ok="doDelete" ok-text="确认删除" cancel-text="取消">
      <div class="bd-reject">
        <icon-exclamation-circle-fill class="bd-reject__ic" />
        <div>
          将删除 <b>{{ target?.account }}</b> 的终端 <b>「{{ target?.name }}」</b> 及其终端环境报告，并释放一个设备名额。
          <template v-if="target?.status === 'revoked'">
            <br><b>该终端当前为已吊销状态</b>：删除记录后，同一指纹再次上报会作为新设备重新登记，吊销将不再生效。
          </template>
        </div>
      </div>
    </a-modal>

    <!-- 批量预登记（导入 CSV）。
         ★上传前就把「预登记 ≠ 能连上」写在脸上，而不是等导完再补一句：
         管理员是在点「导入」之前决定要不要切 strict 的。 -->
    <a-modal v-model:visible="imp.open" title="批量预登记终端（导入 CSV）" :width="640" :footer="false" unmount-on-close>
      <template v-if="!imp.result">
        <div class="bd-wdesc">
          从资产系统导出「账号 + 硬件指纹」清单，一次性完成预授信——这是切换到<b>严格准入</b>之前
          把在用终端纳管完的唯一批量路径（否则只能等每台终端自己上报、再逐台批准）。
        </div>
        <div class="bd-blast">
          <div class="bd-blast__t">格式（第一行必须是表头，认列名不认列序）</div>
          <div class="bd-blast__d">
            必需列：<b>账号</b>（account/user）、<b>指纹</b>（fingerprint/device）；
            可选列：<b>设备名</b>、<b>平台</b>（Windows|macOS|Linux）、<b>状态</b>（待批准 / 已授信，
            <b>留空按「待批准」处理</b>）、<b>资产分类</b>（企业资产 / 个人资产 / 企业纳管个人，
            <b>留空按「企业资产」</b>）、<b>标签</b>（分号分隔）。「已吊销」不接受——那是对既有设备的处置动作。
            <br>单批上限 <b>{{ MAX_ROWS }}</b> 行 / <b>{{ MAX_KIB }} KiB</b>，超限整批拒绝（不会导一半）。
            <br>「导出 CSV」出来的文件可直接当模板：改完再导入，<b>已登记的行会被逐行跳过</b>，
            导入<b>永不改写</b>既有设备的状态（否则一次上传就能静默撤销一条吊销）。
          </div>
        </div>
        <div class="bd-warnbox">
          <icon-exclamation-circle-fill />
          <div>
            <b>预登记不等于这台终端就能连上。</b>它只写设备台账，不产生终端环境报告（posture）：
            若控制面开着 <span class="bd-mono">BAIDI_POSTURE_ENFORCE=strict</span>（缺报即拒），
            这些终端在用客户端真正上报一次环境之前，敲门令牌<b>依然会被拒</b>——
            设备闸与终端合规闸各判各的。导入完成后回执里会显示当前实际取值。
          </div>
        </div>
        <input ref="fileEl" type="file" accept=".csv,text/csv,text/plain" style="display: none" @change="onPick">
        <div class="bd-picker">
          <button class="bd-btn bd-btn--ghost" @click="fileEl?.click()"><icon-folder />选择 CSV 文件</button>
          <span v-if="imp.name" class="bd-sub">{{ imp.name }} · 约 {{ imp.rows }} 行数据</span>
          <span v-else class="bd-sub">尚未选择文件</span>
          <div style="flex: 1" />
          <button class="bd-btn" :disabled="!imp.text || imp.busy" @click="doImport">
            <icon-upload />{{ imp.busy ? '导入中…' : '开始导入' }}
          </button>
        </div>
      </template>

      <!-- 回执：逐行可见。成功与跳过分列，跳过必须带行号与原话理由。 -->
      <template v-else>
        <div class="bd-impsum">
          <span class="bd-tg" :style="tagStyle('var(--bd-success)')">已预登记 {{ imp.result.imported.length }} 台</span>
          <span class="bd-tg" :style="tagStyle('var(--bd-primary)')">其中直接授信 {{ imp.result.trusted }} 台</span>
          <span v-if="imp.result.personal" class="bd-tg" :style="tagStyle('var(--bd-warning)')">
            个人资产 {{ imp.result.personal }} 台
          </span>
          <span class="bd-tg" :style="tagStyle(imp.result.skipped.length ? 'var(--bd-warning)' : 'var(--bd-t3)')">
            跳过 {{ imp.result.skipped.length }} 行
          </span>
        </div>
        <!-- 与 postureEnforce 同一条理由：在 deny 下这批个人资产导进去照样连不上，
             不说的话又是一个「台账是绿的、就是连不上」。 -->
        <div v-if="imp.result.personal && imp.result.personalPolicy && imp.result.personalPolicy !== 'inherit'"
             class="bd-warnbox" :class="{ 'bd-warnbox--red': imp.result.personalPolicy === 'deny' }">
          <icon-exclamation-circle-fill />
          <div>
            本批有 <b>{{ imp.result.personal }}</b> 台标为<b>个人资产</b>，而当前个人资产策略是
            <b>{{ personalPolicyMeta(imp.result.personalPolicy).label }}</b>：
            {{ personalPolicyMeta(imp.result.personalPolicy).desc }}
          </div>
        </div>
        <div class="bd-warnbox" :class="{ 'bd-warnbox--red': imp.result.postureEnforce === 'strict' }">
          <icon-exclamation-circle-fill />
          <div>
            <b>当前 BAIDI_POSTURE_ENFORCE = {{ imp.result.postureEnforce }}</b>
            <template v-if="imp.result.postureEnforce === 'strict'">
              ：这些终端在<b>首次成功上报终端环境之前仍连不进来</b>（缺报即拒）。
            </template>
            <template v-else>：缺报不拒，但一旦切到 strict 就会出现上面这种情况。</template>
            <div class="bd-impnote">{{ imp.result.note }}</div>
          </div>
        </div>
        <div v-if="imp.result.skipped.length" class="bd-implist">
          <div class="bd-implist__h">跳过的行（行号对得上你上传的文件）</div>
          <div v-for="s in imp.result.skipped" :key="s.line" class="bd-improw">
            <span class="bd-improw__ln bd-mono">第 {{ s.line }} 行</span>
            <span class="bd-improw__id">{{ s.account || '（无账号）' }} · <i class="bd-mono">{{ s.fingerprint || '（无指纹）' }}</i></span>
            <span class="bd-improw__why">{{ s.reason }}</span>
          </div>
        </div>
        <div v-if="imp.result.imported.length" class="bd-implist">
          <div class="bd-implist__h">已预登记</div>
          <div v-for="d in imp.result.imported" :key="d.line" class="bd-improw">
            <span class="bd-improw__ln bd-mono">第 {{ d.line }} 行</span>
            <span class="bd-improw__id">{{ d.account }} · {{ d.name }} · <i class="bd-mono">{{ d.fingerprint }}</i></span>
            <!-- 回执显示的是**落库后的实际值**（分类留空按企业资产、标签已去重截断），
                 不是 CSV 原文——省得管理员导完再去台账里逐台核对。 -->
            <span class="bd-improw__why">
              {{ d.status === 'trusted' ? '已授信' : '待批准' }} · {{ classMeta(d.assetClass).label }}
              <template v-if="d.tags?.length"> · 标签 {{ d.tags.join('、') }}</template>
            </span>
          </div>
        </div>
        <div class="bd-picker">
          <div style="flex: 1" />
          <button class="bd-btn bd-btn--ghost" @click="resetImport">再导一批</button>
          <button class="bd-btn" @click="imp.open = false">完成</button>
        </div>
      </template>
    </a-modal>

    <!-- 批量清理陈旧 -->
    <a-modal v-model:visible="cleanupOpen" title="清理陈旧终端" :width="520" @ok="doCleanup" ok-text="确认清理" cancel-text="取消">
      <div class="bd-reject">
        <icon-exclamation-circle-fill class="bd-reject__ic" />
        <div>
          将删除超过 <b>{{ settings.staleDays }}</b> 天未上报终端环境的设备（连同其环境报告）。
          <br><b>已吊销的终端不在清理范围内</b>——清掉吊销记录等于让该指纹可以重新登记，吊销会失效。
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import {
  api, getToken,
  type DeviceBundle, type Device, type TrustApproval, type DeviceTrustSetting, type DeviceImportResult,
  type AssetClass, type PersonalAssetPolicy
} from '@/lib/api';

const tab = ref<'list' | 'approval'>('list');
const live = ref(false);
const loadErr = ref('');
const setOpen = ref(false);
const rejectOpen = ref(false);
const revokeOpen = ref(false);
const renameOpen = ref(false);
const assetOpen = ref(false);
const deleteOpen = ref(false);
const cleanupOpen = ref(false);
const rejectReason = ref('');
const revokeReason = ref('');
const renameVal = ref('');
const kw = ref('');
const classFilter = ref<'' | AssetClass>('');
const target = ref<Device | null>(null);

/* 标签上限与后端 store.DeviceTagMaxCount / DeviceTagMaxRunes 同值；
   仅用于提示与前端截断，**真判定在后端**（前端的数字改了不影响落库）。 */
const MAX_TAGS = 12;
const MAX_TAG_LEN = 24;
const assetForm = reactive<{ assetClass: AssetClass; tags: string[] }>({ assetClass: 'enterprise', tags: [] });

/** 吊销影响面文案：与后端 api.deviceRevokeBlastRadius 同源（后端应答带回来后覆盖）。
 *  界面上写一套、实际做另一套是本项目最不该出现的错误，故默认文案也照实描述。 */
const DEFAULT_BLAST =
  '数据面的撤销通道按账号表达（网关只认账号，敲门令牌与放行窗里都没有设备维度），' +
  '因此吊销该终端会切断该账号在所有终端上的活跃隧道，并在 5 分钟封禁窗内拒绝其重新接入（含已授信设备）。' +
  '封禁到期后，其余已授信终端可正常接入；被吊销的这一台在严格与观察两种模式下都将被持续拒绝。';
const blastRadius = ref(DEFAULT_BLAST);

const settings = reactive<DeviceTrustSetting>({
  mode: 'observe', bindMethod: 'approval', staleDays: 30, perUserQuota: 20, personalPolicy: 'inherit'
});
const form = reactive<DeviceTrustSetting>({ ...settings });
const devices = ref<Device[]>([]);
const approvals = ref<TrustApproval[]>([]);
const selId = ref('');

const cur = computed(() => approvals.value.find((a) => a.id === selId.value) ?? null);
const pendingCount = computed(() => approvals.value.filter((a) => a.status === 'pending').length);
const staleCount = computed(() => devices.value.filter((d) => d.stale && d.status !== 'revoked').length);
const shown = computed(() => {
  const q = kw.value.trim().toLowerCase();
  return devices.value.filter((d) => {
    if (classFilter.value && (d.assetClass || 'enterprise') !== classFilter.value) return false;
    if (!q) return true;
    // 标签一并进搜索：它没有执行方，但"能筛出来"正是它存在的全部意义。
    return [d.account, d.name, d.fingerprint, d.platform, ...(d.tags ?? [])]
      .some((v) => (v || '').toLowerCase().includes(q));
  });
});

function countBy(s: Device['status']) { return devices.value.filter((d) => d.status === s).length; }

function statusMeta(s: Device['status']) {
  return {
    trusted: { label: '已授信', color: 'var(--bd-success)' },
    pending: { label: '待批准', color: 'var(--bd-warning)' },
    revoked: { label: '已吊销', color: 'var(--bd-danger)' }
  }[s];
}
function verdictMeta(v: Device['verdict']) {
  return {
    allow: { label: '合规', color: 'var(--bd-success)' },
    gray: { label: '灰度观察', color: 'var(--bd-t3)' },
    degrade: { label: '已降权', color: 'var(--bd-warning)' },
    block: { label: '不合规', color: 'var(--bd-danger)' },
    '': { label: '从未上报', color: 'var(--bd-t3)' }
  }[v] ?? { label: v, color: 'var(--bd-t3)' };
}
/** 资产分类的显示口径与后端 store.AssetClassZh 同源（导出件、审计、页面必须是同一套说法）。 */
function classMeta(c: AssetClass | undefined) {
  return {
    enterprise: { label: '企业资产', color: 'var(--bd-t3)' },
    personal: { label: '个人资产', color: 'var(--bd-warning)' },
    managed: { label: '企业纳管个人', color: 'var(--bd-primary)' }
  }[c || 'enterprise'];
}
function personalPolicyMeta(p: PersonalAssetPolicy | '') {
  return {
    inherit: { label: '跟随全局', desc: '个人资产与企业资产一视同仁，走全局准入模式。' },
    strict: { label: '按严格准入判定', desc: '个人资产未被批准为「已授信」即拒发敲门令牌，即使全局是观察模式。' },
    deny: { label: '一律拒绝接入', desc: '个人资产全部拒发敲门令牌，含已批准为「已授信」的。' },
    '': { label: '未知', desc: '' }
  }[p || 'inherit'];
}
/** 当前策略下这台设备的实际处置。分类本身不说明后果，必须在它旁边写出来。 */
function assetEffect(d: Device): string {
  if (!isPersonal(d.assetClass)) return '';
  // ★措辞与后端一致：deny 拒的是**新的敲门令牌**，不主动切断已建立的隧道
  //（要立刻切断只有「吊销」——那条走 revoked 通道，网关会 KillUser）。
  if (settings.personalPolicy === 'deny') return '按当前策略：拒发敲门令牌（含已授信）';
  if (settings.personalPolicy === 'strict') {
    return d.status === 'trusted' ? '按当前策略：需保持已授信才可接入' : '按当前策略：未批准，拒绝接入';
  }
  return '';
}
/** managed 按企业资产处理——与后端 store.IsPersonalAsset 同一条判据。 */
function isPersonal(c: AssetClass | undefined) { return (c || 'enterprise') === 'personal'; }

function tagStyle(color: string) { return { color, background: `color-mix(in srgb, ${color} 12%, #fff)` }; }
type ApprovalKind = TrustApproval['timeline'][number]['kind'];
function dotColor(kind: ApprovalKind): string {
  return { submit: '#165DFF', risk: '#FF7D00', login: '#C9CDD4', review: '#165DFF', notify: '#00B42A' }[kind];
}
function fmtTime(ts: number): string {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false });
}
/** 批准来源要分得清「人批的」「策略自动放的」「升级前既有的」——三者的可信度不同。 */
function approverText(d: Device): string {
  if (d.approvedBy === 'auto') return '自动绑定放行';
  if (d.approvedBy === '(迁移回填)') return '升级前既有设备（按历史上报记录纳管）';
  return d.approvedBy ? `由 ${d.approvedBy} 批准` : '';
}

function openSettings() { Object.assign(form, settings); setOpen.value = true; }

async function saveSettings() {
  try {
    const saved = await api<DeviceTrustSetting>('/devices/settings', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: form.mode, bindMethod: form.bindMethod, staleDays: form.staleDays,
        personalPolicy: form.personalPolicy
      })
    });
    Object.assign(settings, saved);
    setOpen.value = false;
    Message.success(saved.mode === 'strict' ? '已切换为严格准入：非授信终端将无法接入' : '已保存：观察准入（放行并留痕）');
    await load();
  } catch (e) { Message.error(`保存失败：${(e as Error).message}`); }
}

async function setStatus(d: Device, status: Device['status'], reason: string) {
  const out = await api<{ blastRadius?: string }>(`/devices/${d.id}/status`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, reason })
  });
  if (out.blastRadius) blastRadius.value = out.blastRadius;
  await load();
}

async function doApprove(d: Device) {
  try {
    await setStatus(d, 'trusted', '');
    Message.success(`已批准「${d.name}」，该终端即可在严格准入模式下接入`);
  } catch (e) { Message.error(`批准失败：${(e as Error).message}`); }
}

function askRevoke(d: Device) { target.value = d; revokeReason.value = ''; revokeOpen.value = true; }
async function doRevoke() {
  const d = target.value;
  revokeOpen.value = false;
  if (!d) return;
  try {
    await setStatus(d, 'revoked', revokeReason.value);
    Message.warning(`已吊销「${d.name}」，并已按账号撤销 ${d.account} 的接入（影响其全部终端，5 分钟内不可重连）`);
  } catch (e) { Message.error(`吊销失败：${(e as Error).message}`); }
}

function askRename(d: Device) { target.value = d; renameVal.value = d.name; renameOpen.value = true; }
async function doRename() {
  const d = target.value;
  renameOpen.value = false;
  if (!d || !renameVal.value.trim()) return;
  try {
    await api(`/devices/${d.id}/name`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: renameVal.value.trim() })
    });
    Message.success('已重命名');
    await load();
  } catch (e) { Message.error(`重命名失败：${(e as Error).message}`); }
}

/* ── 资产分类与标签 ── */
function askAsset(d: Device) {
  target.value = d;
  assetForm.assetClass = d.assetClass || 'enterprise';
  assetForm.tags = [...(d.tags ?? [])];
  assetOpen.value = true;
}
/** 保存前把「改成个人资产在当前策略下意味着什么」写在脸上：
 *  同一次标注在 inherit 下什么都没发生、在 deny 下等于当场断了这台机器的路。 */
const assetWarn = computed(() => {
  if (!isPersonal(assetForm.assetClass)) {
    // 从个人资产改走时也要说一句：约束会随之解除，那同样是一次判定变更。
    if (target.value && isPersonal(target.value.assetClass) && settings.personalPolicy !== 'inherit') {
      return '改为该分类后，这台终端将不再受个人资产策略约束，恢复按全局准入模式判定。';
    }
    return '';
  }
  if (settings.personalPolicy === 'deny') {
    return '当前个人资产策略是「一律拒绝接入」：保存后这台终端将立刻被拒发敲门令牌，'
      + '即使它的状态仍是「已授信」。同一账号下的企业资产终端不受影响。'
      // ★这一句不能省：拒的是**新令牌**，已建立的隧道由客户端收到拒绝后自行断开，
      //   服务端不主动切断。要立刻切断请用「吊销」（那条会经撤销通道让网关 KillUser）。
      + '注意：已建立的隧道不会被服务端主动切断——官方客户端收到拒绝后会自行停止数据面，'
      + '若需要立刻切断，请改用「吊销」。';
  }
  if (settings.personalPolicy === 'strict') {
    return '当前个人资产策略是「按严格准入判定」：保存后这台终端必须处于「已授信」状态才能接入，'
      + '即使全局准入模式仍是观察。同一账号下的企业资产终端不受影响。';
  }
  return '当前个人资产策略是「跟随全局」，本次标注不会改变这台终端的接入判定，'
    + '只影响台账与筛选。要让它生效，请在「准入设置」里选择「按严格判」或「一律拒绝」。';
});
async function doSetAsset() {
  const d = target.value;
  assetOpen.value = false;
  if (!d) return;
  try {
    await api(`/devices/${d.id}/asset`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assetClass: assetForm.assetClass, tags: assetForm.tags })
    });
    Message.success(`已保存「${d.name}」的资产分类：${classMeta(assetForm.assetClass).label}`);
    await load();
  } catch (e) { Message.error(`保存失败：${(e as Error).message}`); }
}

function askDelete(d: Device) { target.value = d; deleteOpen.value = true; }
async function doDelete() {
  const d = target.value;
  deleteOpen.value = false;
  if (!d) return;
  try {
    await api(`/devices/${d.id}`, { method: 'DELETE' });
    Message.success(`已删除「${d.name}」的登记与环境报告`);
    await load();
  } catch (e) { Message.error(`删除失败：${(e as Error).message}`); }
}

async function doCleanup() {
  cleanupOpen.value = false;
  try {
    const out = await api<{ removed: number; staleDays: number }>('/devices/cleanup-stale', { method: 'POST' });
    Message.success(`已清理 ${out.removed} 台超过 ${out.staleDays} 天未上报的终端（已吊销设备未动）`);
    await load();
  } catch (e) { Message.error(`清理失败：${(e as Error).message}`); }
}

async function decide(decision: 'approved' | 'rejected', reason: string) {
  const a = cur.value;
  if (!a) return;
  try {
    const out = await api<{ deviceLinked?: boolean; blastRadius?: string }>(`/approvals/${a.id}/decide`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, reason })
    });
    if (out.blastRadius) blastRadius.value = out.blastRadius;
    // ★没有关联设备的审批单不谎报"已下发授信指纹"：那种单子批了确实什么都没变。
    if (out.deviceLinked === false) Message.warning('该申请未关联任何终端登记，已归档；没有设备被改变状态');
    else if (decision === 'approved') Message.success(`已通过 ${a.user} 对「${a.device}」的绑定，终端已置为授信`);
    else Message.warning(`已驳回并将该终端置为吊销${reason ? `：${reason}` : ''}`);
    await load();
  } catch (e) { Message.error(`处置失败：${(e as Error).message}`); }
}
function reject() {
  rejectOpen.value = false;
  const r = rejectReason.value;
  rejectReason.value = '';
  decide('rejected', r);
}

/* ── 台账导出（GET /devices/export，PermSecurity）──
 *
 * 后端回的是 CSV 附件而不是 JSON，api() 封装只吃 JSON，这里直接 fetch blob 触发下载
 * （与审计导出同一套做法）。文件名跟随后端 Content-Disposition。 */
const exp = reactive({ busy: false });
async function doExport() {
  exp.busy = true;
  try {
    const res = await fetch('/api/v1/devices/export', { headers: { Authorization: `Bearer ${getToken()}` } });
    if (!res.ok) {
      // 403 的原话（"需要权限 security"）是唯一能指导下一步的信息，不要吞掉。
      const msg = await res.text().catch(() => '');
      throw new Error(msg || `${res.status}`);
    }
    const blob = await res.blob();
    const cd = res.headers.get('Content-Disposition') ?? '';
    const name = /filename="([^"]+)"/.exec(cd)?.[1] ?? `baidi-devices-${new Date().toISOString().slice(0, 10)}.csv`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
    Message.success(`已导出 ${name}`);
  } catch (e) {
    Message.error(`导出失败：${(e as Error).message}（需已连 baidi-control，且当前管理员持有「安全策略」权限）`);
  } finally {
    exp.busy = false;
  }
}

/* ── 批量预登记（POST /devices/import，正文是 CSV 文本）── */
const MAX_ROWS = 500;   // 与后端 deviceImportMaxRows 同值；仅用于提示，真判定在后端
const MAX_KIB = 512;    // 同 deviceImportMaxBytes
const fileEl = ref<HTMLInputElement | null>(null);
const imp = reactive({
  open: false, busy: false,
  name: '', text: '', rows: 0,
  result: null as DeviceImportResult | null
});

function resetImport() {
  imp.name = ''; imp.text = ''; imp.rows = 0; imp.result = null; imp.busy = false;
  if (fileEl.value) fileEl.value.value = '';
}
function openImport() { resetImport(); imp.open = true; }

async function onPick(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0];
  if (!f) return;
  imp.name = f.name;
  imp.text = await f.text();
  // 行数只是给人看的估计值（表头不算、空行不算），真正的上限判定在后端。
  imp.rows = Math.max(0, imp.text.split('\n').filter((l) => l.trim() !== '').length - 1);
}

async function doImport() {
  imp.busy = true;
  try {
    imp.result = await api<DeviceImportResult>('/devices/import', {
      method: 'POST', headers: { 'Content-Type': 'text/csv' }, body: imp.text
    });
    const r = imp.result;
    if (r.skipped.length) Message.warning(`已预登记 ${r.imported.length} 台，${r.skipped.length} 行跳过（见逐行原因）`);
    else Message.success(`已预登记 ${r.imported.length} 台终端`);
    await load();
  } catch (e) {
    // 整批被拒（超限 / 表头不合法）时后端一台都没写，文案里已说明，原样透出。
    Message.error(`导入失败：${(e as Error).message}`);
  } finally {
    imp.busy = false;
  }
}

async function load() {
  try {
    const b = await api<DeviceBundle>('/devices');
    Object.assign(settings, b.settings);
    devices.value = b.devices ?? [];
    approvals.value = b.approvals ?? [];
    selId.value = approvals.value[0]?.id ?? '';
    live.value = true;
    loadErr.value = '';
  } catch (e) {
    live.value = false;
    loadErr.value = (e as Error).message;
  }
}
onMounted(load);
</script>

<style scoped>
.bd-head__right { margin-left: auto; }

/* 未连提示 */
.bd-offline { display: flex; align-items: center; gap: 14px; padding: 18px 20px; }
.bd-offline :deep(svg) { color: var(--bd-warning); font-size: 20px; flex: none; }
.bd-offline__t { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.bd-offline__d { font-size: 12.5px; color: var(--bd-t3); line-height: 1.7; margin-top: 3px; }
.bd-offline .bd-btn { margin-left: auto; flex: none; }

/* 准入模式横幅 */
.bd-mode { display: flex; align-items: flex-start; gap: 10px; padding: 11px 14px; border-radius: 8px; font-size: 12.5px; line-height: 1.7; margin-bottom: 16px; }
.bd-mode :deep(svg) { font-size: 16px; flex: none; margin-top: 2px; }
.bd-mode--observe { background: var(--bd-fill-1); color: var(--bd-t2); }
.bd-mode--observe :deep(svg) { color: var(--bd-t3); }
.bd-mode--strict { background: color-mix(in srgb, var(--bd-success) 10%, #fff); color: var(--bd-t1); }
.bd-mode--strict :deep(svg) { color: var(--bd-success); }
.bd-mode--asset { background: color-mix(in srgb, var(--bd-warning) 10%, #fff); color: var(--bd-t1); margin-top: -8px; }
.bd-mode--asset :deep(svg) { color: var(--bd-warning); }

/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { display: flex; align-items: center; gap: 7px; font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }
.bd-tab em { font-style: normal; font-size: 11px; color: var(--bd-t3); }
.bd-tab.on em { color: var(--bd-primary); }
.bd-badge { min-width: 16px; height: 16px; padding: 0 5px; border-radius: 8px; background: var(--bd-danger); color: #fff; font-size: 11px; font-weight: 600; display: inline-flex; align-items: center; justify-content: center; line-height: 1; }

/* 设备清单 */
.bd-toolbar__c { font-size: 12.5px; color: var(--bd-t3); }
.bd-tg--grey { background: var(--bd-fill-2); color: var(--bd-t3); font-weight: 400; }
.bd-cellname { gap: 9px; flex-wrap: wrap; cursor: default; }
.bd-dmono { display: block; font-size: 11px; color: var(--bd-t3); margin-top: 3px; font-family: ui-monospace, monospace; }
.bd-sub { font-size: 11.5px; color: var(--bd-t3); }
.bd-sub--warn { color: var(--bd-warning); }
.bd-tagrow { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
/* 操作列有五个动作，窄屏下允许在链接之间换行，但不许把一个词拆开（「重命 名」）。 */
.bd-table .bd-link { white-space: nowrap; }
.bd-link--danger { color: var(--bd-danger); }

/* 「真实判据」与「仅台账属性」两枚角标：界面上任何一个勾都必须真能生效，
   反过来说，不生效的东西要当面标明它只是标签。 */
.bd-real, .bd-fake { font-size: 10.5px; font-weight: 500; padding: 1px 6px; border-radius: 4px; margin-left: 7px; }
.bd-real { color: var(--bd-primary); background: var(--bd-primary-1); }
.bd-fake { color: var(--bd-t3); background: var(--bd-fill-2); }

/* 审批两栏 */
.bd-two { display: flex; gap: 16px; align-items: flex-start; }
.bd-aplist { width: 300px; flex: none; padding: 10px; }
.bd-aplist__h { font-size: 12px; font-weight: 600; color: var(--bd-t3); padding: 4px 8px 10px; }
.bd-aplist__h em { font-style: normal; margin-left: 4px; }
.bd-apitem { width: 100%; display: block; text-align: left; border: 1px solid transparent; background: transparent; border-radius: 8px; cursor: pointer; padding: 11px 12px; margin-bottom: 4px; transition: background .12s, border-color .12s; }
.bd-apitem:hover { background: var(--bd-fill-1); }
.bd-apitem.on { background: var(--bd-primary-1); border-color: var(--bd-primary-b); }
.bd-apitem__row { display: flex; align-items: center; justify-content: space-between; }
.bd-apitem__user { font-size: 13.5px; font-weight: 600; color: var(--bd-t1); }
.bd-apitem.on .bd-apitem__user { color: var(--bd-primary); }
.bd-apitem__time { font-size: 11px; color: var(--bd-t3); font-family: ui-monospace, monospace; }
.bd-apitem__dev { font-size: 12px; color: var(--bd-t2); margin-top: 4px; }

.bd-apdetail { flex: 1; min-width: 0; padding: 20px 22px 22px; }
.bd-apd__head { display: flex; align-items: flex-start; justify-content: space-between; padding-bottom: 16px; border-bottom: 1px solid var(--bd-fill-2); }
.bd-apd__dev { font-size: 16px; font-weight: 700; color: var(--bd-t1); }
.bd-apd__fp { font-size: 12px; color: var(--bd-t3); margin-top: 4px; }
.bd-apd__meta { padding: 6px 0 4px; }
.bd-kv { display: flex; align-items: center; justify-content: space-between; padding: 9px 0; border-bottom: 1px solid var(--bd-fill-1); font-size: 13px; }
.bd-kv span { color: var(--bd-t3); }
.bd-kv b { font-weight: 500; color: var(--bd-t1); }
.bd-apd__sec { font-size: 13px; font-weight: 600; margin: 20px 0 14px; }

/* 时间线 */
.bd-tl { padding-left: 2px; }
.bd-tl__row { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }
.bd-tl__title { font-size: 13px; font-weight: 600; color: var(--bd-t1); }
.bd-tl__time { font-size: 11.5px; color: var(--bd-t3); flex: none; }
.bd-tl__detail { font-size: 12px; color: var(--bd-t3); line-height: 1.6; margin-top: 3px; }

.bd-apd__acts { display: flex; gap: 10px; margin-top: 22px; }

/* 空态 */
.bd-empty { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--bd-t3); padding: 16px 12px; }
.bd-empty :deep(svg) { color: var(--bd-success); }
.bd-empty--lg { justify-content: center; min-height: 280px; flex-direction: column; gap: 12px; color: var(--bd-t4); }
.bd-empty--lg :deep(svg) { font-size: 28px; color: var(--bd-t4); }

/* 设置 modal */
.bd-setrow { display: flex; align-items: center; gap: 12px; padding: 14px 0; border-bottom: 1px solid var(--bd-fill-1); }
.bd-setrow:last-child { border-bottom: none; }
.bd-setrow__main { flex: 1; min-width: 0; }
.bd-setrow__label { font-size: 13.5px; font-weight: 500; color: var(--bd-t1); }
.bd-setrow__desc { font-size: 12px; color: var(--bd-t3); margin-top: 3px; line-height: 1.6; }

/* 批量预登记 modal */
.bd-wdesc { font-size: 13px; color: var(--bd-t2); line-height: 1.75; margin-bottom: 14px; }
.bd-warnbox { display: flex; gap: 10px; background: color-mix(in srgb, var(--bd-warning) 10%, #fff); border-radius: 8px; padding: 12px 14px; margin-bottom: 14px; font-size: 12.5px; color: var(--bd-t2); line-height: 1.75; }
.bd-warnbox :deep(svg) { color: var(--bd-warning); font-size: 17px; flex: none; margin-top: 2px; }
.bd-warnbox--red { background: color-mix(in srgb, var(--bd-danger) 10%, #fff); }
.bd-warnbox--red :deep(svg) { color: var(--bd-danger); }
.bd-impnote { margin-top: 7px; padding-top: 7px; border-top: 1px solid var(--bd-fill-2); font-size: 12px; color: var(--bd-t3); }
.bd-picker { display: flex; align-items: center; gap: 12px; margin-top: 16px; }
.bd-impsum { display: flex; gap: 8px; margin-bottom: 14px; }
.bd-implist { margin-bottom: 14px; max-height: 220px; overflow: auto; border: 1px solid var(--bd-fill-2); border-radius: 8px; }
.bd-implist__h { position: sticky; top: 0; background: var(--bd-fill-1); font-size: 12px; font-weight: 600; color: var(--bd-t2); padding: 8px 12px; }
.bd-improw { display: flex; gap: 10px; align-items: baseline; padding: 8px 12px; border-top: 1px solid var(--bd-fill-1); font-size: 12px; }
.bd-improw__ln { flex: none; color: var(--bd-t3); width: 66px; }
.bd-improw__id { flex: none; max-width: 46%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--bd-t1); }
.bd-improw__why { flex: 1; color: var(--bd-t3); line-height: 1.6; }

/* 危险确认 modal */
.bd-reject { display: flex; gap: 12px; font-size: 13.5px; line-height: 1.7; color: var(--bd-t2); margin-bottom: 14px; }
.bd-reject__ic { color: var(--bd-danger); font-size: 20px; flex: none; margin-top: 2px; }
.bd-blast { background: var(--bd-fill-1); border-radius: 8px; padding: 12px 14px; margin-bottom: 14px; }
.bd-blast__t { font-size: 12px; font-weight: 600; color: var(--bd-t2); margin-bottom: 5px; }
.bd-blast__d { font-size: 12px; color: var(--bd-t3); line-height: 1.75; }
</style>
