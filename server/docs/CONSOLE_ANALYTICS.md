# 0.1.22 控制台统计口径

默认进入数据分析，另有策略管理（白名单、连接网关）与资产管理。只用已有心跳、配置资产、代理活动及最后请求结果，主要统计单位是终端，不新增请求采集、请求量、正文日志或历史趋势。

- 默认在线范围，阈值为心跳间隔两倍加30秒；陈旧阈值为五倍加30秒。离线范围显示最后上报状态。
- Agent运行覆盖：只取running=true实例，同一终端同一类去重；多类覆盖比例可合计超过100%。实例构成按终端及实例标识去重，比例合计100%。CC Switch独立展示，疑似Agent不计入。
- LLM已观测口径：存在真实请求活动且关联原始目标的终端，按服务商去重；当前配置口径：仅当前启用配置，包含白名单。完整域名/受控子域名匹配，不将统一网关认作服务商；未知、中转及缺失地址明确显示。
- 已观测仅表示现存数据曾观察到请求，无法追溯配置切换前的历史目标，也不覆盖白名单直连请求。
- 最近异常：任一配置关联最后观测请求结果失败，终端计一次；仍上报的未启用配置也保留其最后结果。曾异常：本次运行失败累计大于0。重启后保留的旧结果不等于本次运行失败。未观测请求不等于正常。
- 连接失败、路由失败、网关返回错误独立分组，同一终端可进入多组。网关返回错误不直接归因于代理自身。配置/挂载问题单独显示。
- 白名单覆盖：当前配置+allowlistBypassed=true+routeStatus=bypassed+非空原始地址，标准化Base URL精确分组，每条规则按终端去重；总命中终端跨规则再次去重。表示配置直连，不代表观测到实际直连请求。未应用新策略的旧地址仍以终端上报状态显示；待保存草稿不计入。
- 停用、挂载失败和不支持接管另列其他未接入代理状态；旧客户端及未知字段提示数据不足。

管理员只读接口：GET /admin/v1/analytics、GET /admin/v1/analytics/devices，沿用现有Bearer鉴权。公共参数scope（online/all/stale/offline/legacyClient）、os、providerMode（observed/configured）。下钻支持kind、key、search、agent、provider、anomaly（latest/ever/none）、allowlist、skip、take。take默认50，限制1–500，返回total和当前分页。

聚合与下钻共用口径，同一MySQL REPEATABLE READ只读快照批量读取策略和资产，不在浏览器逐台取详情。每60秒刷新保留筛选和展开，加载失败保留旧结果并提示；下钻转资产保留分析条件，详情返回保留原侧栏。

域名映射参考官方地址：[OpenAI](https://platform.openai.com/docs/api-reference/models)、[火山方舟](https://www.volcengine.com/docs/82379/1795150)、[Kimi](https://platform.kimi.com/docs/api/chat)。
