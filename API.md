# API v1

所有接口均为 HTTP JSON，前缀 `/api/v1`，经由反向代理的唯一宿主机入口访问
（默认 `http://localhost:${API_PORT:-8080}`）。

错误响应统一为：

```json
{ "error": { "code": "MACHINE_CODE", "message": "human readable" } }
```

## 稳定机器码

| code | HTTP | 含义 |
|---|---|---|
| `VALIDATION_ERROR` | 422 | 请求体不符合 schema |
| `CONTENT_CONFLICT` | 409 | 同 commandId 内容不同；或同角色不同签名复用 |
| `SIGNER_NOT_QUALIFIED` | 422 | 公钥未注册，或不属于该主体/角色 |
| `INVALID_SIGNATURE` | 422 | Ed25519 验签失败 |
| `KEY_DISABLED` | 409 | 公钥已停用后到达的**新**签署（已记录签署的幂等重试除外） |
| `NOT_BEFORE_NOT_REACHED` | 200(eligibility) / 内部 | 尚未到 notBefore，不可领取 |
| `COMMAND_EXPIRED` | 409 | 已到/过 expiresAt |
| `REVOKE_RACE_LOST` | 409 | 撤销与领取竞争，领取事务已先提交 |
| `TERMINAL_STATE_CONFLICT` | 409 | 对终态（或已越过领取边界）指令做签署等非法操作 |
| `SUBMITTER_MUST_NOT_SIGN` | 422 | 提交者签署了自己的指令 |
| `DUPLICATE_SUBJECT_ROLE` | 409 | 同一主体占据两个角色 |
| `COMMAND_NOT_FOUND` / `KEY_NOT_FOUND` | 404 | 资源不存在 |
| `CURSOR_INVALID` | 422 | 时间线分页游标损坏 |
| `ACTUATOR_REJECTED` | 记录在终态结果中 | 站端明确拒绝（终态，不自动重投） |
| `INTERNAL_ERROR` | 500 | 内部错误 |

## 1. 签署公钥

### 登记公钥
`POST /api/v1/keys`
```json
{ "subject": "operator-alice", "role": "OPERATOR",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n" }
```
`role` ∈ `OPERATOR` | `SAFETY`。必须是 PEM 编码的 Ed25519 SPKI 公钥。
`201` 返回含 `keyId` 的密钥记录。重复登记同一公钥稳定返回
`CONTENT_CONFLICT`。

### 停用公钥
`POST /api/v1/keys/{keyId}/disable` → `200`。停用以**数据库时间**打戳。
停用不影响此前已成功记录的签署；停用后到达的新签署返回 `KEY_DISABLED`。

### 查询公钥
`GET /api/v1/keys/{keyId}`。

## 2. 指令

### 提交指令
`POST /api/v1/commands`
```json
{
  "commandId": "client-generated-unique-id",
  "submitter": "dispatcher-system",
  "station": "ST-777",
  "device": "BREAKER-01",
  "action": "OPEN",
  "params": { "phaseCount": 3 },
  "notBefore": "2026-09-18T10:00:00.000000Z",
  "expiresAt": "2026-09-18T10:30:00.000000Z",
  "payloadVersion": 1
}
```
时间戳必须带时区（RFC 3339）。提交成功后业务载荷、`expiresAt` 与授权策略
快照均不可修改。

* 相同 `commandId` + **规范化字节完全相同** → 返回原指令（`201` 幂等，
  不新增时间线事件）。
* 相同 `commandId` 但规范化内容不同 → 稳定 `CONTENT_CONFLICT`。

### 查询指令（含时间线首页）
`GET /api/v1/commands/{commandId}` 返回：

* `state`：`PENDING | AUTHORIZED | CLAIMED | EXECUTING | SUCCEEDED |
  FAILED | CANCELLED | EXPIRED`
* `satisfiedRoles`：已满足的角色
* `policyVersion` / `policySnapshot`：提交时的不可变授权策略快照
* `executionKey`：稳定执行键，**仅在已领取（越过投递原子边界）后出现**
* `finalResult` / `finalAt`：最终执行结果
* `timeline`：按单调事件编号排序的首页事件；`timelinePage` 含
  `nextCursor` 与本视图固定的 `viewUpperBoundEventId`

### 投递资格（只读）
`GET /api/v1/commands/{commandId}/delivery-eligibility`
返回 `eligibility` ∈ `DELIVERABLE | PENDING_SIGNATURES |
NOT_BEFORE_NOT_REACHED | COMMAND_EXPIRED | ALREADY_CLAIMED |
TERMINAL_*`，全部以数据库时间裁决，到期时顺带完成 EXPIRED 迁移。

### 签署
`POST /api/v1/commands/{commandId}/sign`
```json
{ "role": "OPERATOR", "subject": "operator-alice",
  "publicKeyPem": "...", "signature": "<base64 Ed25519>" }
```
规则：

* 必须由两个**不同主体**分别以 `OPERATOR`、`SAFETY` 签署；
* 提交者不得签署自己的指令；同一主体不得占两个角色；
* 服务在同一数据库事务、以数据库时间判断：公钥是否已启用、是否属于该
  主体与角色、指令是否仍有效，然后验签；
* 已成功记录的签署不因之后停用公钥而失效；**完全相同**的签署请求重试
  幂等成功且不新增时间线事件；同角色不同签名复用 → `CONTENT_CONFLICT`；
* 两份有效签署齐备后，指令进入 `AUTHORIZED`（可投递，但仍受
  notBefore/expiresAt 窗口约束）。

### 撤销（越过投递原子边界前）
`POST /api/v1/commands/{commandId}/cancel`
```json
{ "requestedBy": "safety-bob", "reason": "plan change" }
```
* `PENDING/AUTHORIZED` 且未到期 → `CANCELLED`（终态）；重复撤销幂等；
* 领取事务已提交（`CLAIMED/EXECUTING/SUCCEEDED/FAILED`）→
  `REVOKE_RACE_LOST`，撤销不会伪装成功；
* 已到期 → `COMMAND_EXPIRED`。

### 时间线分页
`GET /api/v1/commands/{commandId}/timeline?limit=50&cursor=<opaque>`

* 游标是不可变事件编号（base64 封装的 `{after,max}`），对客户端不透明；
* 首次查询（无游标）固定本**视图上界** = 当时最大事件编号；
* 翻页期间新提交的事件不会混入本轮视图、不会重复、也不会挤掉旧事件；
  开启新视图（不带游标重新查询）才会看到更大的上界。

## 3. 确定性签名字节格式（权威定义）

客户端**不得**对 JSON 对象重新序列化来生成签名。签名输入是以下精确字节。
所有多字节整数均为 ASCII 十进制；每个段为
`名称:<UTF-8字节数>:<原始字节>\n`，因此值中即使包含 `:` 或换行也不会
产生歧义。

命令字节（魔法头 `SUBSTATION-CMD-v1\n`，段顺序固定）：

```
commandId:<len>:<bytes>\n
station:<len>:<bytes>\n
device:<len>:<bytes>\n
action:<len>:<bytes>\n
params:<len>:<canonical JSON bytes>\n
notBefore:<len>:<RFC3339 UTC, microsecond, trailing Z>\n
expiresAt:<len>:<...>\n
payloadVersion:<len>:<ASCII decimal>\n
```

签名消息（魔法头 `SUBSTATION-CMD-SIG-v1\n`）= 上述命令字节后追加：

```
policyVersion:<len>:<ASCII decimal>\n
role:<len>:<OPERATOR|SAFETY>\n
```

其中：

* `params` 的规范化 JSON：UTF-8、对象成员按 Unicode 码点排序、无空白、
  `ensure_ascii=false`（等价于 Python
  `json.dumps(v, sort_keys=True, separators=(",",":"), ensure_ascii=False)`）；
* 时间戳统一转 UTC：`YYYY-MM-DDTHH:MM:SS.ffffffZ`（微秒，6 位）；
* 算法：Ed25519 对**签名消息的精确字节**签名，base64 传输。

参考实现见 `app/canonical.py`，字节布局样例与边界用例见
`tests/test_canonical.py`。`GET /api/v1/signing-format` 返回该格式的
自描述摘要。

## 4. 状态机与投递

```
PENDING ──both signatures──▶ AUTHORIZED ──claim(notBefore≤now<expiresAt)──▶ CLAIMED
   │                             │                                          │
   │cancel                       │cancel (race)                             ▼
   ▼                             ▼                                      EXECUTING
CANCELLED                  (race loser: 409)                                │
   │                                                                 ┌──────┴──────┐
   │ expire                                                     SUCCEEDED       FAILED
   ▼                                                                              
EXPIRED
```

* 领取是单条 `UPDATE ... FOR UPDATE SKIP LOCKED` 事务；多 worker 竞争时
  每次投递资格最多一个获胜；提交后行锁保证并发撤销落败。
* `executionKey = "exec-v1-" + commandId`，领取时生成且**永不重新生成**。
* worker 在超时/断连/自身重启后，绝不换新 key 盲发：先用同一 key 调用
  执行器 `/result/{key}` 查询；查询为 UNKNOWN 才用同一 key 幂等重发。
* 瞬时错误按可配置退避（`BACKOFF_SECONDS`）重试；明确拒绝进入 FAILED
  终态，不自动重投。
* 所有领取尝试、发送结果、恢复查询、终态变化都写只追加审计时间线；
  `(command_id,event_key)` 去重，恢复重放不产生重复业务事件。
