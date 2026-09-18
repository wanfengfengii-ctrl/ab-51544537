# 变电站远方操作后端服务（Substation Remote Switching）

面向变电站远方（远程）开关操作的**纯后端**服务。调度系统提交不可变的开关
操作指令；值班操作员（OPERATOR）与安全复核员（SAFETY）分别用 Ed25519
签署后，独立投递 worker 才能把指令发送给站端执行器。API 与 worker 均多
实例运行，所有授权、撤销、到期与领取的裁决都由 PostgreSQL 持久化状态唯一
决定，不依赖内存锁或本机时钟。

> 本仓库**不含任何前端**。只有版本化 HTTP JSON API、独立 worker、模拟站端
> 执行器、数据库迁移、自动化测试与容器编排。

## 它保证什么 / 不保证什么（重要）

* **保证单次物理效果（exactly-once *physical effect*）与最终状态收敛**：
  这依赖下游执行器对稳定 `executionKey` 的幂等契约——同一 key 只产生一次
  物理效果，并提供按 key 查询最终结果的接口。worker 在超时、连接中断或
  自身重启时，**绝不换新 key 盲目重发**，而是用同一 key 重试或查询结果，
  把“执行器已接受但响应丢失”的情况收敛到成功或明确失败。
* **不**承诺在一个非幂等下游上实现网络层的“恰好一次投递”。网络层本质是
  至少一次（at-least-once）：重复的 HTTP 请求可能到达多次。这里的正确性
  边界是执行器基于 `executionKey` 的单次物理效果去重 + worker 的查询收敛，
  而不是“请求只在线上发送一次”。模拟执行器（`actuator/`）实现了这一契约
  以便端到端验证。

## 架构

```
                         Docker network (internal)
  host ──${API_PORT:-8080}──▶ proxy (nginx, LB)
                                  ├── api1 (FastAPI/uvicorn)
                                  └── api2 (FastAPI/uvicorn)
                                        │
                          worker1 ───────┤        worker2
                              │          │            │
                              └──────▶ postgres ◀─────┘
                              │
                              └──────────────▶ actuator (mock, /execute, /result)
```

* `app/`：版本化 HTTP JSON API（FastAPI），无状态、可水平扩展。
* `worker.py`：独立投递进程（可多副本）。提交请求路径**不**做任何投递。
* `actuator/mock_actuator.py`：零第三方依赖的模拟站端执行器；按
  `executionKey` 去重物理效果，提供 `/result/{key}` 恢复查询。
* `migrations/`：SQL 迁移（启动时经咨询锁串行应用）。
* `tests/`：确定性字节格式单测、数据库事务级并发仲裁测试、对整套多实例栈
  的端到端验收测试。

### 关键正确性机制

| 风险 | 机制 |
|---|---|
| 未满足授权即投递 | worker 只领取 `AUTHORIZED` 且在窗口内的指令；状态迁移在 DB 事务内 |
| 撤销与领取竞争 | 领取为单条 `UPDATE ... FOR UPDATE SKIP LOCKED` 事务，行锁至提交；撤销看到 `CLAIMED` 即返回 `REVOKE_RACE_LOST`，提交后撤销不可能伪装成功 |
| 多 worker 重复投递 | `SKIP LOCKED` + 租约（lease owner / epoch / 过期时间），每次投递资格最多一个获胜 |
| 进程崩溃后状态恢复 | 全部状态在 Postgres；租约到期后他者接管，`executionKey` 稳定不变，先查询再决定重发 |
| 响应丢失造成两次物理效果 | 同一稳定 key 幂等重发 + `/result/{key}` 查询；执行器保证一 key 一次效果 |
| 重复提交/签署 | commandId 唯一约束 + 规范化字节比较；签署 `(command,role)`/`(command,subject)` 唯一约束；相同请求幂等，不新增审计事件 |
| 时间伪造 | 启用/停用、到期、窗口判断一律使用数据库 `now()`，不使用本机时钟参与裁决 |
| 恢复重放产生重复事件 | 审计表 `(command_id,event_key)` 去重（claim 按 epoch、attempt/query 按序号） |
| JSON 键顺序影响签名 | 服务定义的长度前缀确定性字节格式（`app/canonical.py`、`API.md`） |

## 只需 Docker

宿主机**不需要**安装 Python、Postgres 或任何测试工具，只需 Docker 与
Docker Compose（v2）。

### 构建并启动整套服务

```bash
docker compose build
docker compose up -d
# 唯一对宿主机发布的入口：
curl -s http://localhost:8080/healthz
```

自定义宿主机端口：

```bash
API_PORT=9090 docker compose up -d
```

服务清单：`db`、`api1`、`api2`、`worker1`、`worker2`、`actuator`、`proxy`。
所有长期服务都配置了健康检查；数据库、执行器不发布到宿主机，只有代理
发布一个 API 入口。

### 一次性验收（verify）

```bash
docker compose --profile verify run --rm verify
```

该服务构建与 API/worker 相同的镜像，等待全部依赖健康后，在容器内运行：

* `tests/test_canonical.py`：签名字节格式的精确布局与无键序依赖；
* `tests/test_db_arbitration.py`：真实多连接交错下的撤销/领取仲裁、
  8 路并发领取只有一个获胜、终态后撤销幂等；
* `tests/test_acceptance.py`：经代理打两套 API 与两个 worker 的端到端
  流程，含密钥停用、重复提交/签署、时间窗口、撤销竞争、时间线固定视图
  分页、执行器超时后查询收敛、瞬时故障退避重试、明确拒绝终态等。

停止与清理：

```bash
docker compose down            # 保留数据卷
docker compose down -v         # 同时删除数据库卷
```

## 快速手工演练

以下用 Python 在宿主机生成密钥与签名（也可在任意容器内进行；示例仅为
调用演示，宿主机无需装库即可改用 `verify` 镜像执行）：

```bash
BASE=http://localhost:8080

# 1) 登记 OPERATOR / SAFETY 两把公钥（不同主体）
# 2) POST /api/v1/commands 提交指令
# 3) 用 app/canonical.py 定义的字节构造签名，POST .../sign 两次
# 4) GET /api/v1/commands/{id} 观察 PENDING -> AUTHORIZED -> CLAIMED
#    -> EXECUTING -> SUCCEEDED，executionKey 在领取后出现
# 5) GET .../timeline?limit=&cursor= 按固定视图分页
```

完整字段、错误码与签名字节格式见 **[API.md](API.md)**。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `API_PORT` | `8080` | 代理发布到宿主机的端口（compose 变量） |
| `DATABASE_URL` / `POSTGRES_*` | 见 compose | 数据库连接 |
| `ACTUATOR_URL` | `http://actuator:8090` | 站端执行器地址 |
| `DELIVERY_LEASE_SECONDS` | `60`（compose 中 10） | 单次投递排他租约时长 |
| `BACKOFF_SECONDS` | `1,2,5,10,30`（compose 中更短） | 瞬时错误退避序列，末值封顶 |
| `MAX_ATTEMPTS` | `20` | 最大发送尝试（超出转明确失败） |
| `HTTP_TIMEOUT_SECONDS` | `5`（compose 中 3） | 调用执行器超时 |
| `POLL_SECONDS` | `0.5`（compose 中 0.2） | worker 空闲轮询间隔 |

## 模拟执行器的故障注入

提交指令时在 `params` 中放 `__sim`（仅模拟执行器识别）：

```json
"params": { "__sim": { "mode": "timeoutFirst", "delaySeconds": 30 } }
```

* `ok`（默认）：接受并成功，一次物理效果；
* `timeoutFirst`：**先持久化成功再挂起**首次响应，模拟“已执行但响应丢失”；
  worker 必须通过同一 key 的 `/result` 查询收敛成功；
* `flaky` + `succeedOnAttempt`：前 N-1 次瞬时 503（无效果），之后成功；
* `reject` + `reason`：明确永久拒绝 → 指令进入 FAILED 终态且不自动重投。

## 目录

```
app/            FastAPI 应用（canonical 字节格式、仓储/事务、错误码、模型）
worker.py       独立投递 worker：领取、幂等投递、查询恢复、退避重试
actuator/       零依赖模拟站端执行器
migrations/     PostgreSQL 迁移
tests/          单元 / 数据库仲裁 / 端到端验收测试
Dockerfile          API 与 worker（同一镜像，不同启动命令）
Dockerfile.actuator 模拟执行器
docker-compose.yml  db ×1、api ×2、worker ×2、actuator、proxy、verify
nginx.conf      反向代理（唯一宿主机入口）
API.md          接口、错误码与确定性签名字节格式权威文档
```
