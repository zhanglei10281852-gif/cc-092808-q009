# 司法鉴定检材流转与复核服务

本项目是面向司法鉴定机构的 Python 后端服务，用于登记委托或移送案件、接收带封识的检材、记录保管位置与流转、执行专业检验、安排复核并处理环境和质量告警。案件、检材、检验记录和领用审批都保存在本地 SQLite 中，关键写入带版本或幂等键，适合在单个 Linux 应用容器内运行。

## 运行环境

- Python 3.11
- FastAPI 与 Uvicorn
- SQLite 3，由 Python 标准库提供

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `data/forensics.db`，也可以通过 `FORENSICS_DATABASE_PATH` 指向其他 `.db`、`.sqlite` 或 `.sqlite3` 文件。

## 初始化与启动

```bash
python -m app.cli init-db
python -m app.cli check-db
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康检查为 `GET /api/system/health`。首次使用可调用 `POST /api/auth/bootstrap` 创建管理员，再通过 `POST /api/auth/login` 取得 Bearer 会话令牌。鉴定业务接口统一位于 `/api/forensics`。

## 测试与构建检查

```bash
python -m pytest
python -m compileall -q app tests
```

下面两条命令分别检查 HTTP 入口和完整的入库演示链路：

```bash
python -m app.cli smoke
python -m app.cli demo
```

## 业务边界

- `app/forensics/cases.py` 管理委托机构、案件档案、委托资料、受理状态与报告签发（报告一经签发不可变更）。
- `app/forensics/custody.py` 管理检材、库位容量、容器摆放、流转、领用和冻结。
- `app/forensics/examinations.py` 管理检验规程、取样、观察记录、检验结果与复核日程。
- `app/forensics/quality.py` 管理温湿度读数、偏离告警和检材领用审批。
- `app/forensics/supplementary.py` 管理补送识别：登记补送包后按委托机构、原始文书号、案号别名和参照封识号形成带证据的候选案件，登记员人工确认后才接收新增检材；无法确定的补送包保持隔离，绝不自动归并；封识被他案占用或原案件已关闭签发时进入有理由的冲突处理。
- `app/forensics/merges.py` 管理误建案件归并：管理员先预演引用迁移并逐字段决定保留值，执行后检材与领用明细迁往存续案件，旧编号登记为别名仍可解析，已签发报告与既有流转、案件事件保持不可变。
- `app/api`、`app/services` 和 `app/repositories` 提供身份、权限、审计、后台作业及维护能力。

## 补送与归并接口

- `POST /api/forensics/supplementary-packages` 登记补送包（幂等键去重，重复提交返回首次结果）；`GET /api/forensics/supplementary-packages/{id}` 查看候选依据、隔离原因、冲突明细与全部人工决定。
- `POST /api/forensics/supplementary-packages/{id}/confirm` 登记员确认原案件；`POST /api/forensics/supplementary-packages/{id}/resolve-conflict` 质量负责人带理由接收或退回冲突补送包。
- `POST /api/forensics/cases/{id}/reports` 签发案件报告（签发后不可修改）。
- `POST /api/forensics/case-merges/previews` 预演归并（展示迁移前后引用与逐字段保留值）；`POST /api/forensics/case-merges/{id}/execute` 执行；`GET /api/forensics/cases/resolve/{编号}` 按编号或别名解析案件并跟随归并链。

## 一致性约定

SQLite 连接启用外键、WAL、忙等待和即时写事务。案件档案、库位、容器摆放、检验任务和领用申请采用版本号防止旧请求覆盖新状态；入库、移库、取样和传感读数使用业务键去重。专业检验保留采用的规程版本和每个检查点的观察记录，完成后可依据鉴定专业及风险策略生成下一次复核日期。会话令牌只保存摘要，审计记录不保存明文密码或令牌。补送包登记使用幂等键，重复提交返回首次结果；编号比对前统一折算为半角大写并去除标点，同一委托编号的不同写法不会误建案件。归并只追加事件不改写历史：检材与领用明细改挂存续案件，已签发报告、流转事件和案件事件保持原样，旧案件转为退出保存并保留归并去向。
