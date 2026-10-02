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

- `app/forensics/cases.py` 管理委托机构、案件档案、委托资料与受理状态。
- `app/forensics/custody.py` 管理检材、库位容量、容器摆放、流转、领用和冻结。
- `app/forensics/examinations.py` 管理检验规程、取样、观察记录、检验结果与复核日程。
- `app/forensics/quality.py` 管理温湿度读数、偏离告警和检材领用审批。
- `app/forensics/supplements.py` 管理补送包登记、候选识别、人工确认、冲突处理与补送检材接收。
- `app/forensics/merges.py` 管理误建案件的归并预演、逐字段保留值决定与归并执行。
- `app/api`、`app/services` 和 `app/repositories` 提供身份、权限、审计、后台作业及维护能力。

## 补送识别与归并

侦查机关补送对照样本时，登记员先登记补送包（`POST /api/forensics/supplements`），系统按委托机构、原始文书号、案号别名和封识号生成带证据的候选案件；编号比对会忽略大小写、空格与分隔符，容忍写法差异。没有候选的材料保持隔离（`quarantined`），系统不会自动归并，一律由登记员确认原案件后才接收新增检材。重复提交同一补送包（同一幂等键）返回首次结果。确认时若封识已被其他案件占用或原案件已关闭签发（已退出保存或已签发报告），补送包进入冲突状态，须由案件审核员填写理由后选择维持隔离或强制确认（必要时重启已退出案件）。确有误建案件时，管理员通过 `/api/forensics/case-merges` 预演引用迁移、逐字段决定保留值后执行；执行后来源案件退出保存并记录归并去向，旧编号仍可经 `/api/forensics/cases/resolve/{case_no}` 解析，既有流转事件、检验记录、审计记录与已签发报告保持不可变。

## 一致性约定

SQLite 连接启用外键、WAL、忙等待和即时写事务。案件档案、库位、容器摆放、检验任务和领用申请采用版本号防止旧请求覆盖新状态；入库、移库、取样和传感读数使用业务键去重。专业检验保留采用的规程版本和每个检查点的观察记录，完成后可依据鉴定专业及风险策略生成下一次复核日期。补送包登记按幂等键去重，确认与冲突处理记录操作人和理由；案件归并预演与执行分步落库，同一来源案件同时只允许一个进行中的归并。会话令牌只保存摘要，审计记录不保存明文密码或令牌。
