## 创业模拟决策系统（重建版）

当前已恢复可运行主链路，并补齐 **MVP 业务（内存态）**：公司、黄金账本、三原料开采、原料市场挂单/撤单/买入、我的交易列表；管理员发放黄金。

- 学生示例账号：`student1` / `student123`（也可用 `student` 或 `student2`，密码同为 `student123`）
- 管理员账号：`admin` / `admin123`

### 1) 启动后端

```powershell
cd D:\cursorWorks\backend
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --port 8010
```

### 2) 打开前端

直接打开：

`D:\cursorWorks\frontend\index.html`

登录默认账号：

- 用户名：`admin`
- 密码：`admin123`

### 3) 使用顺序（建议）

1. 用 **student1** 登录 →「团队/公司」创建公司  
2. 退出，用 **admin** 登录 →「管理员」里粘贴该学生的 **company_id**（总览里创建成功会显示；或黄金页里的 company_id）发放黄金  
3. 再用 **student1** 登录 → 开采 → 市场挂单 → 另一账号买入（或同账号无法自买，需第二个学生账号时再扩展）

### 3.1) 公司转账（学生端）

学生端新增「公司转账」页（公司之间黄金转账）：

- 先确保两家公司都已创建
- 付款方在「公司转账」选择收款公司与金额提交
- 双方黄金账本会分别出现 `transfer_out` / `transfer_in` 记录

数据均在进程内存中，**重启后端会清空**。

### 4) 下一步

- 合同中心、PostgreSQL 持久化、与昨天一致的权限/审计细节。

