# AuthZ

独立权鉴服务（FastAPI + MySQL）。

## 运行

```bash
pip install -r requirements.txt
export DATABASE_URL='mysql+pymysql://user:password@localhost:3306/authz'
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## 数据表

```sql
CREATE TABLE user_system_role (
  user_id BIGINT NOT NULL,
  role_code ENUM(
    'SUPER_ADMIN',
    'DEPARTMENT_ADMIN',
    'PROJECT_ADMIN',
    'GROUP_ADMIN'
  ) NOT NULL,
  scope_type ENUM(
    'system',
    'department',
    'project',
    'group'
  ) NOT NULL,
  scope_id BIGINT NULL,
  granted_by BIGINT,
  granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, role_code, scope_type, scope_id)
);
```

需要业务提供组织关系表（用于授权校验）：

```sql
CREATE TABLE project (
  id BIGINT PRIMARY KEY,
  department_id BIGINT NOT NULL
);

CREATE TABLE `group` (
  id BIGINT PRIMARY KEY,
  project_id BIGINT NOT NULL
);
```

## 接口

### 健康检查

`GET /health`

用于服务探活，返回状态。

### 权限检查

`POST /authz/check`

用于判断用户是否拥有指定范围内的管理员角色。

请求体：

```json
{
  "user_id": 1,
  "role": "GROUP_ADMIN",
  "scope_type": "group",
  "scope_id": 10
}
```

响应：

```json
{
  "allowed": true
}
```

### 授权

`POST /authz/roles`

为用户授予单个管理员角色，包含层级授权校验。

请求体：

```json
{
  "user_id": 1,
  "role": "PROJECT_ADMIN",
  "scope_type": "project",
  "scope_id": 88,
  "granted_by": 1001
}
```

授权规则：

- SUPER_ADMIN 可授权 department / project / group
- DEPARTMENT_ADMIN 可授权其部门下的 project / group
- PROJECT_ADMIN 可授权其项目下的 group

### 批量授权

`POST /authz/roles/batch`

为同一用户批量授予多个管理员角色，包含层级授权校验。

请求体：

```json
{
  "user_id": 1,
  "granted_by": 1001,
  "items": [
    {
      "role": "PROJECT_ADMIN",
      "scope_type": "project",
      "scope_id": 88
    },
    {
      "role": "GROUP_ADMIN",
      "scope_type": "group",
      "scope_id": 10
    }
  ]
}
```

### 撤销授权

`DELETE /authz/roles`

移除用户在指定范围内的管理员角色。

请求体：

```json
{
  "user_id": 1,
  "role": "PROJECT_ADMIN",
  "scope_type": "project",
  "scope_id": 88
}
```

### 查询授权

`GET /authz/roles`

按条件筛选管理员角色分配记录。

查询参数：`user_id`, `role`, `scope_type`, `scope_id`

响应：

```json
{
  "items": [
    {
      "user_id": 1,
      "role": "PROJECT_ADMIN",
      "scope_type": "project",
      "scope_id": 88,
      "granted_by": 1001,
      "granted_at": "2024-01-01T10:00:00"
    }
  ]
}
```

### 管理员用户的组织范围列表

`GET /authz/users/{user_id}/groups`

返回用户管理的小组范围列表。

响应：

```json
{
  "items": [
    {
      "scope_id": 10,
      "role": "GROUP_ADMIN"
    }
  ]
}
```

`GET /authz/users/{user_id}/projects`

返回用户管理的项目范围列表。

`GET /authz/users/{user_id}/departments`

返回用户管理的部门范围列表。
