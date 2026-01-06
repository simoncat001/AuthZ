from sqlalchemy import text


class AuthzService:
    def __init__(self, db):
        self.db = db

    def check(self, user_id, role, scope_type, scope_id):
        sql = text(
            """
            SELECT 1 FROM user_system_role
            WHERE user_id = :uid
              AND role_code = :role
              AND scope_type = :stype
              AND (
                    :sid IS NULL
                 OR scope_id = :sid
              )
            LIMIT 1
            """
        )
        return (
            self.db.execute(
                sql,
                {
                    "uid": user_id,
                    "role": role,
                    "stype": scope_type,
                    "sid": scope_id,
                },
            ).fetchone()
            is not None
        )

    def grant_role(self, user_id, role, scope_type, scope_id, granted_by):
        sql = text(
            """
            INSERT INTO user_system_role (
                user_id, role_code, scope_type, scope_id, granted_by
            ) VALUES (
                :uid, :role, :stype, :sid, :granted_by
            )
            ON DUPLICATE KEY UPDATE
                granted_by = VALUES(granted_by),
                granted_at = CURRENT_TIMESTAMP
            """
        )
        self.db.execute(
            sql,
            {
                "uid": user_id,
                "role": role,
                "stype": scope_type,
                "sid": scope_id,
                "granted_by": granted_by,
            },
        )
        self.db.commit()

    def grant_roles_batch(self, user_id, items, granted_by):
        sql = text(
            """
            INSERT INTO user_system_role (
                user_id, role_code, scope_type, scope_id, granted_by
            ) VALUES (
                :uid, :role, :stype, :sid, :granted_by
            )
            ON DUPLICATE KEY UPDATE
                granted_by = VALUES(granted_by),
                granted_at = CURRENT_TIMESTAMP
            """
        )
        for item in items:
            self.db.execute(
                sql,
                {
                    "uid": user_id,
                    "role": item["role"],
                    "stype": item["scope_type"],
                    "sid": item["scope_id"],
                    "granted_by": granted_by,
                },
            )
        self.db.commit()

    def can_grant(self, grantor_id, role, scope_type, scope_id):
        expected_role = {
            "system": "SUPER_ADMIN",
            "department": "DEPARTMENT_ADMIN",
            "project": "PROJECT_ADMIN",
            "group": "GROUP_ADMIN",
        }
        if scope_type not in expected_role:
            return False, "unsupported_scope_type"
        if role != expected_role[scope_type]:
            return False, "role_scope_mismatch"
        if scope_type in {"project", "group"} and scope_id is None:
            return False, "scope_id_required"
        if self.check(grantor_id, "SUPER_ADMIN", "system", None):
            return True, ""
        if scope_type == "system":
            return False, "insufficient_permission"
        if scope_type == "department":
            return False, "insufficient_permission"
        if scope_type == "project":
            department_id = self.get_project_department_id(scope_id)
            if department_id is None:
                return False, "project_not_found"
            if self.check(grantor_id, "DEPARTMENT_ADMIN", "department", department_id):
                return True, ""
            return False, "insufficient_permission"
        if scope_type == "group":
            project_id = self.get_group_project_id(scope_id)
            if project_id is None:
                return False, "group_not_found"
            if self.check(grantor_id, "PROJECT_ADMIN", "project", project_id):
                return True, ""
            department_id = self.get_project_department_id(project_id)
            if department_id is None:
                return False, "project_not_found"
            if self.check(grantor_id, "DEPARTMENT_ADMIN", "department", department_id):
                return True, ""
            return False, "insufficient_permission"
        return False, "insufficient_permission"

    def get_project_department_id(self, project_id):
        sql = text(
            """
            SELECT department_id
            FROM project
            WHERE id = :pid
            """
        )
        row = self.db.execute(sql, {"pid": project_id}).fetchone()
        return row.department_id if row else None

    def get_group_project_id(self, group_id):
        sql = text(
            """
            SELECT project_id
            FROM `group`
            WHERE id = :gid
            """
        )
        row = self.db.execute(sql, {"gid": group_id}).fetchone()
        return row.project_id if row else None

    def revoke_role(self, user_id, role, scope_type, scope_id):
        if scope_id is None:
            sql = text(
                """
                DELETE FROM user_system_role
                WHERE user_id = :uid
                  AND role_code = :role
                  AND scope_type = :stype
                  AND scope_id IS NULL
                """
            )
            params = {"uid": user_id, "role": role, "stype": scope_type}
        else:
            sql = text(
                """
                DELETE FROM user_system_role
                WHERE user_id = :uid
                  AND role_code = :role
                  AND scope_type = :stype
                  AND scope_id = :sid
                """
            )
            params = {
                "uid": user_id,
                "role": role,
                "stype": scope_type,
                "sid": scope_id,
            }
        self.db.execute(sql, params)
        self.db.commit()

    def list_roles(self, user_id=None, role=None, scope_type=None, scope_id=None):
        clauses = []
        params = {}

        if user_id is not None:
            clauses.append("user_id = :uid")
            params["uid"] = user_id
        if role is not None:
            clauses.append("role_code = :role")
            params["role"] = role
        if scope_type is not None:
            clauses.append("scope_type = :stype")
            params["stype"] = scope_type
            if scope_type == "system" and scope_id is None:
                clauses.append("scope_id IS NULL")
        if scope_id is not None:
            clauses.append("scope_id = :sid")
            params["sid"] = scope_id

        where_clause = ""
        if clauses:
            where_clause = "WHERE " + " AND ".join(clauses)

        sql = text(
            f"""
            SELECT user_id, role_code, scope_type, scope_id, granted_by, granted_at
            FROM user_system_role
            {where_clause}
            ORDER BY granted_at DESC
            """
        )
        rows = self.db.execute(sql, params).fetchall()
        return [
            {
                "user_id": row.user_id,
                "role": row.role_code,
                "scope_type": row.scope_type,
                "scope_id": row.scope_id,
                "granted_by": row.granted_by,
                "granted_at": row.granted_at,
            }
            for row in rows
        ]

    def list_user_scopes(self, user_id, scope_type):
        sql = text(
            """
            SELECT scope_id, role_code
            FROM user_system_role
            WHERE user_id = :uid
              AND scope_type = :stype
            ORDER BY scope_id ASC
            """
        )
        rows = self.db.execute(
            sql,
            {
                "uid": user_id,
                "stype": scope_type,
            },
        ).fetchall()
        return [
            {
                "scope_id": row.scope_id,
                "role": row.role_code,
            }
            for row in rows
        ]
