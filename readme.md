# RBAC Enhancements & Role-Audit Feature

## Overview
We’ve added a **Superadmin** tier on top of our existing roles, and built a full audit trail for every time someone’s role changes.  
Key points:
- Introduce an **AdminRole** column to distinguish “super” admins  
- Only superadmins can promote or demote other users  
- Every role change is recorded in a dedicated **RoleChangeAudit** log  
- Two new API endpoints for changing roles and viewing change history  

---

## Database & Schema Changes
- **New `admin_role` column** on the `users` table, tracking which admins have “SUPERADMIN” privileges  
- **New `role_change_audit` table** capturing:
  - user whose role was changed  
  - superadmin who made the change  
  - old role → new role  
  - timestamp of the change  

---

## Service Layer Updates
- **`change_role`** operation now:
  - Verifies the caller is a superadmin  
  - Updates the target user’s `role` field  
  - Inserts an audit record into `RoleChangeAudit`  
- All existing user-service methods remain unchanged, preserving backwards compatibility  

---

## New API Endpoints
1. **PATCH /users/{user_id}/role**  
   - Restrict: only superadmins may call  
   - Body: new role value  
   - Response: confirms the user’s new role  

2. **GET /users/{user_id}/role-history**  
   - Restrict: only superadmins may call  
   - Returns: list of past role­-change records, newest first  

---

## Authorization Changes
- **JWT payload** now includes both `role` and `admin_role` claims  
- **`get_current_user`** dependency surfaces the `admin_role`  
- **`require_superadmin`** guard checks for `admin_role == SUPERADMIN`  
- Existing role checks (`require_role([...])`) continue to enforce ADMIN/ MANAGER/ USER permissions  

---

## Testing & Quality
- **Unit tests** for:
  - Superadmin role-change logic  
  - Audit-record creation  
  - Permission rejection for non-superadmins  
- **Integration tests** for:
  - Role-change endpoint  
  - Role-history endpoint  
  - Standard CRUD endpoints under new RBAC rules  
- Target **> 90% coverage** on new service methods and routes  

---

## Usage Example
1. **Obtain a superadmin token** via the usual login flow  
2. **Change a user’s role** by sending a PATCH to `/users/{id}/role` with the desired new role  
3. **Fetch that user’s audit trail** with a GET to `/users/{id}/role-history`  

---

## Future Enhancements
- Paginate or filter the audit log by date or actor  
- Email notifications when roles change  
- Dashboard UI for visualizing role-change history  
- Support for additional high-privilege roles beyond SUPERADMIN  
