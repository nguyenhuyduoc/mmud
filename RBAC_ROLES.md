# TeamVault RBAC - Role-Based Access Control

## Roles & Permissions Matrix

| Role | Read | Edit | Share | Delete | Use Case |
|------|------|------|-------|--------|----------|
| **owner** | ✅ | ✅ | ✅ | ✅ | Secret creator, full control |
| **editor** | ✅ | ✅ | ✅ | ❌ | Trusted collaborators, can modify |
| **sharer** | ✅ | ❌ | ✅ | ❌ | Distribution only, read + share |
| **viewer** | ✅ | ❌ | ❌ | ❌ | Read-only access |

## Role Descriptions

### Owner
- Full control over the secret
- Can delete the secret
- Automatically assigned to creator
- Cannot be changed or removed

### Editor
- Can edit secret content
- Can share with others
- Cannot delete the secret
- Ideal for team collaborators

### Sharer (NEW!)
- **Read-only access to content**
- **Can share with others**
- Cannot edit or delete
- **Perfect for: Distribution teams, customer support, sales**

### Viewer
- Read-only access
- Cannot modify or share
- Lowest privilege level

## Example Use Cases

### Sharer Role
```javascript
// Marketing team member receives API docs
// Role: 'sharer'
// Can: Read docs, share to sales team
// Cannot: Edit the docs
```

### Editor Role
```javascript
// DevOps team member
// Role: 'editor'
// Can: Read, edit deployment configs, share to team
// Cannot: Delete the secret
```

### Viewer Role
```javascript
// Contractor or temporary access
// Role: 'viewer'
// Can: Only read the secret
// Cannot: Edit, share, or delete
```

## Sharing Flow

```
Owner (Alice) creates secret
  ↓
Shares with Bob as 'sharer'
  ↓
Bob can read + share (but not edit)
  ↓
Bob shares with Carol as 'viewer'
  ↓
Carol can only read
```

## Permission Inheritance

- Permissions are granted per secret
- No role can grant higher permissions than they have
- Sharing creates new access entries, doesn't transfer ownership
