# Golang Role Based Access Control for Google App Engine
## Installation
> go get github.com/tianhai82/gae_rbac

## Usage
```Golang
import (
	"appengine"
	"github.com/tianhai82/gae_rbac"
)
c := appengine.NewContext(r)

// Create new rbac instance
rbac := New(c)

// Add user ID to role
rbac.AddUseridsToRole([]string{"ahmad", "Lionel"}, "role1")

// Give permision to role
rbac.GivePermissionsToRole([]string{"read_files", "write_files"}, "role1")

//check for permission
permissionAhmad := rbac.HasPermission("ahmad", "read_files")
permissionLionel := rbac.HasPermission("Lionel", "write_files")

// revoking permission from role
rbac.RevokePermissionFromRole("read_files", "role1")

// deleting user ID from role
rbac.DeleteUserIdFromRole("ahmad", "role1")

// remove role
rbac.RemoveRole("role1")

// take away all permission from a user
rbac.RemoveUserIdFromAllRoles("ahmad")

// revoke permission from all roles
rbac.RemovePermissionFromAllRoles("write_files")
```