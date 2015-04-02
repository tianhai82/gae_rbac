package gae_rbac

import (
	"appengine"
	"appengine/datastore"
	"strings"
)

type identity_role struct {
	Identity string
	Role     string
}

type role_permission struct {
	Role       string
	Permission string
}

type Rbac struct {
	c appengine.Context
}

func New(context appengine.Context) *Rbac {
	rbac := new(Rbac)
	rbac.c = context
	return rbac
}

func (rbac Rbac) AddUseridsToRole(userIds []string, role string) bool {
	var keys []*datastore.Key = make([]*datastore.Key, len(userIds))
	var obj []identity_role = make([]identity_role, len(userIds))
	role = strings.ToLower(role)

	for i, user := range userIds {
		user = strings.ToLower(user)
		userKey := datastore.NewKey(rbac.c, "identity", user, 0, nil)
		keys[i] = datastore.NewKey(rbac.c, "identity_role", user+":"+role, 0, userKey)
		obj[i] = identity_role{user, role}
	}
	if _, err := datastore.PutMulti(rbac.c, keys, obj); err != nil {
		return false
	} else {
		return true
	}
}

func (rbac Rbac) GivePermissionsToRole(permissions []string, role string) bool {
	var keys []*datastore.Key = make([]*datastore.Key, len(permissions))
	var obj []role_permission = make([]role_permission, len(permissions))
	role = strings.ToLower(role)
	for i, perm := range permissions {
		perm = strings.ToLower(perm)
		permKey := datastore.NewKey(rbac.c, "permission", perm, 0, nil)
		keys[i] = datastore.NewKey(rbac.c, "role_permission", role+":"+perm, 0, permKey)
		obj[i] = role_permission{role, perm}
	}
	if _, err := datastore.PutMulti(rbac.c, keys, obj); err != nil {
		return false
	} else {
		return true
	}
}

func (rbac Rbac) HasPermission(userId string, permission string) bool {
	permission = strings.ToLower(permission)
	userId = strings.ToLower(userId)
	userKey := datastore.NewKey(rbac.c, "identity", userId, 0, nil)
	q := datastore.NewQuery("identity_role").Filter("Identity =", userId).Ancestor(userKey)
	var idensRole []identity_role
	if _, err := q.GetAll(rbac.c, &idensRole); err != nil {
		return false
	}
	if len(idensRole) == 0 {
		return false
	}
	var rolePerms []role_permission
	permKey := datastore.NewKey(rbac.c, "permission", permission, 0, nil)
	q = datastore.NewQuery("role_permission").Filter("Permission =", permission).Ancestor(permKey)
	if _, err := q.GetAll(rbac.c, &rolePerms); err != nil {
		return false
	}
	if len(rolePerms) == 0 {
		return false
	}
	for _, idRole := range idensRole {
		for _, rlPerm := range rolePerms {
			if idRole.Role == rlPerm.Role {
				return true
			}
		}
	}
	return false
}

func (rbac Rbac) RevokePermissionFromRole(permission string, role string) error {
	permission = strings.ToLower(permission)
	role = strings.ToLower(role)
	permKey := datastore.NewKey(rbac.c, "permission", permission, 0, nil)
	key := datastore.NewKey(rbac.c, "role_permission", role+":"+permission, 0, permKey)
	return datastore.Delete(rbac.c, key)
}

func (rbac Rbac) DeleteUserIdFromRole(userId string, role string) error {
	userId = strings.ToLower(userId)
	role = strings.ToLower(role)
	userKey := datastore.NewKey(rbac.c, "identity", userId, 0, nil)
	key := datastore.NewKey(rbac.c, "identity_role", userId+":"+role, 0, userKey)
	return datastore.Delete(rbac.c, key)
}

func (rbac Rbac) RemoveRole(role string) error {
	role = strings.ToLower(role)
	q := datastore.NewQuery("role_permission").Filter("Role =", role).KeysOnly()
	var rolePerms []role_permission
	if keys, err := q.GetAll(rbac.c, &rolePerms); err == nil {
		if err2 := datastore.DeleteMulti(rbac.c, keys); err2 == nil {
			q = datastore.NewQuery("identity_role").Filter("Role =", role).KeysOnly()
			var idensRole []identity_role
			if keys2, err3 := q.GetAll(rbac.c, &idensRole); err3 == nil {
				return datastore.DeleteMulti(rbac.c, keys2)
			} else {
				return err3
			}
		} else {
			return err2
		}
	} else {
		return err
	}
}

func (rbac Rbac) RemoveUserIdFromAllRoles(userId string) error {
	userId = strings.ToLower(userId)
	userKey := datastore.NewKey(rbac.c, "identity", userId, 0, nil)
	q := datastore.NewQuery("identity_role").Filter("Identity =", userId).KeysOnly().Ancestor(userKey)
	var idensRole []identity_role
	if keys, err := q.GetAll(rbac.c, idensRole); err == nil {
		return datastore.DeleteMulti(rbac.c, keys)
	} else {
		return err
	}
}

func (rbac Rbac) RemovePermissionFromAllRoles(permission string) error {
	permission = strings.ToLower(permission)
	permKey := datastore.NewKey(rbac.c, "permission", permission, 0, nil)
	q := datastore.NewQuery("role_permission").Filter("Permission =", permission).KeysOnly().Ancestor(permKey)
	var rolePerms []role_permission
	if keys, err := q.GetAll(rbac.c, &rolePerms); err == nil {
		return datastore.DeleteMulti(rbac.c, keys)
	} else {
		return err
	}
}
