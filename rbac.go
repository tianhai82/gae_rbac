package gae_rbac

import (
	"appengine"
)

const (
	IDENTITY        = "_identity"
	PERMISSION      = "_permission"
	ROLE            = "_role"
	IDENTITY_ROLE   = "_identity_role"
	ROLE_PERMISSION = "_role_permission"
)

type permission struct {
	Permission string
}
type role struct {
	Role string
}
type identity struct {
	Userid   string
	Username string
}
type identity_role struct {
	IdentityId int64
	RoleId     int64
}
type role_permission struct {
	RoleId       int64
	PermissionId int64
}

type Role struct {
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
	Id          int64        `json:"id"`
}
type User struct {
	Userid   string `json:"userid"`
	Username string `json:"username"`
	Roles    []Role `json:"roles"`
	Id       int64  `json:"id"`
}
type Permission struct {
	Name string `json:"name"`
	Id   int64  `json:"id"`
}
type Rbac struct {
	c appengine.Context
}

func New(context appengine.Context) *Rbac {
	return &Rbac{context}
}

func (rbac *Rbac) HasPermission(userid string, permission string) bool {
	users, err := rbac.GetUsers([]string{userid}, true)
	if err != nil || users == nil || len(users) != 1 {
		return false
	}
	var roleIds []int64 = make([]int64, len(users[0].Roles))
	for i, role := range users[0].Roles {
		roleIds[i] = role.Id
	}
	roles, err := rbac.GetRoles(roleIds, true)
	if err != nil {
		return false
	}
	for _, r := range roles {
		for _, p := range r.Permissions {
			if p.Name == permission {
				return true
			}
		}
	}
	return false
}
