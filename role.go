package gae_rbac

import (
	"fmt"

	"appengine"
	"appengine/datastore"
)

func (rbac *Rbac) CreateRole(rol Role) (*Role, error) {
	key := datastore.NewIncompleteKey(rbac.c, ROLE, nil)
	var intid int64
	err := datastore.RunInTransaction(rbac.c, func(c appengine.Context) error {
		key, err := datastore.Put(rbac.c, key, &role{rol.Name})
		intid = key.IntID()
		if err != nil {
			return err
		}
		var keys []*datastore.Key = make([]*datastore.Key, len(rol.Permissions))
		var rps []*role_permission = make([]*role_permission, len(rol.Permissions))
		for i, perm := range rol.Permissions {
			rps[i] = &role_permission{key.IntID(), perm.Id}
			keys[i] = datastore.NewIncompleteKey(rbac.c, ROLE_PERMISSION, nil)
		}
		_, err = datastore.PutMulti(rbac.c, keys, rps)
		if err != nil {
			return err
		}
		return nil
	}, nil)
	if err != nil {
		return nil, err
	}
	rol.Id = intid
	return &rol, nil
}

func (rbac *Rbac) GetRoleByName(roleName string) (error, Role) {
	var roles []role
	keys, err := datastore.NewQuery(ROLE).Filter("Role =", roleName).GetAll(rbac.c, &roles)
	if err != nil {
		return err, Role{}
	}
	if len(roles) > 1 {
		return fmt.Errorf("Error. Duplicated roles found: %s.", roleName), Role{}
	}
	if len(roles) == 0 {
		return fmt.Errorf("Error. Role: %s not found.", roleName), Role{}
	}
	return nil, Role{roles[0].Role, nil, keys[0].IntID()}
}

func (rbac *Rbac) GetRoles(ids []int64, withPermission bool) ([]Role, error) {
	keys := make([]*datastore.Key, len(ids))
	for i, id := range ids {
		keys[i] = datastore.NewKey(rbac.c, ROLE, "", id, nil)
	}
	var rols []role = make([]role, len(ids))
	err := datastore.GetMulti(rbac.c, keys, rols)
	if err != nil {
		return nil, err
	}
	var roles []Role = make([]Role, len(rols))
	for i, rol := range rols {
		r := Role{Name: rol.Role, Id: ids[i]}
		if withPermission {
			q := datastore.NewQuery(ROLE_PERMISSION).Filter("RoleId =", ids[i])
			var rps []role_permission
			_, err = q.GetAll(rbac.c, &rps)
			if err != nil {
				return nil, err
			}
			permIds := make([]int64, len(rps))
			for i, rp := range rps {
				permIds[i] = rp.PermissionId
			}
			r.Permissions, err = rbac.GetPermissions(permIds)
			if err != nil {
				return nil, err
			}
		}
		roles[i] = r
	}
	return roles, nil
}

func (rbac *Rbac) GetAllRoles() ([]Role, error) {
	q := datastore.NewQuery(ROLE)
	count, err := q.Count(rbac.c)
	if err != nil {
		return nil, err
	}
	t := q.Run(rbac.c)
	gotError := false
	var roles []Role = make([]Role, count)
	i := 0
	for {
		var p role
		key, err := t.Next(&p)
		if err == datastore.Done {
			break
		}
		if err != nil {
			gotError = true
			break
		}
		r := Role{Name: p.Role, Id: key.IntID()}

		q := datastore.NewQuery(ROLE_PERMISSION).Filter("RoleId =", key.IntID())
		var rps []role_permission
		_, err = q.GetAll(rbac.c, &rps)
		if err != nil {
			return nil, err
		}
		permIds := make([]int64, len(rps))
		for i, rp := range rps {
			permIds[i] = rp.PermissionId
		}
		r.Permissions, err = rbac.GetPermissions(permIds)
		if err != nil {
			return nil, err
		}
		roles[i] = r
		i++
	}
	if gotError {
		return nil, err
	}
	return roles, nil
}

func (rbac *Rbac) DeleteRoles(ids []int64) error {
	keys := make([]*datastore.Key, len(ids))
	for i, id := range ids {
		keys[i] = datastore.NewKey(rbac.c, ROLE, "", id, nil)
	}
	err := datastore.RunInTransaction(rbac.c, func(c appengine.Context) error {
		err := datastore.DeleteMulti(rbac.c, keys)
		if err != nil {
			return err
		}
		for _, id := range ids {
			q := datastore.NewQuery(ROLE_PERMISSION).Filter("RoleId =", id).KeysOnly()
			keys, err := q.GetAll(rbac.c, nil)
			if err != nil {
				return err
			}
			err = datastore.DeleteMulti(rbac.c, keys)
			if err != nil {
				return err
			}
			q = datastore.NewQuery(IDENTITY_ROLE).Filter("RoleId =", id).KeysOnly()
			keys, err = q.GetAll(rbac.c, nil)
			if err != nil {
				return err
			}
			err = datastore.DeleteMulti(rbac.c, keys)
			if err != nil {
				return err
			}
		}
		return nil
	}, nil)
	return err
}
func (rbac *Rbac) UpdateRole(id int64, newRole Role) error {
	key := datastore.NewKey(rbac.c, ROLE, "", id, nil)

	err := datastore.RunInTransaction(rbac.c, func(c appengine.Context) error {
		_, err := datastore.Put(rbac.c, key, &role{newRole.Name})
		if err != nil {
			return err
		}
		q := datastore.NewQuery(ROLE_PERMISSION).Filter("RoleId =", id).KeysOnly()
		keys, err := q.GetAll(rbac.c, nil)
		if err != nil {
			return err
		}
		err = datastore.DeleteMulti(rbac.c, keys)
		if err != nil {
			return err
		}
		var keysPerm []*datastore.Key = make([]*datastore.Key, len(newRole.Permissions))
		var rps []*role_permission = make([]*role_permission, len(newRole.Permissions))
		for i, perm := range newRole.Permissions {
			rps[i] = &role_permission{id, perm.Id}
			keysPerm[i] = datastore.NewIncompleteKey(rbac.c, ROLE_PERMISSION, nil)
		}
		_, err = datastore.PutMulti(rbac.c, keysPerm, rps)
		if err != nil {
			return err
		}
		return nil
	}, nil)

	return err
}
