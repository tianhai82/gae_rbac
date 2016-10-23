package gae_rbac

import (
	"appengine"
	"appengine/datastore"
)

func (rbac *Rbac) CreatePermission(perm string) (*Permission, error) {
	key := datastore.NewIncompleteKey(rbac.c, PERMISSION, nil)
	key1, err := datastore.Put(rbac.c, key, &permission{perm})
	if err != nil {
		return nil, err
	} else {
		return &Permission{perm, key1.IntID()}, nil
	}
}

func (rbac *Rbac) GetPermissions(ids []int64) ([]Permission, error) {
	keys := make([]*datastore.Key, len(ids))
	for i, id := range ids {
		keys[i] = datastore.NewKey(rbac.c, PERMISSION, "", id, nil)
	}

	var perms []permission = make([]permission, len(ids))
	err := datastore.GetMulti(rbac.c, keys, perms)
	if err != nil {
		return nil, err
	}
	permissions := make([]Permission, len(perms))
	for i, perm := range perms {
		permissions[i] = Permission{perm.Permission, keys[i].IntID()}
	}
	return permissions, nil
}
func (rbac *Rbac) GetAllPermissions() ([]Permission, error) {
	q := datastore.NewQuery(PERMISSION)
	count, err := q.Count(rbac.c)
	if err != nil {
		return nil, err
	}
	t := q.Run(rbac.c)
	gotError := false
	var permissions []Permission = make([]Permission, count)
	i := 0
	for {
		var p permission
		key, err := t.Next(&p)
		if err == datastore.Done {
			break
		}
		if err != nil {
			gotError = true
			break
		}
		permissions[i] = Permission{p.Permission, key.IntID()}
		i++
	}
	if gotError {
		return nil, err
	}
	return permissions, nil
}

func (rbac *Rbac) DeletePermissions(ids []int64) error {
	keys := make([]*datastore.Key, len(ids))
	for i, id := range ids {
		keys[i] = datastore.NewKey(rbac.c, PERMISSION, "", id, nil)
	}

	err := datastore.RunInTransaction(rbac.c, func(c appengine.Context) error {
		err := datastore.DeleteMulti(rbac.c, keys)
		if err != nil {
			return err
		}
		for _, id := range ids {
			q := datastore.NewQuery(ROLE_PERMISSION).Filter("PermissionId =", id).KeysOnly()
			keys, err := q.GetAll(rbac.c, nil)
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
func (rbac *Rbac) UpdatePermission(id int64, newPerm string) error {
	key := datastore.NewKey(rbac.c, PERMISSION, "", id, nil)
	_, err := datastore.Put(rbac.c, key, &permission{newPerm})
	return err
}
