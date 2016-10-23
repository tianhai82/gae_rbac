package gae_rbac

import (
	"fmt"

	"appengine"
	"appengine/datastore"
)

func (rbac *Rbac) CreateUser(user User) (*User, error) {
	key := datastore.NewIncompleteKey(rbac.c, IDENTITY, nil)
	var intid int64
	err := datastore.RunInTransaction(rbac.c, func(c appengine.Context) error {
		key, err := datastore.Put(rbac.c, key, &identity{user.Userid, user.Username})
		intid = key.IntID()
		if err != nil {
			return err
		}
		var keys []*datastore.Key = make([]*datastore.Key, len(user.Roles))
		var irs []*identity_role = make([]*identity_role, len(user.Roles))
		for i, r := range user.Roles {
			irs[i] = &identity_role{intid, r.Id}
			keys[i] = datastore.NewIncompleteKey(rbac.c, IDENTITY_ROLE, nil)
		}
		_, err = datastore.PutMulti(rbac.c, keys, irs)
		if err != nil {
			return err
		}
		return nil
	}, nil)
	if err != nil {
		return nil, err
	}
	user.Id = intid
	return &user, nil
}

func (rbac *Rbac) GetUsers(userids []string, withRoles bool) ([]User, error) {
	var idens []identity = make([]identity, len(userids))
	var ids []int64 = make([]int64, len(userids))
	for i, uid := range userids {
		var idensTemp []identity
		keys, err := datastore.NewQuery(IDENTITY).Filter("Userid =", uid).GetAll(rbac.c, &idensTemp)
		if err != nil {
			return nil, err
		}
		if len(idensTemp) != 1 {
			return nil, fmt.Errorf("User: %s is not found", uid)
		}
		idens[i] = idensTemp[0]
		ids[i] = keys[0].IntID()
	}
	var users []User = make([]User, len(idens))
	for i, iden := range idens {
		u := User{Userid: iden.Userid, Username: iden.Username, Id: ids[i]}
		if withRoles {
			q := datastore.NewQuery(IDENTITY_ROLE).Filter("IdentityId =", ids[i])
			var irs []identity_role
			_, err := q.GetAll(rbac.c, &irs)
			if err != nil {
				return nil, err
			}
			roleIds := make([]int64, len(irs))
			for i, ir := range irs {
				roleIds[i] = ir.RoleId
			}
			u.Roles, err = rbac.GetRoles(roleIds, false)
			if err != nil {
				return nil, err
			}
		}
		users[i] = u
	}
	return users, nil
}

func (rbac *Rbac) GetAllUsers() ([]User, error) {
	q := datastore.NewQuery(IDENTITY)
	count, err := q.Count(rbac.c)
	if err != nil {
		return nil, err
	}
	t := q.Run(rbac.c)
	gotError := false
	var users []User = make([]User, count)
	i := 0
	for {
		var iden identity
		key, err := t.Next(&iden)
		if err == datastore.Done {
			break
		}
		if err != nil {
			gotError = true
			break
		}
		u := User{Username: iden.Username, Userid: iden.Userid, Id: key.IntID()}
		q := datastore.NewQuery(IDENTITY_ROLE).Filter("IdentityId =", key.IntID())
		var irs []identity_role
		_, err = q.GetAll(rbac.c, &irs)
		if err != nil {
			return nil, err
		}
		roleIds := make([]int64, len(irs))
		for i, ir := range irs {
			roleIds[i] = ir.RoleId
		}
		u.Roles, err = rbac.GetRoles(roleIds, false)
		if err != nil {
			return nil, err
		}
		users[i] = u
		i++
	}
	if gotError {
		return nil, err
	}
	return users, nil
}

func (rbac *Rbac) DeleteUsers(ids []int64) error {
	keys := make([]*datastore.Key, len(ids))
	for i, id := range ids {
		keys[i] = datastore.NewKey(rbac.c, IDENTITY, "", id, nil)
	}
	err := datastore.RunInTransaction(rbac.c, func(c appengine.Context) error {
		err := datastore.DeleteMulti(rbac.c, keys)
		if err != nil {
			return err
		}
		for _, id := range ids {
			q := datastore.NewQuery(IDENTITY_ROLE).Filter("IdentityId =", id).KeysOnly()
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

func (rbac *Rbac) UpdateUser(id int64, newUser User) error {
	key := datastore.NewKey(rbac.c, IDENTITY, "", id, nil)

	err := datastore.RunInTransaction(rbac.c, func(c appengine.Context) error {
		_, err := datastore.Put(rbac.c, key, &identity{newUser.Userid, newUser.Username})
		if err != nil {
			return err
		}
		q := datastore.NewQuery(IDENTITY_ROLE).Filter("IdentityId =", id).KeysOnly()
		keys, err := q.GetAll(rbac.c, nil)
		if err != nil {
			return err
		}
		err = datastore.DeleteMulti(rbac.c, keys)
		if err != nil {
			return err
		}
		var keysRoles []*datastore.Key = make([]*datastore.Key, len(newUser.Roles))
		var irs []*identity_role = make([]*identity_role, len(newUser.Roles))
		for i, r := range newUser.Roles {
			irs[i] = &identity_role{id, r.Id}
			keysRoles[i] = datastore.NewIncompleteKey(rbac.c, IDENTITY_ROLE, nil)
		}
		_, err = datastore.PutMulti(rbac.c, keysRoles, irs)
		if err != nil {
			return err
		}
		return nil
	}, nil)

	return err
}
