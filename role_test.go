package gae_rbac

import (
	"appengine/aetest"
	"testing"
	"time"
)

func containsRole(roles []Role, rol Role, withPerm bool) bool {
	for _, r := range roles {
		if r.Name == rol.Name {
			if r.Id == rol.Id {
				if withPerm {
					if len(r.Permissions) == len(rol.Permissions) {
						for _, p := range r.Permissions {
							if !containsPermission(rol.Permissions, p.Name) {
								return false
							}
						}
						return true
					}
				} else {
					if len(r.Permissions) == 0 {
						return true
					}
				}
			}
		}
	}
	return false
}

func TestCreateGetRole(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	p1, _ := rbac.CreatePermission("p1")
	p2, _ := rbac.CreatePermission("p2")
	p3, _ := rbac.CreatePermission("p3")
	p4, _ := rbac.CreatePermission("p4")
	time.Sleep(500 * time.Millisecond)
	rol := Role{"role1", []Permission{*p1, *p2, *p3, *p4}, 0}
	t.Logf("original id %d", rol.Id)
	rol1, err := rbac.CreateRole(rol)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	t.Logf("rol name %s, id %d", rol1.Name, rol1.Id)
	if rol1.Name != "role1" {
		t.Errorf("Role created is of wrong name - %s", rol.Name)
	}
	if rol1.Id == 0 {
		t.Errorf("Role id should not be %d", rol.Id)
	}
	if len(rol1.Permissions) != 4 {
		t.Errorf("permission len is wrong")
	}
	if !containsPermission(rol1.Permissions, "p1") {
		t.Errorf("Role should contain p1")
	}
	if !containsPermission(rol1.Permissions, "p2") {
		t.Errorf("Role should contain p2")
	}
	if !containsPermission(rol1.Permissions, "p3") {
		t.Errorf("Role should contain p1")
	}
	if !containsPermission(rol1.Permissions, "p4") {
		t.Errorf("Role should contain p2")
	}
	getRols, err := rbac.GetRoles([]int64{rol1.Id}, true)
	if err != nil {
		t.Errorf("cannot get back rol: %s", err)
	}
	if len(getRols) != 1 {
		t.Errorf("wrong no. of roles returned")
	}
	if getRols[0].Name != "role1" {
		t.Errorf("wrong role name gotten, %s", getRols[0].Name)
	}
	if getRols[0].Id != rol1.Id {
		t.Errorf("Rol id gotten is different")
	}
	if len(getRols[0].Permissions) != 4 {
		t.Errorf("permission len is wrong")
	}
	if !containsPermission(getRols[0].Permissions, "p1") {
		t.Errorf("Role should contain p1")
	}
	if !containsPermission(getRols[0].Permissions, "p2") {
		t.Errorf("Role should contain p2")
	}
	if !containsPermission(getRols[0].Permissions, "p3") {
		t.Errorf("Role should contain p1")
	}
	if !containsPermission(getRols[0].Permissions, "p4") {
		t.Errorf("Role should contain p2")
	}
	for _, p := range getRols[0].Permissions {
		if p.Name == "p1" {
			if p.Id != p1.Id {
				t.Errorf("p1 id is wrong")
			}
		} else if p.Name == "p2" {
			if p.Id != p2.Id {
				t.Errorf("p2 id is wrong")
			}
		} else if p.Name == "p3" {
			if p.Id != p3.Id {
				t.Errorf("p3 id is wrong")
			}
		} else if p.Name == "p4" {
			if p.Id != p4.Id {
				t.Errorf("p4 id is wrong")
			}
		}
	}
}
func TestGetRoles(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	p1, _ := rbac.CreatePermission("p1")
	p2, _ := rbac.CreatePermission("p2")
	p3, _ := rbac.CreatePermission("p3")
	p4, _ := rbac.CreatePermission("p4")
	time.Sleep(500 * time.Millisecond)
	rol1 := Role{"role1", []Permission{*p1}, 0}
	rol2 := Role{"role2", []Permission{*p2}, 0}
	rol3 := Role{"role3", []Permission{*p3}, 0}
	rol4 := Role{"role4", []Permission{*p4}, 0}

	role1, err := rbac.CreateRole(rol1)
	role2, err := rbac.CreateRole(rol2)
	role3, err := rbac.CreateRole(rol3)
	role4, err := rbac.CreateRole(rol4)
	time.Sleep(500 * time.Millisecond)
	roles, err := rbac.GetRoles([]int64{role1.Id, role2.Id, role4.Id}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 3 {
		t.Errorf("no. of roles returned is wrong")
	}
	if !containsRole(roles, *role1, true) {
		t.Errorf("role1 is not returned")
	}
	if !containsRole(roles, *role2, true) {
		t.Errorf("role2 is not returned")
	}
	if containsRole(roles, *role3, true) {
		t.Errorf("role3 should not be returned but is")
	}
	if !containsRole(roles, *role4, true) {
		t.Errorf("role4 is not returned")
	}
	for _, r := range roles {
		if r.Name == "role1" {
			if r.Id != role1.Id {
				t.Errorf("role1 id is wrong")
			}

		} else if r.Name == "role2" {
			if r.Id != role2.Id {
				t.Errorf("role2 id is wrong")
			}
		} else if r.Name == "role3" {
			t.Errorf("role3 should not be returned")
		} else if r.Name == "role4" {
			if r.Id != role4.Id {
				t.Errorf("role4 id is wrong")
			}
		}
	}

	roless, err := rbac.GetRoles([]int64{role1.Id, role3.Id, role4.Id}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(roless) != 3 {
		t.Errorf("no. of roles returned is wrong")
	}
	if !containsRole(roless, *role1, false) {
		t.Errorf("role1 is not returned")
	}
	if containsRole(roless, *role2, false) {
		t.Errorf("role2 should not be returned")
	}
	if !containsRole(roless, *role3, false) {
		t.Errorf("role3 is not returned")
	}
	if !containsRole(roless, *role4, false) {
		t.Errorf("role4 is not returned")
	}
	for _, r := range roless {
		if r.Name == "role1" {
			if r.Id != role1.Id {
				t.Errorf("role1 id is wrong")
			}
		} else if r.Name == "role2" {
			t.Errorf("role2 should not be returned")
		} else if r.Name == "role3" {
			if r.Id != role3.Id {
				t.Errorf("role3 id is wrong")
			}
		} else if r.Name == "role4" {
			if r.Id != role4.Id {
				t.Errorf("role4 id is wrong")
			}
		}
	}
}
func TestGetAllRoles(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	p1, _ := rbac.CreatePermission("p1")
	p2, _ := rbac.CreatePermission("p2")
	p3, _ := rbac.CreatePermission("p3")
	p4, _ := rbac.CreatePermission("p4")
	time.Sleep(500 * time.Millisecond)
	rol1 := Role{"role1", []Permission{*p1}, 0}
	rol2 := Role{"role2", []Permission{*p2}, 0}
	rol3 := Role{"role3", []Permission{*p3}, 0}
	rol4 := Role{"role4", []Permission{*p4}, 0}
	role1, err := rbac.CreateRole(rol1)
	role2, err := rbac.CreateRole(rol2)
	role3, err := rbac.CreateRole(rol3)
	role4, err := rbac.CreateRole(rol4)
	time.Sleep(500 * time.Millisecond)
	roles, err := rbac.GetAllRoles()
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 4 {
		t.Errorf("no. of roles returned is wrong")
	}
	if !containsRole(roles, *role1, true) {
		t.Errorf("role1 is not returned")
	}
	if !containsRole(roles, *role2, true) {
		t.Errorf("role2 is not returned")
	}
	if !containsRole(roles, *role3, true) {
		t.Errorf("role3 is not returned")
	}
	if !containsRole(roles, *role4, true) {
		t.Errorf("role4 is not returned")
	}
	for _, r := range roles {
		if r.Name == "role1" {
			if r.Id != role1.Id {
				t.Errorf("role1 id is wrong")
			}

		} else if r.Name == "role2" {
			if r.Id != role2.Id {
				t.Errorf("role2 id is wrong")
			}
		} else if r.Name == "role3" {
			if r.Id != role3.Id {
				t.Errorf("role3 id is wrong")
			}
		} else if r.Name == "role4" {
			if r.Id != role4.Id {
				t.Errorf("role4 id is wrong")
			}
		}
	}
}
func TestDeleteRoles(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	p1, _ := rbac.CreatePermission("p1")
	p2, _ := rbac.CreatePermission("p2")
	p3, _ := rbac.CreatePermission("p3")
	p4, _ := rbac.CreatePermission("p4")
	time.Sleep(500 * time.Millisecond)
	rol1 := Role{"role1", []Permission{*p1}, 0}
	rol2 := Role{"role2", []Permission{*p2}, 0}
	rol3 := Role{"role3", []Permission{*p3}, 0}
	rol4 := Role{"role4", []Permission{*p4}, 0}
	role1, err := rbac.CreateRole(rol1)
	role2, err := rbac.CreateRole(rol2)
	role3, err := rbac.CreateRole(rol3)
	role4, err := rbac.CreateRole(rol4)
	t.Log(role1)
	t.Log(role2)
	t.Log(role3)
	t.Log(role4)
	time.Sleep(500 * time.Millisecond)
	err = rbac.DeleteRoles([]int64{role1.Id, role3.Id})
	time.Sleep(500 * time.Millisecond)
	roless, err := rbac.GetAllRoles()
	time.Sleep(500 * time.Millisecond)
	t.Log(roless)
	if err != nil {
		t.Fatal(err)
	}
	if len(roless) != 2 {
		t.Errorf("no. of roles returned is wrong")
	}
	if containsRole(roless, *role1, true) {
		t.Errorf("role1 should not returned")
	}
	if !containsRole(roless, *role2, true) {
		t.Errorf("role2 is not returned")
	}
	if containsRole(roless, *role3, true) {
		t.Errorf("role3 should not returned")
	}
	if !containsRole(roless, *role4, true) {
		t.Errorf("role4 is not returned")
	}
	for _, r := range roless {
		if r.Name == "role1" {
			t.Errorf("role1 should not be there")
		} else if r.Name == "role2" {
			if r.Id != role2.Id {
				t.Errorf("role2 id is wrong")
			}
		} else if r.Name == "role3" {
			t.Errorf("role3 should not be there")
		} else if r.Name == "role4" {
			if r.Id != role4.Id {
				t.Errorf("role4 id is wrong")
			}
		}
	}
}
func TestUpdateRoles(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	p1, _ := rbac.CreatePermission("p1")
	p2, _ := rbac.CreatePermission("p2")
	p3, _ := rbac.CreatePermission("p3")
	p4, _ := rbac.CreatePermission("p4")
	time.Sleep(500 * time.Millisecond)
	rol1 := Role{"role1", []Permission{*p1}, 0}
	rol2 := Role{"role2", []Permission{*p2}, 0}
	rol3 := Role{"role3", []Permission{*p3}, 0}
	rol4 := Role{"role4", []Permission{*p4}, 0}
	role1, err := rbac.CreateRole(rol1)
	role2, err := rbac.CreateRole(rol2)
	_, err = rbac.CreateRole(rol3)
	_, err = rbac.CreateRole(rol4)
	time.Sleep(500 * time.Millisecond)
	rol1.Name = "role1new"
	err = rbac.UpdateRole(role1.Id, rol1)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	roles, err := rbac.GetRoles([]int64{role1.Id}, true)
	if roles[0].Id != role1.Id {
		t.Errorf("role1 id should not change")
	}
	if roles[0].Name != "role1new" {
		t.Errorf("role1 name is not updated correctly")
	}
	if !containsPermission(roles[0].Permissions, "p1") {
		t.Errorf("role1 does not contain p1")
	}
	rol2.Permissions = []Permission{*p3, *p4}
	t.Log(rol2)
	err = rbac.UpdateRole(role2.Id, rol2)
	time.Sleep(500 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	roles2, err := rbac.GetRoles([]int64{role2.Id}, true)
	time.Sleep(500 * time.Millisecond)
	t.Log(rol2)
	if roles2[0].Id != role2.Id {
		t.Errorf("role2 id should not change")
	}
	if roles2[0].Name != "role2" {
		t.Errorf("role2 name should not be changed")
	}
	if len(roles2[0].Permissions) != 2 {
		t.Errorf("role2 permission is not updated properly")
	}
	if !containsPermission(roles2[0].Permissions, "p3") {
		t.Errorf("role2 permission does not contain p3")
	}
	if !containsPermission(roles2[0].Permissions, "p4") {
		t.Errorf("role2 permission does not contain p4")
	}
}
