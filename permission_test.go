package gae_rbac

import (
	"appengine/aetest"
	"testing"
	"time"
)

func containsPermission(perms []Permission, name string) bool {
	for _, p := range perms {
		if p.Name == name {
			return true
		}
	}
	return false
}

func TestCreateGetPermission(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	perm, err := rbac.CreatePermission("p1")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("perm name %s, id %d", perm.Name, perm.Id)
	if perm.Name != "p1" {
		t.Errorf("Permission created is of wrong name - %s", perm.Name)
	}
	if perm.Id == 0 {
		t.Errorf("Permission id should not be %d", perm.Id)
	}
	getPerms, err := rbac.GetPermissions([]int64{perm.Id})

	if err != nil {
		t.Errorf("cannot get back perm: %s", err)
	}
	if len(getPerms) != 1 {
		t.Errorf("no of permissions retrieved is wrong")
	}
	if getPerms[0].Name != "p1" {
		t.Errorf("wrong permission name gotten, %s", getPerms[0].Name)
	}
	if getPerms[0].Id != perm.Id {
		t.Errorf("Perm id gotten is different")
	}
}
func TestGetPermissions(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	p1, _ := rbac.CreatePermission("p1")
	p2, _ := rbac.CreatePermission("p2")
	p3, _ := rbac.CreatePermission("p3")
	perms, err := rbac.GetPermissions([]int64{p1.Id, p2.Id, p3.Id})
	for _, perm := range perms {
		if perm.Name == "p1" {
			if perm.Id != p1.Id {
				t.Errorf("p1 id is wrong")
			}
		} else if perm.Name == "p2" {
			if perm.Id != p2.Id {
				t.Errorf("p2 id is wrong")
			}
		} else if perm.Name == "p3" {
			if perm.Id != p3.Id {
				t.Errorf("p3 id is wrong")
			}
		}
	}

}
func TestGetAllPermissions(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	rbac.CreatePermission("p1")
	rbac.CreatePermission("p2")
	rbac.CreatePermission("p3")
	time.Sleep(500 * time.Millisecond)
	permissions, err := rbac.GetAllPermissions()
	if err != nil {
		t.Fatal(err)
	}
	if len(permissions) != 3 {
		t.Errorf("wrong no of permissions returned, %d", len(permissions))
	}
	if !containsPermission(permissions, "p1") {
		t.Errorf("p1 is not returned")
	}
	if !containsPermission(permissions, "p2") {
		t.Errorf("p2 is not returned")
	}
	if !containsPermission(permissions, "p3") {
		t.Errorf("p3 is not returned")
	}
}
func TestDeletePermission(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	perm, _ := rbac.CreatePermission("p1")
	rbac.CreatePermission("p2")
	rbac.CreatePermission("p3")
	time.Sleep(500 * time.Millisecond)
	rbac.DeletePermissions([]int64{perm.Id})
	time.Sleep(500 * time.Millisecond)
	permissions, _ := rbac.GetAllPermissions()
	if len(permissions) != 2 {
		t.Errorf("wrong no of permissions returned, %d", len(permissions))
	}
	if containsPermission(permissions, "p1") {
		t.Errorf("p1 is should be already deleted")
	}
	if !containsPermission(permissions, "p2") {
		t.Errorf("p2 is not returned")
	}
	if !containsPermission(permissions, "p3") {
		t.Errorf("p3 is not returned")
	}
}
func TestUpdatePermission(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	perm, _ := rbac.CreatePermission("p1")
	rbac.CreatePermission("p2")
	rbac.CreatePermission("p3")
	time.Sleep(500 * time.Millisecond)
	rbac.UpdatePermission(perm.Id, "p5")
	time.Sleep(500 * time.Millisecond)
	permissions, _ := rbac.GetAllPermissions()
	if len(permissions) != 3 {
		t.Errorf("wrong no of permissions returned, %d", len(permissions))
	}
	if containsPermission(permissions, "p1") {
		t.Errorf("p1 is should be already updated")
	}
	if !containsPermission(permissions, "p2") {
		t.Errorf("p2 is not returned")
	}
	if !containsPermission(permissions, "p3") {
		t.Errorf("p3 is not returned")
	}
	if !containsPermission(permissions, "p5") {
		t.Errorf("p5 is not returned")
	}
}
