package gae_rbac

import (
	"appengine/aetest"
	"testing"
	"time"
)

func TestHasPermission(t *testing.T) {
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

	user1 := User{"user1", "user1name", []Role{*role1, *role2}, 0}
	user2 := User{"user2", "user2name", []Role{*role3, *role4}, 0}
	_, err = rbac.CreateUser(user1)
	_, err = rbac.CreateUser(user2)
	time.Sleep(500 * time.Millisecond)
	if !rbac.HasPermission("user1", "p1") {
		t.Errorf("user1 should have p1 permission")
	}
	if !rbac.HasPermission("user1", "p2") {
		t.Errorf("user1 should have p2 permission")
	}
	if rbac.HasPermission("user1", "p3") {
		t.Errorf("user1 should not have p3 permission")
	}
	if rbac.HasPermission("user1", "p4") {
		t.Errorf("user1 should not have p4 permission")
	}
	if rbac.HasPermission("user2", "p1") {
		t.Errorf("user1 should not have p1 permission")
	}
	if rbac.HasPermission("user2", "p2") {
		t.Errorf("user1 should not have p2 permission")
	}
	if !rbac.HasPermission("user2", "p3") {
		t.Errorf("user1 should have p3 permission")
	}
	if !rbac.HasPermission("user2", "p4") {
		t.Errorf("user1 should have p4 permission")
	}
}

func BenchmarkAppendPermission(b *testing.B) {

	for i := 0; i < b.N; i++ {
		var ps []Permission
		for j := 0; j < 10; j++ {
			ps = append(ps, Permission{"perm1", 1268})
		}
	}
}
func BenchmarkAllocatePermission(b *testing.B) {

	for i := 0; i < b.N; i++ {
		ps := make([]Permission, 10)
		for j := 0; j < 10; j++ {
			ps[j] = Permission{"perm1", 1268}
		}
	}
}
