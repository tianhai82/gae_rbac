package gae_rbac

import (
	"appengine/aetest"
	"testing"
)

func TestAddRoleAndPermission(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	if rbac.HasPermission("ahmad", "P1") {
		t.Fail()
	}
	rbac.AddUseridsToRole([]string{"AhMad", "Lionel"}, "role1")
	if rbac.HasPermission("ahmaD", "P1") {
		t.Fail()
	}
	rbac.GivePermissionsToRole([]string{"P1", "p2"}, "role1")
	if !rbac.HasPermission("ahmad", "P1") {
		t.Fail()
	}
	if !rbac.HasPermission("ahmad", "P2") {
		t.Fail()
	}
	if !rbac.HasPermission("lionel", "P1") {
		t.Fail()
	}
	if !rbac.HasPermission("lionel", "P2") {
		t.Fail()
	}
	if rbac.HasPermission("peter", "p1") {
		t.Fail()
	}
	if rbac.HasPermission("peter", "p2") {
		t.Fail()
	}
	rbac.GivePermissionsToRole([]string{"P3", "p4"}, "role2")
	if rbac.HasPermission("peter", "p3") {
		t.Fail()
	}
	if rbac.HasPermission("peter", "P4") {
		t.Fail()
	}
	rbac.AddUseridsToRole([]string{"PETER"}, "ROLE2")
	if !rbac.HasPermission("peter", "p3") {
		t.Fail()
	}
	if !rbac.HasPermission("peter", "P4") {
		t.Fail()
	}
}

func TestRevokePermissionFromRole(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	rbac.AddUseridsToRole([]string{"AhMad", "Lionel"}, "role1")
	rbac.GivePermissionsToRole([]string{"P1", "p2"}, "role1")
	rbac.AddUseridsToRole([]string{"AhMad"}, "role2")
	rbac.GivePermissionsToRole([]string{"P1", "p4"}, "role2")
	if !rbac.HasPermission("ahmad", "P1") {
		t.Errorf("ahmad should have p1")
	}
	if !rbac.HasPermission("lionel", "P2") {
		t.Errorf("lionel should have p2")
	}
	rbac.RevokePermissionFromRole("p1", "role1")
	if rbac.HasPermission("lionel", "P1") {
		t.Errorf("lionel should not have p1 anymore")
	}
	if !rbac.HasPermission("ahmad", "P2") {
		t.Errorf("ahmad should still have p2")
	}
	if !rbac.HasPermission("ahmad", "P1") {
		t.Errorf("ahmad should still have p1 inherited from role2")
	}
	rbac.RevokePermissionFromRole("p2", "role2")
	if !rbac.HasPermission("ahmad", "p2") {
		t.Errorf("ahmad should still have p2 as p2 is revoked for role2 only")
	}
	rbac.RevokePermissionFromRole("p2", "role1")
	if rbac.HasPermission("ahmad", "p2") {
		t.Errorf("ahmad should not longer have p2")
	}
	if rbac.HasPermission("lionel", "p2") {
		t.Errorf("lionel should not longer have p2")
	}
	rbac.GivePermissionsToRole([]string{"p2"}, "role1")
	if !rbac.HasPermission("lionel", "p2") {
		t.Errorf("lionel should have p2 as it is added back")
	}
	if !rbac.HasPermission("ahmad", "p2") {
		t.Errorf("ahmad should have p2 as it is added back")
	}
}

func TestDeleteUserIdFromRole(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	rbac.AddUseridsToRole([]string{"AhMad", "Lionel"}, "role1")
	rbac.AddUseridsToRole([]string{"AhMad", "Lionel"}, "role2")
	rbac.GivePermissionsToRole([]string{"P1", "p2"}, "role1")
	rbac.GivePermissionsToRole([]string{"P5", "p2"}, "role2")
	if !rbac.HasPermission("ahmad", "P1") {
		t.Errorf("ahmad should have p1")
	}
	if !rbac.HasPermission("lionel", "P2") {
		t.Errorf("lionel should have p2")
	}
	rbac.DeleteUserIdFromRole("ahmad", "role1")
	if rbac.HasPermission("ahmad", "P1") {
		t.Errorf("ahmad is removed from role1 - p1")
	}
	if !rbac.HasPermission("ahmad", "P2") {
		t.Errorf("ahmad is removed from role1 but role 2 still contains p2")
	}
	if !rbac.HasPermission("lionel", "P2") {
		t.Errorf("lionel should have p2")
	}
	rbac.AddUseridsToRole([]string{"ahmad"}, "role1")
	if !rbac.HasPermission("ahmad", "P1") {
		t.Errorf("ahmad should have p1")
	}
}

func TestRemoveRole(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	rbac.AddUseridsToRole([]string{"AhMad", "Lionel"}, "role1")
	rbac.AddUseridsToRole([]string{"AhMad", "Lionel"}, "role2")
	rbac.GivePermissionsToRole([]string{"P1", "p2"}, "role1")
	rbac.GivePermissionsToRole([]string{"P1", "p3"}, "role2")
	if !rbac.HasPermission("ahmad", "P1") {
		t.Errorf("ahmad should have p1")
	}
	if !rbac.HasPermission("lionel", "P2") {
		t.Errorf("lionel should have p2")
	}
	rbac.RemoveRole("role1")
	if !rbac.HasPermission("ahmad", "P1") {
		t.Errorf("ahmad should still have p1 as he is in role2")
	}
	if rbac.HasPermission("lionel", "P2") {
		t.Errorf("lionel should not have p2")
	}
}

func TestRemoveUserIdFromAllRoles(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	rbac.AddUseridsToRole([]string{"AhMad", "Lionel"}, "role1")
	rbac.AddUseridsToRole([]string{"AhMad", "Lionel"}, "role2")
	rbac.GivePermissionsToRole([]string{"P1", "p2"}, "role1")
	rbac.GivePermissionsToRole([]string{"P1", "p3"}, "role2")
	if !rbac.HasPermission("ahmad", "P1") {
		t.Errorf("ahmad should have p1")
	}
	if !rbac.HasPermission("lionel", "P2") {
		t.Errorf("lionel should have p2")
	}
	rbac.RemoveUserIdFromAllRoles("ahmad")
	if rbac.HasPermission("ahmad", "P1") {
		t.Errorf("ahmad no longer have p1")
	}
	if rbac.HasPermission("ahmad", "P2") {
		t.Errorf("ahmad no longer have p1")
	}
	if rbac.HasPermission("ahmad", "P3") {
		t.Errorf("ahmad no longer have p1")
	}

	if !rbac.HasPermission("lionel", "P1") {
		t.Errorf("lionel should have p1")
	}
	if !rbac.HasPermission("lionel", "P2") {
		t.Errorf("lionel should have p1")
	}
	if !rbac.HasPermission("lionel", "P3") {
		t.Errorf("lionel should have p1")
	}
	rbac.AddUseridsToRole([]string{"AhMad", "john"}, "role2")
	if !rbac.HasPermission("ahmad", "P1") {
		t.Errorf("ahmad added back to role2")
	}
	if rbac.HasPermission("ahmad", "P2") {
		t.Errorf("ahmad added back to role2 only")
	}
	if !rbac.HasPermission("ahmad", "P3") {
		t.Errorf("ahmad added back to role2")
	}
}

func TestRemovePermissionFromAllRoles(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	rbac.AddUseridsToRole([]string{"AhMad", "Lionel"}, "role1")
	rbac.AddUseridsToRole([]string{"peter", "Lionel"}, "role2")
	rbac.GivePermissionsToRole([]string{"P1", "p2"}, "role1")
	rbac.GivePermissionsToRole([]string{"P1", "p3"}, "role2")
	rbac.RemovePermissionFromAllRoles("p1")
	if rbac.HasPermission("ahmad", "P1") {
		t.Errorf("p1 already removed ")
	}
	if !rbac.HasPermission("ahmad", "P2") {
		t.Errorf("p2 not removed")
	}
	if rbac.HasPermission("peter", "P1") {
		t.Errorf("p1 already removed ")
	}
	rbac.GivePermissionsToRole([]string{"p1", "p5"}, "role1")
	if !rbac.HasPermission("ahmad", "P1") {
		t.Errorf("p1 added back ")
	}
	if !rbac.HasPermission("ahmad", "P2") {
		t.Errorf("p2 not removed ")
	}
	if !rbac.HasPermission("ahmad", "P5") {
		t.Errorf("p5 added")
	}
	if rbac.HasPermission("peter", "P1") {
		t.Errorf("p1 only added back to role1 not role2")
	}
}
