package gae_rbac

import (
	"appengine/aetest"
	"testing"
	"time"
)

func TestCreateGetUser(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	rol1, _ := rbac.CreateRole(Role{"role1", []Permission{}, 0})
	rol2, _ := rbac.CreateRole(Role{"role2", []Permission{}, 0})
	time.Sleep(500 * time.Millisecond)
	user := User{"user1", "user1name", []Role{*rol1, *rol2}, 0}
	usr, err := rbac.CreateUser(user)
	if err != nil {
		t.Fatal(err)
	}
	if usr.Id == 0 {
		t.Errorf("user id should not be 0")
	}
	time.Sleep(500 * time.Millisecond)
	users, err := rbac.GetUsers([]string{"user1"}, true)
	if err != nil {
		t.Errorf("error calling GetUsers: %s", err)
	}
	time.Sleep(500 * time.Millisecond)
	if len(users) != 1 {
		t.Errorf("no of users returned is wrong")
	}
	if users[0].Id != usr.Id {
		t.Errorf("user id is wrong")
	}
	if users[0].Userid != "user1" {
		t.Errorf("username is wrong")
	}
	if users[0].Username != "user1name" {
		t.Errorf("username is wrong")
	}
	if len(users[0].Roles) != 2 {
		t.Errorf("no of roles in users is wrong")
	}
	if !containsRole(users[0].Roles, *rol1, false) {
		t.Errorf("role1 is not in user")
	}
	if !containsRole(users[0].Roles, *rol2, false) {
		t.Errorf("role2 is not in user")
	}
}
func TestGetUsers(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	rol1, _ := rbac.CreateRole(Role{"role1", []Permission{}, 0})
	rol2, _ := rbac.CreateRole(Role{"role2", []Permission{}, 0})
	time.Sleep(500 * time.Millisecond)
	user1 := User{"user1", "user1name", []Role{*rol1, *rol2}, 0}
	user2 := User{"user2", "user2name", []Role{*rol2}, 0}
	usr1, _ := rbac.CreateUser(user1)
	usr2, _ := rbac.CreateUser(user2)
	time.Sleep(500 * time.Millisecond)
	users, err := rbac.GetUsers([]string{"user1", "user2"}, false)
	time.Sleep(500 * time.Millisecond)
	if len(users) != 2 {
		t.Errorf("no of users returned is wrong")
	}
	for _, user := range users {
		if user.Userid == "user1" {
			if user.Username != "user1name" {
				t.Errorf("user name wrong")
			}
			if user.Id != usr1.Id {
				t.Errorf("id wrong")
			}
			if len(user.Roles) != 0 {
				t.Errorf("no of roles in user wrong")
			}
		}
		if user.Userid == "user2" {
			if user.Username != "user2name" {
				t.Errorf("user name wrong")
			}
			if user.Id != usr2.Id {
				t.Errorf("id wrong")
			}
			if len(user.Roles) != 0 {
				t.Errorf("no of roles in user wrong")
			}
		}
	}
}
func TestGetAllUsers(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	rol1, _ := rbac.CreateRole(Role{"role1", []Permission{}, 0})
	rol2, _ := rbac.CreateRole(Role{"role2", []Permission{}, 0})
	time.Sleep(500 * time.Millisecond)
	user1 := User{"user1", "user1name", []Role{*rol1, *rol2}, 0}
	user2 := User{"user2", "user2name", []Role{*rol2}, 0}
	usr1, _ := rbac.CreateUser(user1)
	usr2, _ := rbac.CreateUser(user2)
	time.Sleep(500 * time.Millisecond)
	users, err := rbac.GetAllUsers()
	time.Sleep(500 * time.Millisecond)
	if len(users) != 2 {
		t.Errorf("no of users returned is wrong")
	}
	for _, user := range users {
		if user.Userid == "user1" {
			if user.Username != "user1name" {
				t.Errorf("user name wrong")
			}
			if user.Id != usr1.Id {
				t.Errorf("id wrong")
			}
			if len(user.Roles) != 2 {
				t.Errorf("no of roles in user wrong")
			}
			if !containsRole(user.Roles, *rol1, false) {
				t.Errorf("user1 should contain role1")
			}
			if !containsRole(user.Roles, *rol2, false) {
				t.Errorf("user1 should contain role2")
			}
		}
		if user.Userid == "user2" {
			if user.Username != "user2name" {
				t.Errorf("user name wrong")
			}
			if user.Id != usr2.Id {
				t.Errorf("id wrong")
			}
			if len(user.Roles) != 1 {
				t.Errorf("no of roles in user wrong")
			}
			if !containsRole(user.Roles, *rol2, false) {
				t.Errorf("user1 should contain role2")
			}
		}
	}
}
func TestDeleteUsers(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	rol1, _ := rbac.CreateRole(Role{"role1", []Permission{}, 0})
	rol2, _ := rbac.CreateRole(Role{"role2", []Permission{}, 0})
	time.Sleep(500 * time.Millisecond)
	user1 := User{"user1", "user1name", []Role{*rol1, *rol2}, 0}
	user2 := User{"user2", "user2name", []Role{*rol2}, 0}
	usr1, _ := rbac.CreateUser(user1)
	usr2, _ := rbac.CreateUser(user2)
	time.Sleep(500 * time.Millisecond)

	rbac.DeleteUsers([]int64{usr1.Id})
	time.Sleep(500 * time.Millisecond)
	users, err := rbac.GetAllUsers()
	time.Sleep(500 * time.Millisecond)
	if len(users) != 1 {
		t.Errorf("no of users returned is wrong")
	}
	if users[0].Username != "user2name" {
		t.Errorf("user name wrong")
	}
	if users[0].Userid != "user2" {
		t.Errorf("user name wrong")
	}
	if users[0].Id != usr2.Id {
		t.Errorf("id wrong")
	}
	if len(users[0].Roles) != 1 {
		t.Errorf("no of roles in user wrong")
	}
	if !containsRole(users[0].Roles, *rol2, false) {
		t.Errorf("user1 should contain role2")
	}
}
func TestUpdateUsers(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rbac := New(c)
	rol1, _ := rbac.CreateRole(Role{"role1", []Permission{}, 0})
	rol2, _ := rbac.CreateRole(Role{"role2", []Permission{}, 0})
	time.Sleep(500 * time.Millisecond)
	user1 := User{"user1", "user1name", []Role{*rol1, *rol2}, 0}
	user2 := User{"user2", "user2name", []Role{*rol2}, 0}
	usr1, _ := rbac.CreateUser(user1)
	rbac.CreateUser(user2)
	time.Sleep(500 * time.Millisecond)

	user1.Userid = "user1new"
	user1.Username = "user1name new"
	user1.Roles = []Role{*rol2}
	rbac.UpdateUser(usr1.Id, user1)
	time.Sleep(500 * time.Millisecond)
	users, err := rbac.GetUsers([]string{"user1new"}, true)
	time.Sleep(500 * time.Millisecond)
	if len(users) != 1 {
		t.Errorf("no of users returned is wrong")
	}
	if users[0].Username != "user1name new" {
		t.Errorf("user name wrong")
	}
	if users[0].Userid != "user1new" {
		t.Errorf("user id wrong")
	}
	if users[0].Id != usr1.Id {
		t.Errorf("id wrong")
	}
	if len(users[0].Roles) != 1 {
		t.Errorf("no of roles in user wrong")
	}
	if !containsRole(users[0].Roles, *rol2, false) {
		t.Errorf("user1 should contain role2")
	}
}
