package com.example.demo.services;

import com.example.demo.entities.Role;
import com.example.demo.entities.User;

import java.util.List;

public interface IUserService {

    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers();

}