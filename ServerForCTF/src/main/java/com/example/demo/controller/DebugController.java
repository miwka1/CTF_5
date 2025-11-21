package com.example.demo.controller;

import com.example.demo.Users;
import com.example.demo.service.UsersService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/debug")
@CrossOrigin(origins = "http://frontend:3000")
public class DebugController {

    private final UsersService usersService;

    public DebugController(UsersService usersService) {
        this.usersService = usersService;
    }

    @GetMapping("/public/test")
    public String test() {
        return "Привет";
    }


    @GetMapping("/public/ping")
    public String ping() {
        return "Сервер жив!";
    }

    @GetMapping("/users")
    public List<Users> getAllUsers() {
        return usersService.getAllUsers();
    }

    @DeleteMapping("/admin/delete/{id}")
    public String deleteUser(@PathVariable Long id) {
        usersService.deleteUser(id);
        return "Пользователь с id " + id + " удалён.";
    }
}
