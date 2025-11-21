package com.example.demo.controller;

import com.example.demo.Users;
import com.example.demo.service.UsersService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.demo.RegisterRequest;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UsersService usersService;

    public AuthController(UsersService usersService) {
        this.usersService = usersService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        try {
            Users user = usersService.registerUser(request.getLogin(), request.getPassword());
            return ResponseEntity.ok("Пользователь зарегистрирован: " + user.getLogin());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        var userOpt = usersService.getUserByLogin(request.getLogin());

        if (userOpt.isEmpty()) {
            return ResponseEntity.status(401).body("Неверный логин или пароль");
        }

        Users user = userOpt.get();
        if (!usersService.checkPassword(user.getLogin(), request.getPassword())) {
            return ResponseEntity.status(401).body("Неверный логин или пароль");
        }

        return ResponseEntity.ok("Успешная авторизация");
    }

}
