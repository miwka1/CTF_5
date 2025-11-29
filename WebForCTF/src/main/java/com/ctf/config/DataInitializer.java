package com.ctf.config;

import com.ctf.service.ChallengeService;
import com.ctf.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserService userService;

    @Autowired
    private ChallengeService challengeService;

    @Override
    public void run(String... args) throws Exception {
        // Инициализация пользователей (если нужно)
        initializeUsers();

        // Инициализация заданий
        initializeChallenges();
    }

    private void initializeUsers() {
        // Существующая логика инициализации пользователей
        try {
            if (!userService.usernameExists("admin")) {
                userService.registerUser("admin", "admin123", "admin@ctf.local");
            }
            if (!userService.usernameExists("user1")) {
                userService.registerUser("user1", "password1", "user1@ctf.local");
            }
        } catch (Exception e) {
            System.out.println("User initialization error: " + e.getMessage());
        }
    }

    private void initializeChallenges() {
        System.out.println("Initializing CTF challenges...");
        challengeService.initializeChallenges();
        System.out.println("CTF challenges initialized successfully");
    }
}