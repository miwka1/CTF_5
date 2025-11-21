package com.example.demo.service;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UsersService usersService;

    public DataInitializer(UsersService usersService) {
        this.usersService = usersService;
    }

    @Override
    public void run(String... args) throws Exception {
        String defaultLogin = "user";
        String defaultPassword = "123456";
        int defaultPoints = 0;

        usersService.createOrUpdateUser(defaultLogin, defaultPassword, defaultPoints);
        System.out.println("Дефолтный пользователь установлен: " + defaultLogin);
    }

}
