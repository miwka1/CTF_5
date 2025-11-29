package com.ctf.service;

import com.ctf.model.Challenge;
import com.ctf.repository.ChallengeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class ChallengeService {

    @Autowired
    private ChallengeRepository challengeRepository;

    // Добавить метод для инициализации заданий
    public void initializeChallenges() {
        // SQL Injection Challenge
        if (!challengeRepository.findByTitle("SQL Injection Basic").isPresent()) {
            Challenge sqliChallenge = new Challenge(
                    "SQL Injection Basic",
                    "Обойдите аутентификацию с помощью SQL инъекции. Найдите флаг в базе данных.",
                    "web",
                    100,
                    "easy",
                    "CTF{sql_1nj3ct10n_3asy_w1n}",
                    "Используйте ' OR '1'='1 в поле username",
                    "Попробуйте использовать SQL инъекцию в поле username. Пример: ' OR '1'='1"
            );
            challengeRepository.save(sqliChallenge);
        }

        // Authentication Bypass Challenge
        if (!challengeRepository.findByTitle("Authentication Bypass").isPresent()) {
            Challenge authBypassChallenge = new Challenge(
                    "Authentication Bypass",
                    "Обойдите механизм аутентификации и получите доступ к административной панели.",
                    "web",
                    120,
                    "easy",
                    "CTF{auth_bypass_m4st3r_2024}",
                    "Методы обхода: 1) ' OR '1'='1 в токене, 2) admin_session_12345 в сессии, 3) Установите cookie admin=true",
                    "Попробуйте разные методы обхода: SQL инъекция, специальные сессии, cookies администратора"
            );
            challengeRepository.save(authBypassChallenge);
        }
    }

    public Optional<Challenge> getChallengeByTitle(String title) {
        return challengeRepository.findByTitle(title);
    }

    public boolean validateFlagByChallengeName(String challengeName, String flag) {
        Optional<Challenge> challenge = challengeRepository.findByTitle(challengeName);
        return challenge.isPresent() && challenge.get().getFlag().equals(flag);
    }

    // Уязвимый метод для SQL инъекции
    public boolean validateSqlInjection(String username, String password) {
        // Эмулируем уязвимый SQL запрос
        String vulnerableQuery = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";

        System.out.println("Executing vulnerable query: " + vulnerableQuery);

        // Проверяем различные векторы SQL инъекции
        if (username.contains("' OR '1'='1") ||
                username.contains("' OR 1=1--") ||
                username.contains("' OR 'a'='a") ||
                username.contains("admin'--")) {
            return true;
        }

        // Проверяем правильные credentials (для тестирования)
        if ("admin".equals(username) && "password123".equals(password)) {
            return true;
        }

        return false;
    }

    public List<Challenge> getChallengesByCategory(String category) {
        return challengeRepository.findByCategory(category);
    }

    public List<Challenge> getAllChallenges() {
        return challengeRepository.findAll();
    }

    public Challenge saveChallenge(Challenge challenge) {
        return challengeRepository.save(challenge);
    }

    public void deleteChallenge(Long id) {
        challengeRepository.deleteById(id);
    }
}