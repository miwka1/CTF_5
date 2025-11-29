package com.ctf.controller;

import com.ctf.model.Challenge;
import com.ctf.service.ChallengeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/challenges/sqli")
public class SqlInjectionController {

    @Autowired
    private ChallengeService challengeService;

    @GetMapping
    public String sqliChallengePage(Model model) {
        // Добавляем информацию о задании в модель
        challengeService.getChallengeByTitle("SQL Injection Basic")
                .ifPresent(challenge -> {
                    model.addAttribute("challenge", challenge);
                    model.addAttribute("points", challenge.getPoints());
                });

        return "challenges/sqli"; // Добавить папку challenges/
    }

    @GetMapping("/info")
    @ResponseBody
    public String getChallengeInfo() {
        return challengeService.getChallengeByTitle("SQL Injection Basic")
                .map(challenge -> String.format(
                        "{\"title\": \"%s\", \"points\": %d, \"difficulty\": \"%s\"}",
                        challenge.getTitle(),
                        challenge.getPoints(),
                        challenge.getDifficulty()
                ))
                .orElse("{\"title\": \"SQL Injection Basic\", \"points\": 100, \"difficulty\": \"easy\"}");
    }

    @PostMapping("/login")
    @ResponseBody
    public String vulnerableLogin(@RequestParam String username,
                                  @RequestParam String password) {

        System.out.println("SQL Injection attempt - Username: " + username + ", Password: " + password);

        if (challengeService.validateSqlInjection(username, password)) {
            // Успешная SQL инъекция - возвращаем флаг
            return challengeService.getChallengeByTitle("SQL Injection Basic")
                    .map(challenge -> String.format(
                            "{\"success\": true, \"message\": \"✅ SQL Injection успешен! Доступ получен.\", \"flag\": \"%s\"}",
                            challenge.getFlag()
                    ))
                    .orElse("{\"success\": false, \"message\": \"Ошибка: задание не найдено\"}");
        } else {
            return "{\"success\": false, \"message\": \"❌ Неверные учетные данные\"}";
        }
    }

    @PostMapping("/validate")
    @ResponseBody
    public String validateFlag(@RequestParam String flag) {
        boolean isValid = challengeService.validateFlagByChallengeName("SQL Injection Basic", flag);

        if (isValid) {
            return "{\"success\": true, \"message\": \"🎉 Флаг верный! Задание выполнено.\"}";
        } else {
            return "{\"success\": false, \"message\": \"❌ Неверный флаг. Попробуйте еще раз.\"}";
        }
    }

    @GetMapping("/hint")
    @ResponseBody
    public String getHint() {
        return challengeService.getChallengeByTitle("SQL Injection Basic")
                .map(challenge -> "{\"hint\": \"" + challenge.getHints() + "\"}")
                .orElse("{\"hint\": \"Подсказка не найдена\"}");
    }
}