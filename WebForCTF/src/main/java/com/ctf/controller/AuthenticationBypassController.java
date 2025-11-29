package com.ctf.controller;

import com.ctf.model.Challenge;
import com.ctf.service.ChallengeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/challenges/auth-bypass")
public class AuthenticationBypassController {

    @Autowired
    private ChallengeService challengeService;

    @GetMapping
    public String authBypassChallengePage(Model model) {
        challengeService.getChallengeByTitle("Authentication Bypass")
                .ifPresent(challenge -> {
                    model.addAttribute("challenge", challenge);
                    model.addAttribute("points", challenge.getPoints());
                });
        return "challenges/auth-bypass"; // Добавить папку challenges/
    }




    @PostMapping("/check-admin")
    @ResponseBody
    public String checkAdminAccess(@RequestParam String token,
                                   @RequestParam(required = false) String sessionId,
                                   @CookieValue(value = "admin", required = false) String adminCookie) {

        // Уязвимая проверка - можно обойти разными способами
        boolean isAdmin = false;
        String method = "";

        // Способ 1: Правильный токен
        if ("SUPER_SECRET_ADMIN_TOKEN_2024".equals(token)) {
            isAdmin = true;
            method = "token";
        }
        // Способ 2: Специальная сессия
        else if ("admin_session_12345".equals(sessionId)) {
            isAdmin = true;
            method = "session";
        }
        // Способ 3: Админская кука
        else if ("true".equals(adminCookie) || "1".equals(adminCookie)) {
            isAdmin = true;
            method = "cookie";
        }
        // Способ 4: SQL инъекция в токен
        else if (token != null && token.contains("' OR '1'='1")) {
            isAdmin = true;
            method = "sql_injection";
        }

        if (isAdmin) {
            // Используем final переменные для лямбды
            final String finalMethod = method;
            return challengeService.getChallengeByTitle("Authentication Bypass")
                    .map(challenge -> String.format(
                            "{\"success\": true, \"message\": \"✅ Authentication Bypass успешен! Метод: %s\", \"flag\": \"%s\"}",
                            finalMethod, challenge.getFlag()
                    ))
                    .orElse("{\"success\": false, \"message\": \"Ошибка: задание не найдено\"}");
        } else {
            return "{\"success\": false, \"message\": \"❌ Доступ запрещен. Попробуйте обойти аутентификацию\"}";
        }
    }

    @PostMapping("/validate")
    @ResponseBody
    public String validateFlag(@RequestParam String flag) {
        boolean isValid = challengeService.validateFlagByChallengeName("Authentication Bypass", flag);

        if (isValid) {
            return "{\"success\": true, \"message\": \"🎉 Флаг верный! Задание выполнено.\"}";
        } else {
            return "{\"success\": false, \"message\": \"❌ Неверный флаг. Попробуйте еще раз.\"}";
        }
    }

    @GetMapping("/info")
    @ResponseBody
    public String getChallengeInfo() {
        return challengeService.getChallengeByTitle("Authentication Bypass")
                .map(challenge -> String.format(
                        "{\"title\": \"%s\", \"points\": %d, \"difficulty\": \"%s\"}",
                        challenge.getTitle(),
                        challenge.getPoints(),
                        challenge.getDifficulty()
                ))
                .orElse("{\"title\": \"Authentication Bypass\", \"points\": 120, \"difficulty\": \"easy\"}");
    }

    @GetMapping("/hint")
    @ResponseBody
    public String getHint() {
        return challengeService.getChallengeByTitle("Authentication Bypass")
                .map(challenge -> "{\"hint\": \"" + challenge.getHints() + "\"}")
                .orElse("{\"hint\": \"Подсказка не найдена\"}");
    }
}