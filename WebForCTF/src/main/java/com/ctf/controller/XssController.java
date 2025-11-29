package com.ctf.controller;

import com.ctf.model.Challenge;
import com.ctf.service.ChallengeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/challenges/xss")
public class XssController {

    @Autowired
    private ChallengeService challengeService;

    @GetMapping
    public String xssChallengePage(Model model) {
        challengeService.getChallengeByTitle("XSS Challenge")
                .ifPresent(challenge -> {
                    model.addAttribute("challenge", challenge);
                    model.addAttribute("points", challenge.getPoints());
                });
        return "challenges/xss";
    }

    @PostMapping("/comment")
    @ResponseBody
    public String postComment(@RequestParam String comment) {
        // Уязвимый код - возвращает комментарий без санитизации
        return String.format("{\"success\": true, \"comment\": \"%s\", \"user\": \"anonymous\", \"time\": \"%s\"}",
                comment, java.time.LocalTime.now().toString());
    }

    @PostMapping("/validate")
    @ResponseBody
    public String validateFlag(@RequestParam String flag) {
        boolean isValid = challengeService.validateFlagByChallengeName("XSS Challenge", flag);
        
        if (isValid) {
            return "{\"success\": true, \"message\": \"🎉 Флаг верный! Задание выполнено.\"}";
        } else {
            return "{\"success\": false, \"message\": \"❌ Неверный флаг. Попробуйте еще раз.\"}";
        }
    }

    @GetMapping("/info")
    @ResponseBody
    public String getChallengeInfo() {
        return challengeService.getChallengeByTitle("XSS Challenge")
                .map(challenge -> String.format(
                        "{\"title\": \"%s\", \"points\": %d, \"difficulty\": \"%s\"}",
                        challenge.getTitle(),
                        challenge.getPoints(),
                        challenge.getDifficulty()
                ))
                .orElse("{\"title\": \"XSS Challenge\", \"points\": 200, \"difficulty\": \"medium\"}");
    }

    @GetMapping("/hint")
    @ResponseBody
    public String getHint() {
        return challengeService.getChallengeByTitle("XSS Challenge")
                .map(challenge -> "{\"hint\": \"" + challenge.getHints() + "\"}")
                .orElse("{\"hint\": \"Подсказка не найдена\"}");
    }
}