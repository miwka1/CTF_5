package com.ctf.controller;

import com.ctf.model.Challenge;
import com.ctf.service.ChallengeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/challenges/csrf")
public class CsrfController {

    @Autowired
    private ChallengeService challengeService;

    @GetMapping
    public String csrfChallengePage(Model model) {
        challengeService.getChallengeByTitle("CSRF Challenge")
                .ifPresent(challenge -> {
                    model.addAttribute("challenge", challenge);
                    model.addAttribute("points", challenge.getPoints());
                });
        return "challenges/csrf"; // Добавить папку challenges/
    }

    @PostMapping("/transfer")
    @ResponseBody
    public String transferFunds(@RequestParam String amount, 
                               @RequestParam String targetAccount) {
        // Уязвимый endpoint без CSRF защиты
        return String.format("{\"success\": true, \"message\": \"✅ Transfer of $%s to %s completed\", \"flag\": \"%s\"}",
                amount, targetAccount, "CTF{csrf_vulnerable_2024}");
    }

    @PostMapping("/validate")
    @ResponseBody
    public String validateFlag(@RequestParam String flag) {
        boolean isValid = challengeService.validateFlagByChallengeName("CSRF Challenge", flag);
        
        if (isValid) {
            return "{\"success\": true, \"message\": \"🎉 Флаг верный! Задание выполнено.\"}";
        } else {
            return "{\"success\": false, \"message\": \"❌ Неверный флаг. Попробуйте еще раз.\"}";
        }
    }

    @GetMapping("/info")
    @ResponseBody
    public String getChallengeInfo() {
        return challengeService.getChallengeByTitle("CSRF Challenge")
                .map(challenge -> String.format(
                        "{\"title\": \"%s\", \"points\": %d, \"difficulty\": \"%s\"}",
                        challenge.getTitle(),
                        challenge.getPoints(),
                        challenge.getDifficulty()
                ))
                .orElse("{\"title\": \"CSRF Challenge\", \"points\": 150, \"difficulty\": \"medium\"}");
    }

    @GetMapping("/hint")
    @ResponseBody
    public String getHint() {
        return challengeService.getChallengeByTitle("CSRF Challenge")
                .map(challenge -> "{\"hint\": \"" + challenge.getHints() + "\"}")
                .orElse("{\"hint\": \"Подсказка не найдена\"}");
    }

}