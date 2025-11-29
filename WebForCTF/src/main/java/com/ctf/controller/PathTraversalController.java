package com.ctf.controller;

import com.ctf.model.Challenge;
import com.ctf.service.ChallengeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/challenges/path-traversal")
public class PathTraversalController {

    @Autowired
    private ChallengeService challengeService;

    @GetMapping
    public String pathTraversalChallengePage(Model model) {
        challengeService.getChallengeByTitle("Path Traversal")
                .ifPresent(challenge -> {
                    model.addAttribute("challenge", challenge);
                    model.addAttribute("points", challenge.getPoints());
                });
        return "challenges/path-traversal"; // ✅ Правильный путь
    }

    @GetMapping("/file")
    @ResponseBody
    public String getFile(@RequestParam String path) {
        // Уязвимый код - позволяет path traversal
        if (path.contains("..") || path.contains("etc/passwd") || path.contains("flag")) {
            return "{\"success\": true, \"content\": \"CTF{path_traversal_success_2024}\", \"type\": \"file\"}";
        } else if (path.equals("/public/")) {
            return "{\"success\": true, \"content\": \"index.html\\nstyle.css\\nscript.js\", \"type\": \"directory\"}";
        } else {
            return "{\"success\": false, \"message\": \"File not found or access denied\"}";
        }
    }

    @PostMapping("/validate")
    @ResponseBody
    public String validateFlag(@RequestParam String flag) {
        boolean isValid = challengeService.validateFlagByChallengeName("Path Traversal", flag);
        
        if (isValid) {
            return "{\"success\": true, \"message\": \"🎉 Флаг верный! Задание выполнено.\"}";
        } else {
            return "{\"success\": false, \"message\": \"❌ Неверный флаг. Попробуйте еще раз.\"}";
        }
    }

    @GetMapping("/info")
    @ResponseBody
    public String getChallengeInfo() {
        return challengeService.getChallengeByTitle("Path Traversal")
                .map(challenge -> String.format(
                        "{\"title\": \"%s\", \"points\": %d, \"difficulty\": \"%s\"}",
                        challenge.getTitle(),
                        challenge.getPoints(),
                        challenge.getDifficulty()
                ))
                .orElse("{\"title\": \"Path Traversal\", \"points\": 250, \"difficulty\": \"hard\"}");
    }

    @GetMapping("/hint")
    @ResponseBody
    public String getHint() {
        return challengeService.getChallengeByTitle("Path Traversal")
                .map(challenge -> "{\"hint\": \"" + challenge.getHints() + "\"}")
                .orElse("{\"hint\": \"Подсказка не найдена\"}");
    }
}