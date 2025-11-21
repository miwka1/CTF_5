package com.ctf.service;

import com.ctf.model.User;
import com.ctf.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@Transactional
public class UserService {

    @Autowired
    private UserRepository userRepository;

    /**
     * Регистрация нового пользователя
     */
    public User registerUser(String username, String password, String email) {

        if (username == null || username.trim().isEmpty()) {
            throw new RuntimeException("Имя пользователя не может быть пустым");
        }

        if (password == null || password.trim().isEmpty()) {
            throw new RuntimeException("Пароль не может быть пустым");
        }

        if (email == null || email.trim().isEmpty()) {
            throw new RuntimeException("Email не может быть пустым");
        }

        username = username.trim();
        email = email.trim().toLowerCase();


        if (username.length() < 3) {
            throw new RuntimeException("Имя пользователя должно содержать минимум 3 символа");
        }


        if (password.length() < 6) {
            throw new RuntimeException("Пароль должен содержать минимум 6 символов");
        }


        if (!isValidEmail(email)) {
            throw new RuntimeException("Некорректный формат email");
        }


        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("Имя пользователя '" + username + "' уже занято");
        }


        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email '" + email + "' уже используется");
        }

        try {

            User user = new User();
            user.setUsername(username);
            user.setPassword(password);
            user.setEmail(email);
            user.setScore(0);
            user.setRole("USER");

            return userRepository.save(user);

        } catch (Exception e) {
            throw new RuntimeException("Ошибка при сохранении пользователя: " + e.getMessage());
        }
    }


    public Optional<User> authenticate(String username, String password) {
        Optional<User> user = userRepository.findByUsername(username);
        // Простая проверка пароля (без хеширования)
        if (user.isPresent() && password.equals(user.get().getPassword())) {
            return user;
        }
        return Optional.empty();
    }


    public List<User> getAllUsers() {
        return userRepository.findAllOrderByCreatedAt();
    }

    public List<User> getTopUsers() {
        return userRepository.findTopUsers();
    }


    public boolean usernameExists(String username) {
        return userRepository.existsByUsername(username.trim());
    }

    /**
     * Проверка существования email
     */
    public boolean emailExists(String email) {
        return userRepository.existsByEmail(email.trim().toLowerCase());
    }

    /**
     * Поиск пользователя по ID
     */
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }


    public User save(User user) {
        return userRepository.save(user);
    }


    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    /**
     * Валидация email
     */
    private boolean isValidEmail(String email) {
        String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
        return email.matches(emailRegex);
    }


    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }


    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}