package com.example.demo;

import jakarta.persistence.*;

@Entity
@Table(name = "users")
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String login;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private int points = 0;

    public Users() {}

    public Users(String login, String password, int points) {
        this.login = login;
        this.password = password;
        this.points = points;
    }

    // ======================
    // DTO для отображения очков
    // ======================
    public static class UserNamePointsDTO {
        private String name;
        private int points;

        public UserNamePointsDTO(String name, int points) {
            this.name = name;
            this.points = points;
        }

        // геттеры
        public String getName() { return name; }
        public int getPoints() { return points; }
    }

    // ======================
    // Геттеры и сеттеры
    // ======================
    public Long getId() { return id; }

    public String getLogin() { return login; }
    public void setLogin(String login) { this.login = login; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public int getPoints() { return points; }
    public void setPoints(int points) { this.points = points; }

    @Override
    public String toString() {
        return "Users{" +
                "id=" + id +
                ", login='" + login + '\'' +
                ", points=" + points +
                '}';
    }
}
