package com.example.demo.repository;

import com.example.demo.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UsersRepository extends JpaRepository<Users, Long> {

    Optional<Users> findByLogin(String login);

    boolean existsByLogin(String login);

    List<Users> findTop3ByOrderByPointsDesc();

    @Query("SELECT new com.example.demo.Users$UserNamePointsDTO(u.login, u.points) FROM Users u")
    List<Users.UserNamePointsDTO> findAllNames();
}
