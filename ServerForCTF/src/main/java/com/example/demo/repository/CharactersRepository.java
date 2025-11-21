package com.example.demo.repository;

import com.example.demo.Character;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface CharactersRepository extends JpaRepository<Character, Long> {
    List<Character> findByName(String name);
    @Query("SELECT c.name AS name, c.id AS id  FROM Character c")
    List<Character.CharacterIdName> findAllNames();
    List<Character> findAll();
}

