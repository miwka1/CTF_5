package com.example.demo.repository;

import com.example.demo.Character;
import com.example.demo.Mobs;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface MobsRepository extends JpaRepository<Mobs, Long> {
    List<Character> findByName(String name);
    @Query("SELECT c.name AS name, c.id AS id  FROM Character c")
    List<Mobs.MobsIdName> findAllNames();
    List<Mobs> findAll();
}
