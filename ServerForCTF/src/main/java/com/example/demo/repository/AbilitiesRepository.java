package com.example.demo.repository;

import com.example.demo.Abilities;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.util.List;

public interface AbilitiesRepository extends JpaRepository<Abilities, Long>  {
    List<Abilities> findAll();
    @Query("SELECT c.id AS id, c.name AS name FROM Abilities c")
    List<Abilities.AbilitiesIdName> findAllNames();

}
