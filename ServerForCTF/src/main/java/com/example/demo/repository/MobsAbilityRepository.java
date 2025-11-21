package com.example.demo.repository;

import com.example.demo.Abilities;
import com.example.demo.Mobs_Ability;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface MobsAbilityRepository extends JpaRepository<Mobs_Ability, Long> {
    List<Mobs_Ability> findByMobsId(Long mobsId);
    List<Mobs_Ability> findByAbilityId(Long abilityId);
}
