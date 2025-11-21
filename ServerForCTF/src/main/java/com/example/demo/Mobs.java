package com.example.demo;
import jakarta.persistence.*;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "mobs")
public class Mobs {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    public String name;
    public int Health;
    public int ClassDefense;
    public String Characteristics;


    @OneToMany(mappedBy = "mobs")
    private Set<Mobs_Ability> characterAbilities = new HashSet<>();

    public interface MobsIdName {
        Long getId();
        String getName();
    }
}
