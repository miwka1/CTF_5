package com.example.demo;
import jakarta.persistence.*;

@Entity
@Table(name = "mobs_abilities")
public class Mobs_Ability {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "mobs_id")
    private Mobs mobs;

    @ManyToOne
    @JoinColumn(name = "ability_id")
    private Abilities ability;

}