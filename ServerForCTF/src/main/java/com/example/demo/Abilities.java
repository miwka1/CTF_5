package com.example.demo;
import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "abilities")
public class Abilities {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "name")
    private String name;

    @Column(name = "stuff")
    private String stuff;

    public static interface AbilitiesIdName {
        Long getId();
        String getName();
    }

    @OneToMany(mappedBy = "ability")
    private Set<Mobs_Ability> mobsAbilities = new HashSet<>();

    // Конструкторы
    public Abilities() {}

    public Abilities(String name, String stuff) {
        this.name = name;
        this.stuff = stuff;
    }

    public Long getId() {
        return id;
    }

    void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getStuff() {
        return stuff;
    }

    public void setStuff(String stuff) {
        this.stuff = stuff;
    }


}
