package com.example.demo;
import jakarta.persistence.*;

@Entity
@Table(name = "characters")
public class Character {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    public String name;
    public String race;
    public String type;
    public String archetype;
    public String charnick;

    // Конструкторы, геттеры, сеттеры
    public Character() {}
    public Character(String name, String race, String type, String archetype, String charnick){
        this.name=name;
        this.race=race;
        this.type=type;
        this.archetype=archetype;
        this.charnick=charnick;
    }
    public Long getId() {
        return id;
    }

    // ID не имеет сеттера, так как генерируется автоматически

    public interface CharacterIdName {
        Long getId();
        String getName();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getRace() {
        return race;
    }

    public void setRace(String race) {
        this.race = race;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getArchetype() {
        return archetype;
    }

    public void setArchetype(String archetype) {
        this.archetype = archetype;
    }

    public String getCharnick() {
        return charnick;
    }

    public void setCharnick(String charnick) {
        this.charnick = charnick;
    }


}


