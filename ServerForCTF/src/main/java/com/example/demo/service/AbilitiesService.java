package com.example.demo.service;
import com.example.demo.Abilities;
import com.example.demo.repository.AbilitiesRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import jakarta.annotation.PostConstruct;
import java.util.List;
import java.util.Optional;

@Service
public class AbilitiesService {
    @Autowired
    private AbilitiesRepository abilitiesRepository;

    public List<Abilities> findAllAbilities() {return abilitiesRepository.findAll();}
    public Optional<Abilities> findAbilityById(Long id) {return abilitiesRepository.findById(id);}
    public List<Abilities.AbilitiesIdName> findNames() {return abilitiesRepository.findAllNames();}

    public void deletAbility(Long ID){abilitiesRepository.deleteById(ID);}
    public Abilities appAbility(Abilities abilities) {return abilitiesRepository.save(abilities);}

    @PostConstruct
    public void logConnection() {
        System.out.println("Spring Boot сервис AbilitiesService запущен!");
        abilitiesRepository.findAll().forEach(a ->
                System.out.println(a.getId() + " " + a.getName() + " " + a.getStuff())
        );
    }
}
