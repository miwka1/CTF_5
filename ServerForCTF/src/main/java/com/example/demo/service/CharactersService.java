package com.example.demo.service;
import com.example.demo.Character;
import com.example.demo.repository.CharactersRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class CharactersService {
    @Autowired
    private CharactersRepository charactersRepository;

    public List<Character> getAllCharacters() {
        return charactersRepository.findAll();
    }
    public List<Character.CharacterIdName> getAllNames(){
        return charactersRepository.findAllNames();
    }
    public List<Character> getCharacterByName(String name) {
        return charactersRepository.findByName(name);
    }
    public void deletCharacter(Long ID){
        charactersRepository.deleteById(ID);
    }
    public Character appCharacter(Character character){
        return charactersRepository.save(character);
    }
    public Character updateCharacter(long ID, Character characterDetails){
        Character character = charactersRepository.findById(ID).orElseThrow();
        character.setName(characterDetails.name);
        character.setRace(characterDetails.race);
        character.setType(characterDetails.type);
        character.setArchetype(characterDetails.archetype);
        character.setCharnick(characterDetails.charnick);
        return charactersRepository.save(character);
    }
}
