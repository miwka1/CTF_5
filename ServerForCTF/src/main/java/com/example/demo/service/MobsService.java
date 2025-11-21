package com.example.demo.service;
import com.example.demo.Mobs;
import com.example.demo.repository.MobsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

@Service
public class MobsService {
    @Autowired
    private MobsRepository mobsRepository;

    public List<Mobs> findAllMobs() {return mobsRepository.findAll();}
    public Optional<Mobs> findMobsById(Long id) {return mobsRepository.findById(id);}
    public List<Mobs.MobsIdName> findNames() {return mobsRepository.findAllNames();}

    public void deletMobs(Long ID){mobsRepository.deleteById(ID);}
    public Mobs appMobs(Mobs mobs) {return mobsRepository.save(mobs);}
}
