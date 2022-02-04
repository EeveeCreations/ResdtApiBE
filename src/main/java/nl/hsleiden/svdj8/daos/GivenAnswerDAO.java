package nl.hsleiden.svdj8.daos;

import nl.hsleiden.svdj8.models.tables.GivenAnswer;
import nl.hsleiden.svdj8.repository.GivenAnswerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@Component
public class GivenAnswerDAO {
    @Autowired
    private GivenAnswerRepository givenAnswerRepository;

    public GivenAnswerDAO(GivenAnswerRepository givenAnswerRepository) {
        this.givenAnswerRepository = givenAnswerRepository;
    }

    public List<GivenAnswer> getAll() {
        ArrayList<GivenAnswer> givenAnswers = (ArrayList<GivenAnswer>) this.givenAnswerRepository.findAll();
        givenAnswers.sort(Comparator.comparingLong(GivenAnswer::getGivenAnswerID));
        return givenAnswers;
    }

    public GivenAnswer getById(long id) {
        Optional<GivenAnswer> optionalGivenAnswer = givenAnswerRepository.findById(id);
        if (optionalGivenAnswer.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "GivenAnswer with the id: " + id + " not found");
        }
        return optionalGivenAnswer.get();
    }

    public Optional<GivenAnswer> getByIdOptional(long id) {
        Optional<GivenAnswer> optionalGivenAnswer = givenAnswerRepository.findById(id);
        return optionalGivenAnswer;
    }

    public GivenAnswer addGivenAnswer(GivenAnswer newGivenAnswer) {
        return givenAnswerRepository.save(newGivenAnswer);
    }

    public void deleteGivenAnswer(long id) {
        givenAnswerRepository.deleteById(id);
    }

}
