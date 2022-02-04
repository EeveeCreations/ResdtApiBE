package nl.hsleiden.svdj8.daos;

import nl.hsleiden.svdj8.models.tables.Answer;
import nl.hsleiden.svdj8.repository.AnswerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@Component
public class AnswerDAO {

    @Autowired
    private AnswerRepository answerRepository;

    public AnswerDAO(AnswerRepository answerRepository) {
        this.answerRepository = answerRepository;
    }

    public List<Answer> getAll() {
        ArrayList<Answer> answers = (ArrayList<Answer>) this.answerRepository.findAll();
        answers.sort(Comparator.comparingLong(Answer::getAnswerID));
        return answers;
    }

    public Answer getById(long id) {
        Optional<Answer> optionalAnswer = answerRepository.findById(id);
        if (optionalAnswer.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Answer with the id: " + id + " not found");
        }
        return optionalAnswer.get();
    }

    public Optional<Answer> getByIdOptional(long id) {
        Optional<Answer> optionalAnswer = answerRepository.findById(id);
        return optionalAnswer;
    }

    public void deleteByAnswerId(long answerId) {
        answerRepository.deleteById(answerId);
    }

    public Answer addAnswer(Answer newAnswer) {
        return answerRepository.save(newAnswer);
    }
}
