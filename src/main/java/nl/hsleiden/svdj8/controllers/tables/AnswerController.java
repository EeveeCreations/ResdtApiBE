package nl.hsleiden.svdj8.controllers.tables;

import nl.hsleiden.svdj8.daos.AnswerDAO;
import nl.hsleiden.svdj8.daos.AdviceDAO;
import nl.hsleiden.svdj8.models.tables.Answer;
import nl.hsleiden.svdj8.models.tables.Advice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
public class AnswerController {

    @Autowired
    public final AnswerDAO answerDAO;

    public final AdviceDAO adviceDAO;

    public AnswerController(AnswerDAO answerDAO, AdviceDAO adviceDAO) {
        this.answerDAO = answerDAO;
        this.adviceDAO = adviceDAO;
    }

    @GetMapping(value = "/answer/all")
    public List<Answer> getAllAnswers() {
        return answerDAO.getAll();
    }

    @GetMapping(value = "/answer/{id}")
    public Answer getAnswer(@PathVariable final Long id) {
        return answerDAO.getById(id);
    }


    @PutMapping(value = "/answer/{id}")
    public Answer editAnswer(@RequestBody Answer editAnswer, @PathVariable Long id) throws Exception {
        Answer returnAnswer = answerDAO.getByIdOptional(id)
                .map(answer -> {
                    answer.setAnswerText(editAnswer.getAnswerText());
                    answer.setParentQuestionID(editAnswer.getParentQuestionID());
                    answer.setNextQuestion(editAnswer.getNextQuestion());
                    answer.setAdvice(editAnswer.getAdvice());
                    return answerDAO.addAnswer(answer);
                })
                .orElseThrow(() -> new Exception(
                        "No answer found with id " + id + "\""));
        return returnAnswer;
    }

    @PutMapping(value = "/answer")
    public Answer addAnswer(@RequestBody Answer newAnswer) {
        return answerDAO.addAnswer(newAnswer);
    }

    @DeleteMapping("/answer/{id}")
    public void deleteAnswer(@PathVariable Long id) {
        answerDAO.deleteByAnswerId(id);
    }
}
