package nl.hsleiden.svdj8.controllers.tables;

import nl.hsleiden.svdj8.daos.AnswerDAO;
import nl.hsleiden.svdj8.daos.GivenAnswerDAO;
import nl.hsleiden.svdj8.daos.QuestionDAO;
import nl.hsleiden.svdj8.daos.RouteDAO;
import nl.hsleiden.svdj8.models.tables.GivenAnswer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
public class GivenAnswerController {

    @Autowired
    public final GivenAnswerDAO givenAnswerDAO;

    @Autowired
    public final RouteDAO routeDAO;

    @Autowired
    public final QuestionDAO questionDAO;

    @Autowired
    public final AnswerDAO answerDAO;

    public GivenAnswerController(GivenAnswerDAO givenAnswerDAO, RouteDAO routeDAO, QuestionDAO questionDAO, AnswerDAO answerDAO) {
        this.givenAnswerDAO = givenAnswerDAO;
        this.routeDAO = routeDAO;
        this.questionDAO = questionDAO;
        this.answerDAO = answerDAO;
    }

    @GetMapping(value = "/givenanswer/all")
    public List<GivenAnswer> getAllGivenAnswers() {
        return givenAnswerDAO.getAll();
    }

    @GetMapping(value = "givenanswer/{id}")
    public GivenAnswer getGivenAnswer(@PathVariable final Long id) {
        return givenAnswerDAO.getById(id);
    }

    @PutMapping(value = "/givenanswer/{id}")
    public GivenAnswer editGivenAnswer(@RequestBody GivenAnswer editGivenAnswer, @PathVariable Long id) throws Exception {
        GivenAnswer returnGivenAnswer = givenAnswerDAO.getByIdOptional(id)
                .map(givenAnswer -> {
                    givenAnswer.setElapsedSeconds(editGivenAnswer.getElapsedSeconds());
                    givenAnswer.setAnswer(editGivenAnswer.getAnswer());
                    givenAnswer.setRouteId(editGivenAnswer.getRouteId());
                    givenAnswer.setQuestion(editGivenAnswer.getQuestion());

                    return givenAnswerDAO.addGivenAnswer(givenAnswer);
                })
                .orElseThrow(() -> new Exception(
                        "No answer found with id " + id + "\""));

        returnGivenAnswer.setAnswer(answerDAO.getById(returnGivenAnswer.getAnswer().getAnswerID()));
        returnGivenAnswer.setQuestion(questionDAO.getById(returnGivenAnswer.getQuestion().getQuestionID()));

        return returnGivenAnswer;

    }

    @PutMapping(value = "/givenanswer")
    public GivenAnswer addGivenAnswer(@RequestBody GivenAnswer newGivenAnswer) {
        return givenAnswerDAO.addGivenAnswer(newGivenAnswer);
    }

    @DeleteMapping("/givenanswer/{id}")
    public void deleteGivenAnswer(@PathVariable Long id) {
        givenAnswerDAO.deleteGivenAnswer(id);
    }
}
