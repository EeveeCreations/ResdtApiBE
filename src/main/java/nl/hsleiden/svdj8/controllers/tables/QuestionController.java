package nl.hsleiden.svdj8.controllers.tables;

import nl.hsleiden.svdj8.daos.AnswerDAO;
import nl.hsleiden.svdj8.daos.QuestionDAO;
import nl.hsleiden.svdj8.models.tables.Answer;
import nl.hsleiden.svdj8.models.tables.Question;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
public class QuestionController {

    @Autowired
    public final QuestionDAO questionDAO;

    @Autowired
    public final AnswerDAO answerDAO;

    public QuestionController(QuestionDAO questionDAO, AnswerDAO answerDAO) {
        this.questionDAO = questionDAO;
        this.answerDAO = answerDAO;
    }

    @CrossOrigin(origins = "http://localhost:4200")
    @GetMapping(value = "/question/all")
    public List<Question> getAllQuestions() {
        return questionDAO.getAll();
    }

    @GetMapping(value = "/question/{id}")
    public Question getQuestion(@PathVariable final java.lang.Long id) {
        return questionDAO.getById(id);
    }

    @PutMapping(value = "/question/{id}")
    public Question editQuestion(@RequestBody Question editQuestion, @PathVariable java.lang.Long id) throws Exception {
        Question resultQuestion = questionDAO.getByIdOptional(id)
                .map(question -> {
                    question.setQuestionText(editQuestion.getQuestionText());
                    question.setExtraInfoTile(editQuestion.getExtraInfoTile());
                    question.setExtraInfoDescription(editQuestion.getExtraInfoDescription());
                    question.setExtraInfoVideoURL(editQuestion.getExtraInfoVideoURL());
                    question.setAnswers(editQuestion.getAnswers());
                    return questionDAO.addQuestion(question);
                })
                .orElseThrow(() -> new Exception(
                        "No question found with id " + id + "\""));
        for (Answer answer : resultQuestion.getAnswers()) {
            answer.setParentQuestionID(resultQuestion.getQuestionID());
            answerDAO.addAnswer(answer);
        }
        return resultQuestion;
    }

    @PutMapping(value = "/question")
    public Question addQuestion(@RequestBody Question newQuestion) {
        Question resultQuestion = questionDAO.addQuestion(newQuestion);
        for (Answer answer : resultQuestion.getAnswers()) {
            answer.setParentQuestionID(resultQuestion.getQuestionID());
            answerDAO.addAnswer(answer);
        }
        return resultQuestion;
    }

    @DeleteMapping("/question/{id}")
    public void deleteQuestion(@PathVariable java.lang.Long id) {
        questionDAO.deleteQuestion(id);
    }
}
