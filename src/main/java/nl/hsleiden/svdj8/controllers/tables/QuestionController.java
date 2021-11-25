package nl.hsleiden.svdj8.controllers.tables;

import nl.hsleiden.svdj8.daos.AnswerDAO;
import nl.hsleiden.svdj8.daos.QuestionDAO;
import nl.hsleiden.svdj8.models.tables.Answer;
import nl.hsleiden.svdj8.models.tables.Question;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

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

    @GetMapping(value = "/question/all")
    public List<Question> getAllQuestions() {
        return questionDAO.getAll();
    }

    @GetMapping(value = "/question/{id}")
    public Question getQuestion(@PathVariable final Long id) {
        return questionDAO.getById(id);
    }

    @PutMapping(value = "/question/{id}")
    public Question editQuestion(@RequestBody Question editQuestion, @PathVariable Long id) throws Exception {
        Question resultQuestion = questionDAO.getByIdOptional(id)
                .map(question -> {
                    question.setQuestionText(editQuestion.getQuestionText());
                    question.setExtraInfoTile(editQuestion.getExtraInfoTile());
                    question.setExtraInfoDescription(editQuestion.getExtraInfoDescription());
                    question.setExtraInfoVideoURL(editQuestion.getExtraInfoVideoURL());
                    question.setAnswers(editQuestion.getAnswers());
                    return questionDAO.addQuestion(question);
                }).get();

        for (Answer answer : resultQuestion.getAnswers()) {
            answer.setQuestionID(resultQuestion.getQuestionID());
            answerDAO.addAnswer(answer);
        }
        return resultQuestion;
    }

    @PostMapping(value = "/question")
    public Question addQuestion(@RequestBody Question newQuestion) {
        Question resultQuestion = questionDAO.addQuestion(newQuestion);
        for (Answer answer : resultQuestion.getAnswers()) {
            answer.setQuestionID(resultQuestion.getQuestionID());
            answerDAO.addAnswer(answer);
        }
        return resultQuestion;
    }

    @DeleteMapping("/question/{id}")
    public void deleteQuestion(@PathVariable Long id) {
        questionDAO.deleteQuestion(id);
    }
}
