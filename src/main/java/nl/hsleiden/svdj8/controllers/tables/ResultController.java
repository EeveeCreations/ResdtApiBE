package nl.hsleiden.svdj8.controllers.tables;

import nl.hsleiden.svdj8.daos.AdviceDAO;
import nl.hsleiden.svdj8.daos.ResultDAO;
import nl.hsleiden.svdj8.models.tables.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
public class ResultController {

    @Autowired
    public final ResultDAO resultDAO;

    @Autowired
    public final AdviceDAO adviceDAO;


    public ResultController(ResultDAO resultDAO, AdviceDAO adviceDAO) {
        this.resultDAO = resultDAO;
        this.adviceDAO = adviceDAO;
    }

    @GetMapping(value = "/result/all")
    public List<Result> getAllResults() {
        return resultDAO.getAll();
    }

    @GetMapping(value = "/result/{id}")
    public Result getResult(@PathVariable final Long id) {
        return resultDAO.getById(id);
    }

    @PutMapping(value = "/result/{id}")
    public Result editResult(@RequestBody Result editResult, @PathVariable Long id) throws Exception {
        Result returnResult = resultDAO.getByIdOptional(id)
                .map(result -> {
                    result.setTotalTime(editResult.getTotalTime());
                    result.setAmountQuestions(editResult.getAmountQuestions());
                    result.setAdvice(editResult.getAdvice());
                    return resultDAO.addQuestion(result);
                })
                .orElseThrow(() -> new Exception(
                        "No result found with id " + id + "\""));
        returnResult.setAdvice(adviceDAO.getById(returnResult.getAdvice().getAdviceID()));
        return returnResult;
    }

    @PostMapping(value = "/result")
    public Result addResult(@RequestBody Result newResult) {
        return resultDAO.addQuestion(newResult);
    }

    @DeleteMapping("/result/{id}")
    public void deleteResult(@PathVariable Long id) {
        resultDAO.deleteQuestion(id);
    }
}
