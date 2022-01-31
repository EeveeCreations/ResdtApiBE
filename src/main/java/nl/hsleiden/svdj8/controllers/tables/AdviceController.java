package nl.hsleiden.svdj8.controllers.tables;

import nl.hsleiden.svdj8.daos.AdviceDAO;
import nl.hsleiden.svdj8.models.tables.Advice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
public class AdviceController {

    @Autowired
    public final AdviceDAO adviceDAO;

    public AdviceController(AdviceDAO adviceDAO) {
        this.adviceDAO = adviceDAO;
    }

    @GetMapping(value = "/advice/all")
    public List<Advice> getAllCategories() {
        return adviceDAO.getAll();
    }

    @GetMapping(value = "/advice/{id}")
    public Advice getCategory(@PathVariable final Long id) {
        return adviceDAO.getById(id);
    }

    @PutMapping(value = "/advice/{id}")
    public Advice editCategory(@RequestBody Advice editAdvice, @PathVariable Long id) throws Exception {

        return adviceDAO.getByIdOptional(id)
                .map(advice -> {
                    advice.setName(editAdvice.getName());
                    advice.setDescription(editAdvice.getDescription());
                    advice.setGrants(editAdvice.getGrants());
                    return adviceDAO.addCategory(advice);
                })
                .orElseThrow(() -> new Exception(
                        "No category found with id " + id + "\""));
    }

    @PutMapping(value = "/advice")
    public Advice addCategory(@RequestBody Advice newAdvice) {
        return adviceDAO.addCategory(newAdvice);
    }

    @DeleteMapping("/advice/{id}")
    public void deleteCategory(@PathVariable Long id) {
        adviceDAO.deleteCategory(id);
    }
}
