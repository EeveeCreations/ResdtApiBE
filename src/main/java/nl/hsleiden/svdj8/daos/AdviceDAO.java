package nl.hsleiden.svdj8.daos;

import nl.hsleiden.svdj8.models.tables.Advice;
import nl.hsleiden.svdj8.repository.CategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@Component
public class AdviceDAO {

    @Autowired
    private CategoryRepository categoryRepository;

    public AdviceDAO(CategoryRepository categoryRepository) {
        this.categoryRepository = categoryRepository;
    }

    public List<Advice> getAll() {
        ArrayList<Advice> categories = (ArrayList<Advice>) categoryRepository.findAll();
        categories.sort(Comparator.comparingLong(Advice::getAdviceID));
        return categories;
    }

    public Optional<Advice> getByIdOptional(long id) {
        Optional<Advice> optionalCategory = categoryRepository.findById(id);
        return optionalCategory;
    }

    public Advice getById(long id) {
        Optional<Advice> optionalCategory = categoryRepository.findById(id);
        if (optionalCategory.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Category with the id: " + id + " not found");
        }
        return optionalCategory.get();
    }

    public Advice addCategory(Advice newAdvice) {
        return categoryRepository.save(newAdvice);
    }

    public void deleteCategory(long id) {
        categoryRepository.deleteById(id);
    }
}
