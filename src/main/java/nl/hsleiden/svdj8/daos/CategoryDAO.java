package nl.hsleiden.svdj8.daos;

import javassist.NotFoundException;
import nl.hsleiden.svdj8.models.tables.Answer;
import nl.hsleiden.svdj8.models.tables.Category;
import nl.hsleiden.svdj8.repository.CategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@Component
public class CategoryDAO {

    @Autowired
    private CategoryRepository categoryRepository;

    public CategoryDAO(CategoryRepository categoryRepository) {
        this.categoryRepository = categoryRepository;
    }

    public List<Category> getAll() {
        ArrayList<Category> categories = (ArrayList<Category>) categoryRepository.findAll();
        categories.sort(Comparator.comparingLong(Category::getCategoryID));
        return categories;
    }

    public Category getById(long id) {
        return getOutOfRepositoryBy(id).get();
    }

    public Optional<Category> getOutOfRepositoryBy(long id) {
        Optional<Category> optionalCategory = categoryRepository.findById(id);
        if (optionalCategory.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Category with the id: " + id + " not found");
        }
        return optionalCategory;
    }

    public Category addCategory(Category newCategory) {
        return categoryRepository.save(newCategory);
    }

    public void deleteCategory(long id) {
        categoryRepository.deleteById(id);
    }
}
