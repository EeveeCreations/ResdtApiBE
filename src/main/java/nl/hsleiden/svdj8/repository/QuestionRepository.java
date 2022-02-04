package nl.hsleiden.svdj8.repository;

import nl.hsleiden.svdj8.models.tables.Question;
import org.springframework.data.repository.CrudRepository;

public interface QuestionRepository  extends CrudRepository<Question, java.lang.Long> {
}
