package nl.hsleiden.svdj8.repository;

import nl.hsleiden.svdj8.models.tables.Advice;
import org.springframework.data.repository.CrudRepository;

public interface CategoryRepository extends CrudRepository<Advice, Long> {
}
