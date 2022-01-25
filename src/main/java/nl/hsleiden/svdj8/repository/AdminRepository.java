package nl.hsleiden.svdj8.repository;

import nl.hsleiden.svdj8.models.tables.Admin;
import org.springframework.data.repository.CrudRepository;

public interface AdminRepository extends CrudRepository<Admin, Long> {
    Admin findByName(String name);
}
