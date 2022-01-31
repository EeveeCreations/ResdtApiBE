package nl.hsleiden.svdj8.controllers.tables;

import nl.hsleiden.svdj8.daos.GrantDAO;
import nl.hsleiden.svdj8.models.tables.Grant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
public class GrantController {

    @Autowired
    public final GrantDAO grantDAO;

    public GrantController(GrantDAO grantDAO) {
        this.grantDAO = grantDAO;
    }

    @GetMapping(value = "/grant/all")
    public List<Grant> getAllGrants() {
        return grantDAO.getAll();
    }

    @GetMapping(value = "/grant/{id}")
    public Grant getGrant(@PathVariable final Long id) {
        return grantDAO.getById(id);
    }

    @PutMapping(value = "/grant/{id}")
    public Grant editGrant(@RequestBody Grant editGrant, @PathVariable Long id) throws Exception {

        return grantDAO.getByIdOptional(id)
                .map(grant -> {
                    grant.setName(editGrant.getName());
                    grant.setDescription(editGrant.getDescription());
                    return grantDAO.addGrant(grant);
                })
                .orElseThrow(() -> new Exception(
                        "No grant found with id " + id + "\""));

    }

    @PutMapping(value = "/grant")
    public Grant addGrant(@RequestBody Grant newGrant) {
        return grantDAO.addGrant(newGrant);
    }

    @DeleteMapping("/grant/{id}")
    public void deleteGrant(@PathVariable Long id) {
        grantDAO.deleteById(id);
    }
}
