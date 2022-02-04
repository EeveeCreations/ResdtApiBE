package nl.hsleiden.svdj8.daos;

import nl.hsleiden.svdj8.models.tables.Grant;
import nl.hsleiden.svdj8.repository.GrantRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@Component
public class GrantDAO {

    @Autowired
    private GrantRepository grantRepository;

    public GrantDAO(GrantRepository grantRepository) {
        this.grantRepository = grantRepository;
    }

    public List<Grant> getAll() {
        ArrayList<Grant> grants = (ArrayList<Grant>) this.grantRepository.findAll();
        grants.sort(Comparator.comparingLong(Grant::getGrantID));
        return grants;
    }

    public Grant getById(long id) {
        Optional<Grant> optionalGrant = grantRepository.findById(id);
        if (optionalGrant.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Grant with the id: " + id + " not found");
        }
        return optionalGrant.get();

    }

    public Optional<Grant> getByIdOptional(long id) {
        Optional<Grant> optionalGrant = grantRepository.findById(id);
        return optionalGrant;
    }

    public Grant addGrant(Grant newGrant) {
        return grantRepository.save(newGrant);
    }

    public void deleteById(long id) {
        grantRepository.deleteById(id);
    }
}
