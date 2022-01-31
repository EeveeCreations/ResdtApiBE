package nl.hsleiden.svdj8.controllers.tables;

import nl.hsleiden.svdj8.daos.AdminDAO;
import nl.hsleiden.svdj8.models.tables.Admin;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
public class AdminController {

    @Autowired
    public final AdminDAO adminDAO;

    public AdminController(AdminDAO adminDAO) {
        this.adminDAO = adminDAO;
    }

    @GetMapping(value = "/admin/all")
    public List<Admin> getAllAdmins() {
        return adminDAO.getAll();
    }

    @GetMapping(value = "/admin/{id}")
    public Admin getAdmin(@PathVariable final Long id) {
        return adminDAO.getById(id);
    }

    @PutMapping(value = "/admin/{id}")
    public Admin editAdmin(@RequestBody Admin editAdmin, @PathVariable Long id) throws Exception {

        return adminDAO.getByIdOptional(id)
                .map(admin -> {
                    admin.setName(editAdmin.getName());
                    admin.setPassword(editAdmin.getPassword());
                    return adminDAO.addAdmin(admin);
                })
                .orElseThrow(() -> new Exception(
                        "No admin found with id " + id + "\""));
    }

    @PostMapping(value = "/admin")
    public Admin addAdmin(@RequestBody Admin newAdmin) {
        return adminDAO.addAdmin(newAdmin);
    }

    @DeleteMapping("/admin/{id}")
    public void deleteAdmin(@PathVariable Long id) {
        adminDAO.deleteAdmin(id);
    }

}
