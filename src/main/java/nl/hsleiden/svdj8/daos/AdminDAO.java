package nl.hsleiden.svdj8.daos;

import javassist.NotFoundException;
import lombok.AllArgsConstructor;
import nl.hsleiden.svdj8.models.tables.Admin;
import nl.hsleiden.svdj8.repository.AdminRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@Component
@AllArgsConstructor
public class AdminDAO  implements UserDetailsService {
    @Autowired
    private AdminRepository adminRepository;

    private final BCryptPasswordEncoder passwordEncoder;
//    private final PasswordEncoder passwordEncoder;

    public List<Admin> getAll() {
        ArrayList<Admin> admins = (ArrayList<Admin>) this.adminRepository.findAll();
        admins.sort(Comparator.comparingLong(Admin::getAdminID));
        return admins;
    }

    public Admin getById(long id) {
        Optional<Admin> optionalAdmin = adminRepository.findById(id);
        if (optionalAdmin.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Admin with the id: " + id + " not found");
        }
        return optionalAdmin.get();
    }

    public Optional<Admin> getByIdOptional(long id) {
        return adminRepository.findById(id);
    }

    public void deleteAdmin(long id) {
        adminRepository.deleteById(id);
    }
    public Admin addAdmin(Admin newAdmin) {
        newAdmin.setPassword(this.passwordEncoder.encode(newAdmin.getPassword()));
        return adminRepository.save(newAdmin);
    }

    @Override
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        Admin admin =  adminRepository.findByName(name);
        if(admin != null){
            throw new UsernameNotFoundException("User is not found (Name incorrect)");
        }
        return new User(admin.getName(), admin.getPassword(),grantAuthorities(admin));
    }

    private Collection<SimpleGrantedAuthority> grantAuthorities(Admin admin) {
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(admin.getRole()));
        return authorities;
    }
}
