package nl.hsleiden.svdj8.controllers;


import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import nl.hsleiden.svdj8.daos.AdminDAO;
import nl.hsleiden.svdj8.models.tables.Admin;
import nl.hsleiden.svdj8.services.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@AllArgsConstructor
@RestController
@CrossOrigin(origins = {"*"})
public class AuthenticationController {

    @Autowired
    private final AdminDAO adminDAO;

    @Autowired
    private final TokenService tokenService;


    @PostMapping(value = "/register")
    public Admin addUser(@RequestBody Admin newAdmin) {
        return adminDAO.addAdmin(newAdmin);
    }

    @GetMapping(value = "/token/refresh")
    public void refreshToken(HttpServletRequest request,
                             HttpServletResponse response,
                             FilterChain filterChain,
                             Authentication authentication) throws IOException, ServletException {
        String authorisationHeader = request.getHeader(AUTHORIZATION);
        String refreshToken = request.getHeader(AUTHORIZATION);
        if (authorisationHeader != null && authorisationHeader.startsWith("Bearer ")) {
            try {
                String adminName = this.tokenService.getUserNameFromToken(authorisationHeader.substring("Bearer ".length()));
                Admin admin = adminDAO.getAdminByName(adminName);
                String accessToken = tokenService.createForRefreshToken(admin);
                Map<String, String> tokens = new HashMap<>();
                tokens.put("name", admin.getName());
                tokens.put("password", admin.getPassword());
                tokens.put("role", admin.getRole());
                tokens.put("accessToken", accessToken);
                tokens.put("refreshToken", refreshToken);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
            } catch (Exception exception) {
                response.setHeader("error", exception.getMessage());
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                Map<String, String> error = new HashMap<>();
                error.put("error_message", exception.getMessage());
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        } else {
            filterChain.doFilter(request, response);
        }


    }
}

