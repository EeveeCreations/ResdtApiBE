package nl.hsleiden.svdj8.authfilters;
import com.fasterxml.jackson.databind.ObjectMapper;
import nl.hsleiden.svdj8.services.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.CrossOrigin;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@CrossOrigin(origins = {"http://localhost:4200/", "*"})
public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Autowired
    private final TokenService tokenService;

    public AuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        this.tokenService = new TokenService();
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(authToken);
    }


    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user = (User) authResult.getPrincipal();
        String accessToken = this.tokenService.createToken(user, request, "access");
        String refreshToken = this.tokenService.createToken(user, request, "refresh");

        Map<String,String> tokens = new HashMap<>();
        tokens.put("username", user.getUsername());
        tokens.put("role", user.getAuthorities().toString());
        tokens.put("accessToken",accessToken);
        tokens.put("refreshToken",refreshToken);

        response.setContentType( APPLICATION_JSON_VALUE);
//        response.addHeader("Access-Control-Expose-Headers", "Authorization");
//        response.addHeader("Access-Control-Expose-Headers","*");
        response.addHeader("Access-Control-Allow-Headers", "Authorization, ContentType, Origin");
        response.addHeader(
                "Access-Control-Allow-Origin","http://localhost:4200");
        response.addHeader(
                "Access-Control-Allow-Methods", "GET,POST,DELETE,PUT");
        response.setStatus(200);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }
}