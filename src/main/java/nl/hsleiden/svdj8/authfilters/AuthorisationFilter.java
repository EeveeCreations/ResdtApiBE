package nl.hsleiden.svdj8.authfilters;

import com.fasterxml.jackson.databind.ObjectMapper;
import nl.hsleiden.svdj8.services.TokenService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;
@CrossOrigin("http://localhost:4200")
public class AuthorisationFilter extends OncePerRequestFilter {

    private final TokenService tokenService = new TokenService();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (request.getServletPath().equals("/login") ||
                request.getServletPath().equals("/auth/token/refresh") ||
                request.getServletPath().equals("/auth/register")) {
            filterChain.doFilter(request, response);
        } else {
            String authorizationHeader = request.getHeader("Authorization");
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                try {
                    String token = authorizationHeader.substring("Bearer ".length());
                    String userName = this.tokenService.getUserNameFromToken(token);
                    Collection<SimpleGrantedAuthority> authorities = this.tokenService.getRolesFromToken(token);
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(userName, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    response.addHeader(
                            "Access-Control-Allow-Origin","http://localhost4200");
                    response.addHeader(
                            "Access-Control-Allow-Methods", "GET,POST,DELETE,PUT");
                    response.setHeader("Access-Control-Allow-Credentials", "true");
                    response.setStatus(200);
                    filterChain.doFilter(request, response);
                } catch (Exception exception) {
                    response.setHeader("errors", exception.getMessage());
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    Map<String,String> errors = new HashMap<>();
                    errors.put("errors",exception.getMessage());
                    response.setHeader("Access-Control-Allow-Origin","http://localhost4200");
                    response.addHeader(
                            "Access-Control-Allow-Methods", "GET,POST,DELETE,PUT");
                    response.setHeader("Access-Control-Allow-Credentials", "true");
                    response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
                    response.setContentType( APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), errors);
                }
            }
        }

    }
}
