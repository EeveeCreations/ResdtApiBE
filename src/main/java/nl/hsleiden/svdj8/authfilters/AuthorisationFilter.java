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

import static org.springframework.http.HttpHeaders.*;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@CrossOrigin(origins = {"*"})
public class AuthorisationFilter extends OncePerRequestFilter {

    private final TokenService tokenService = new TokenService();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        response.setContentType(APPLICATION_JSON_VALUE);
        if (request.getServletPath().equals("/login") ||
                request.getServletPath().equals("/auth/token/refresh") ||
                request.getServletPath().equals("/auth/register") ||
                request.getServletPath().equals("/question/all") ||
                request.getServletPath().equals("/grant/all") ||
                request.getServletPath().equals("/route/new") ||
                request.getServletPath().equals("/route/new") ||
                (request.getServletPath().startsWith("/grant/") && request.getMethod().equals("GET")) ||
                (request.getServletPath().startsWith("/answer/") && request.getMethod().equals("GET"))) {
                filterChain.doFilter(request, response);
        } else {
             String authorizationHeader = request.getHeader(AUTHORIZATION);
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                try {
                    String token = authorizationHeader.substring("Bearer ".length());
                    String userName = this.tokenService.getUserNameFromToken(token);
                    Collection<SimpleGrantedAuthority> authorities = this.tokenService.getRolesFromToken(token);
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(userName, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    response.setStatus(200);
                    filterChain.doFilter(request, response);
                } catch (Exception exception) {
                    response.setHeader("errors", exception.getMessage());
                    Map<String, String> errors = new HashMap<>();
                    errors.put("errors", exception.getMessage());
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    new ObjectMapper().writeValue(response.getOutputStream(), errors);
                }
            } else {
                response.setHeader("errors", "no authizati");
                Map<String, String> errors = new HashMap<>();
                errors.put("errors", "no auth");
                response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
                new ObjectMapper().writeValue(response.getOutputStream(), errors);
            }
        }

    }
}
