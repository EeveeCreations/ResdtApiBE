package nl.hsleiden.svdj8.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import nl.hsleiden.svdj8.models.tables.Admin;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

public class TokenService {

//     TODO: Considder if this is save
    private final String algorithm = "SVDJ";
    private final int MINUTE = 60;
    private final int MILLISECONDS = 1000;
    private int EXPIRE_TIME = 30;

    public String createToken(User user, HttpServletRequest request, String type) {
        if(type.equals("refresh")){
           this.EXPIRE_TIME = 40;
        }
        Algorithm algorithm = returnAlgorithm();
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (long) this.EXPIRE_TIME * this.MINUTE * this.MILLISECONDS))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("role", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

    }

     public Algorithm returnAlgorithm(){
         return Algorithm.HMAC256(this.algorithm.getBytes());
     }

     public Map<String, String> createTokenHeader(String accessToken,String  refreshToken){
         Map<String,String> tokens = new HashMap<>();
         tokens.put("accessToken",accessToken);
         tokens.put("refreshToken",refreshToken);
         return tokens;
     }

    public String createForRefreshToken(Admin admin) {
        return JWT.create()
                .withSubject(admin.getName())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRE_TIME * MINUTE * MILLISECONDS))
                .withClaim("role", admin.getRole())
                .sign(returnAlgorithm());
    }
    public String getUserNameFromToken(String token){
        Algorithm algorithm = Algorithm.HMAC256(this.algorithm.getBytes());
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(token);
        return decodedJWT.getSubject();
    }
    public Collection<SimpleGrantedAuthority> getRolesFromToken(String token){
        Algorithm algorithm = Algorithm.HMAC256(this.algorithm.getBytes());
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(token);
        String[] roles = decodedJWT.getClaim("role").asArray(String.class);
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        stream(roles).forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role));
        });
        return authorities;
    }
}
