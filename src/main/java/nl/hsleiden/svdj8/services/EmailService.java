package nl.hsleiden.svdj8.services;

import com.auth0.jwt.JWT;
import nl.hsleiden.svdj8.models.tables.Admin;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Service;

@Service
public class EmailService extends SimpleMailMessage {

    @Autowired
    private TokenService tokenService;

    public void randomiseLinkToken(){

    }

    public void setUpEmail(String email, Admin admin){
        createEmail(email, admin);
    }

    public void sendEmail(){

    }

    public void createEmail(String email, Admin admin){
//        String passwordToken = JWT.create(admin.getName()).sign(tokenService.returnAlgorithm());

    }

    public String checkTokenForAdmin(String passwordToken){
        return this.tokenService.getUserNameFromToken(passwordToken);
    }

    public void ResetPassword(){

    }
}
