package nl.hsleiden.svdj8.services;

import nl.hsleiden.svdj8.models.tables.Admin;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Service;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Properties;

@Service
public class EmailService extends SimpleMailMessage {

    @Autowired
    private TokenService tokenService;

    public URL randomiseLinkToken(String email, Admin admin) {
//       "https://www.svdj.nl/
        try {
            String passwordToken = this.tokenService.createPasswordToken(admin);
            URIBuilder uri = new URIBuilder("http://localhost:4200/admin/wachtwoord-vergeten");
            uri.addParameter("token", passwordToken);
            uri.addParameter("email", email);

            return uri.build().toURL();
        }catch (URISyntaxException | MalformedURLException uriSyntaxException){
           uriSyntaxException.getMessage();
        }
        return null;
    }

    public void setUpEmail(String email, Admin admin){
        sendEmail(email,admin);
    }

    public void sendEmail(String to, Admin admin){
        String from = "svdj@noreply.com";
        String host = "smtp.gmail.com";
        Properties properties = setMailProperties(host);
        Session session = setSession(properties);
        session.setDebug(true);
        try {
            MimeMessage message = new MimeMessage(session);

            message.setFrom(new InternetAddress(from));
            message.addRecipient(Message.RecipientType.TO, new InternetAddress(to));
            message.setSubject("Wachtwoord Reset SVDJ subsidiewijzer");
            message.setText("Beste Admin,"+
                    "Hierbij de reset lnk voor een nieuw wachtwoord " +
                    "Klik de link onder"+
                    randomiseLinkToken(to,admin));
            Transport.send(message);
        } catch (MessagingException mex) {
            mex.printStackTrace();
        }

    }

    private Properties setMailProperties(String host) {
        Properties properties = System.getProperties();
        properties.put("mail.smtp.host", host);
        properties.put("mail.smtp.port", "465");
        properties.put("mail.smtp.ssl.enable", "true");
        properties.put("mail.smtp.auth", "true");
        return properties;
    }

    private Session setSession(Properties properties) {
        return  Session.getInstance(properties, new javax.mail.Authenticator() {

            protected PasswordAuthentication getPasswordAuthentication() {

                return new PasswordAuthentication("eeveethestudent@gmail.com", "ThisIsStudentOnly38");

            }

        });
    }


    public String checkTokenForAdmin(String passwordToken){
        return this.tokenService.getUserNameFromToken(passwordToken);
    }
}
