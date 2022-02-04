package nl.hsleiden.svdj8;

import nl.hsleiden.svdj8.daos.AdminDAO;
import nl.hsleiden.svdj8.models.tables.Admin;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.Arrays;
import java.util.Collections;

@SpringBootApplication
@EnableSwagger2
public class Svdj8Application {

    public static void main(String[] args) {
        SpringApplication.run(Svdj8Application.class, args);
    }

    @Bean
    CommandLineRunner runner(AdminDAO adminDAO) {
        return args -> {
//				adminDAO.addAdmin(new Admin(null,"Eevee","root112","Admin"));
//							adminDAO.addAdmin(new Admin(null,"Eevee2","3ff1d66d2b6f0a0121f7a88d4de4d75d","Admin"));
            adminDAO.addAdmin(new Admin(null, "Admin", "114663ab194edcb3f61d409883ce4ae6c3c2f9854194095a5385011d15becbef" //admin12
                    , "Admin"));
            adminDAO.addAdmin(new Admin(null,"Mariet@svdj.nl","114663ab194edcb3f61d409883ce4ae6c3c2f9854194095a5385011d15becbef" //admin12
                    ,"Admin"));

//							adminDAO.addAdmin(new Admin(null,"Brandon","Noodels","Admin"));
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200/"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Origin", "content-type", "contenttype"));
        configuration.setExposedHeaders(Arrays.asList("Authorization", "Origin", "content-type", "contenttype"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**").allowedOrigins("http://localhost:4200/");
//                registry.addMapping("/**").allowedOrigins("*");

                registry.addMapping("/**").allowedHeaders("Authorization", "Origin", "Content-type");


            }
        };
    }

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(RequestHandlerSelectors.basePackage("nl.hsleiden.svdj8.controllers"))
                .paths(PathSelectors.any())
                .build()
                .apiInfo(metaData());
    }

    private ApiInfo metaData() {
        return new ApiInfo(
                "Svdj groep 8",
                "Spring Boot REST API for Svdj Application",
                "1.0",
                "Terms of service",
                new Contact("Brandon Plokker, Eefje Karremans", "https://springframework.guru/about/", "bla@bla.nl"),
                "Apache License Version 2.0",
                "https://www.apache.org/licenses/LICENSE-2.0",
                Collections.emptyList());
    }

    //	Authentication
    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
