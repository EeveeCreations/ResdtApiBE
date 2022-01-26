package nl.hsleiden.svdj8.configuration;

import lombok.RequiredArgsConstructor;
import nl.hsleiden.svdj8.authfilters.AuthenticationFilter;
import nl.hsleiden.svdj8.authfilters.AuthorisationFilter;
import nl.hsleiden.svdj8.daos.AdminDAO;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.CrossOrigin;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@CrossOrigin("http://localhost:4200")
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final BCryptPasswordEncoder passwordEncoder;

    private final AdminDAO adminDetailService;

    @Override
    protected void configure(AuthenticationManagerBuilder authManagerBuilder) throws Exception {
        authManagerBuilder
                .userDetailsService(adminDetailService)
                .passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity httpSec) throws Exception {
        AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManagerBean());
        httpSec.csrf().disable();
        httpSec.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        chooseAuthorisedRequests(httpSec);
        httpSec.addFilter(authenticationFilter);
        httpSec.addFilterBefore(new AuthorisationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    private void chooseAuthorisedRequests(HttpSecurity httpSec) throws Exception {
        httpSec.authorizeRequests().antMatchers(HttpMethod.GET,"questions/all").permitAll();
        httpSec.authorizeRequests().antMatchers(HttpMethod.GET,"advise/{id}").permitAll();
        httpSec.authorizeRequests().antMatchers(HttpMethod.GET,"grant/all").permitAll();
        httpSec.authorizeRequests().antMatchers(HttpMethod.POST,"route/new").permitAll();
        httpSec.authorizeRequests().antMatchers(HttpMethod.POST,"put/{id}").permitAll();

//        httpSec.authorizeRequests().antMatchers(HttpMethod.POST,"route/new").hasAnyAuthority("platform");

        httpSec.authorizeRequests().antMatchers("questions/**").hasAnyAuthority("Admin");
        httpSec.authorizeRequests().antMatchers("advice/**").hasAnyAuthority("Admin");
        httpSec.authorizeRequests().antMatchers("grant/**").hasAnyAuthority("Admin");
        httpSec.authorizeRequests().antMatchers("answer/**").hasAnyAuthority("Admin");
        httpSec.authorizeRequests().antMatchers("admin/**").hasAnyAuthority("Admin");
        httpSec.authorizeRequests().antMatchers("result/**").hasAnyAuthority("Admin");
        httpSec.authorizeRequests().antMatchers("route/**").hasAnyAuthority("Admin");
        httpSec.authorizeRequests().antMatchers("givenAnswer/**").hasAnyAuthority("Admin");
    }


    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
