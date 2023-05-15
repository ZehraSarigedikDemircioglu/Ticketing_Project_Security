package com.cydeo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {

        List<UserDetails> userList = new ArrayList<>();

        userList.add(
                new User("mike",encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")))
        );

        userList.add(
                new User("ozzy",encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGER")))
        );

        return new InMemoryUserDetailsManager(userList);

    } // always Spring user, be careful not import our User entity

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests()// authorization for each request, localhost:8080 with the user what is the authorization
                .antMatchers("/user/**").hasRole("ADMIN")
                .antMatchers("/project/**").hasRole("MANAGER")
                .antMatchers("/task/employee/**").hasRole("EMPLOYEE")
                .antMatchers("/task/**").hasRole("MANAGER")
//                .antMatchers("/task/**").hasAnyRole("EMPLOYEE", "ADMIN") // we do not use this, but it is just example it can be multiple duty
                .antMatchers("/task/**").hasAuthority("ROLE_EMPLOYEE")
                .antMatchers( // certain things in the pages, we permit anybody can access these pages
                        "/",
                        "/login",
                        "/fragments/**",
                        "/assets/**",
                        "/images/**"
                ).permitAll()
                .anyRequest().authenticated() // any other request needs to be authenticated
                .and()
                .httpBasic() // one pop-up page
                .and().build();
    }
}
