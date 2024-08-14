package com.tutorial.springsecurityjwt.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, jsr250Enabled = true)
public class WebSecurityConfig extends JsonWebTokenSecurityConfig {

    @Override
    protected void setupAuthorization(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> {
            auth.requestMatchers("/error/**").permitAll();
            auth.requestMatchers("/api/auth/**").permitAll();
            auth.anyRequest().authenticated();
        });
    }
}
