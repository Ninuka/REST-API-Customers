package com.luv2code.springboot.cruddemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
@Configuration
public class DemoSecurityConfig {

    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource){

        JdbcUserDetailsManager jdbcUserDetailsManager =new JdbcUserDetailsManager(dataSource);
        //define query to fte a user by username
        jdbcUserDetailsManager.setUsersByUsernameQuery(
                "select user_id,pw,active from members where user_id=?"
        );
        //define query to retrieve the authorities // roles by username
        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(
                "select user_id,role form roles where user_id=?"
        );

        return jdbcUserDetailsManager;

    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws  Exception{
        http.authorizeHttpRequests( configurer -> configurer
                .requestMatchers(HttpMethod.GET,"/api/employees").hasRole("EMPLOYEE")
                .requestMatchers(HttpMethod.GET,"/api/employees/**").hasRole("EMPLOYEE")
                .requestMatchers(HttpMethod.POST,"/api/employees").hasRole("MANAGER")
                .requestMatchers(HttpMethod.PUT,"/api/employees").hasRole("MANAGER")
                .requestMatchers(HttpMethod.DELETE,"/api/employees/**").hasRole("ADMIN"));

        //use HTTP Basic Authentication
        http.httpBasic();

        //disable Cross Site Request Forgery (CSRF)
        http.csrf().disable();

        return http.build();
    }
}
