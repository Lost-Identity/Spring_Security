package com.lostidentity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
        /*http.authorizeHttpRequests((requests -> requests.anyRequest().permitAll()));*/
        /*http.authorizeHttpRequests((requests -> requests.anyRequest().denyAll()));*/
        http.csrf(csrfConfig -> csrfConfig.disable())
                .authorizeHttpRequests((requests) -> requests
                .requestMatchers("/myAccount", "/myBalance", "myCards", "myLoans").authenticated()
                .requestMatchers("/notices", "/contact", "/register", "/error").permitAll());
        /*http.formLogin(Customizer.withDefaults());*/
        /*http.formLogin(httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer.disable());*/
        /*http.httpBasic(Customizer.withDefaults());*/
        /*http.httpBasic(httpSecurityHttpBasicConfigurer -> httpSecurityHttpBasicConfigurer.disable());*/
        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());
        return http.build();
    }

/*    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource){
        return new JdbcUserDetailsManager(dataSource);

    }*/

    @Bean
    public PasswordEncoder passwordEncoder(){
        /*return new BCryptPasswordEncoder();*/
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();

    }

    /**
     * From Spring Security 3.6
     * @return
     */
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker(){
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }
}
