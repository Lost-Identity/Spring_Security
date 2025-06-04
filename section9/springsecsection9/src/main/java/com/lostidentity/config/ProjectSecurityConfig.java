package com.lostidentity.config;

import com.lostidentity.exceptionhandling.CustomAccessDeniedHandler;
import com.lostidentity.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import com.lostidentity.filter.CsrfCookieFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@Profile("!prod")
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
        /*http.authorizeHttpRequests((requests -> requests.anyRequest().permitAll()));*/
        /*http.authorizeHttpRequests((requests -> requests.anyRequest().denyAll()));*/
        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
//        csrfTokenRequestAttributeHandler.setCsrfRequestAttributeName("_csrf");

        http.securityContext(contextConfig -> contextConfig.requireExplicitSave(false))
                .sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .cors(corsConfig -> corsConfig.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        config.setMaxAge(3600L);
                        return config;
                    }
                }))
                .csrf(csrfConfig -> csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                        .ignoringRequestMatchers("/contact", "/register")
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .requiresChannel(rcc -> rcc.anyRequest().requiresInsecure()) //only http
                .authorizeHttpRequests((requests) -> requests
                /*.requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
                .requestMatchers("/myBalance").hasAuthority("VIEWBALANCE")
                .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
                .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")*/
                .requestMatchers("/myAccount").hasRole("USER")
                .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/myCards").hasRole("USER")
                .requestMatchers("/myLoans").hasRole("ADMIN")
                .requestMatchers("/user").authenticated()
                .requestMatchers("/notices", "/contact", "/register", "/error", "/invalidSession").permitAll());
        /*http.formLogin(Customizer.withDefaults());*/
        /*http.formLogin(httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer.disable());*/
        /*http.httpBasic(Customizer.withDefaults());*/
        /*http.httpBasic(httpSecurityHttpBasicConfigurer -> httpSecurityHttpBasicConfigurer.disable());*/
        http.formLogin(Customizer.withDefaults());
//        http.httpBasic(Customizer.withDefaults());
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler())); // It is global config
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
