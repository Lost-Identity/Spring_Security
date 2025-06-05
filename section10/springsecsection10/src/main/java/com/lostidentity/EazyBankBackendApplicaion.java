package com.lostidentity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity(debug = true)
/*@EnableJpaRepositories("com.lostidentity.repository")
@EntityScan("com.lostidentity.model")*/
public class EazyBankBackendApplicaion {

	public static void main(String[] args) {

		SpringApplication.run(EazyBankBackendApplicaion.class, args);
	}

}
