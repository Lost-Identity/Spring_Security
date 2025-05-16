package com.lostidentity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
/*@EnableJpaRepositories("com.lostidentity.repository")
@EntityScan("com.lostidentity.model")*/
public class EazyBankBackendApplicaion {

	public static void main(String[] args) {

		SpringApplication.run(EazyBankBackendApplicaion.class, args);
	}

}
