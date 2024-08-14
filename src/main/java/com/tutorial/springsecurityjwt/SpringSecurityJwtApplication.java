package com.tutorial.springsecurityjwt;

import com.tutorial.springsecurityjwt.config.RsaKeyConfigProperties;
import com.tutorial.springsecurityjwt.model.User;
import com.tutorial.springsecurityjwt.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableConfigurationProperties(RsaKeyConfigProperties.class)
@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

	@Bean
	public CommandLineRunner initializeUser(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
		return args -> {

				User user = new User();
				user.setUsername("admin");
				user.setEmail("admin@gmail.com");
				user.setPassword(passwordEncoder.encode("admin"));
				// Save the user to the database
				//userRepository.save(user);

		};
	}

}
