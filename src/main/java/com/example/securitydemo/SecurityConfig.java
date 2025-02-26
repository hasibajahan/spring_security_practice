package com.example.securitydemo;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import static org.springframework.security.config.Customizer.withDefaults;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((requests) -> 
		requests.requestMatchers("/h2-console/**").permitAll()
				.anyRequest().authenticated()).csrf(csrf->csrf.ignoringRequestMatchers("/h2-console/**"));
		http.sessionManagement(session
				-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		
		//http.formLogin(withDefaults());
		http.httpBasic(withDefaults());
		http.headers(headers->
		headers.frameOptions(frameOptions->frameOptions.sameOrigin()));
		return http.build();
	} 
	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user1=User.withUsername("user1")
				.password("{noop}password1")//use of {noop} -> stores the passwords in memory as plain text instead of encoding it. Not a production grade practice
				.roles("USER")
				.build();
		 UserDetails admin= User.withUsername("admin")
				 .password("{noop}adminPass")
				 .roles("ADMIN")
				 .build();
		 
		return new InMemoryUserDetailsManager(user1,admin);
	}
}
