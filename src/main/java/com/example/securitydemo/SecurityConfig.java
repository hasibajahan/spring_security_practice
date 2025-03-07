package com.example.securitydemo;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
	
	@Autowired
	DataSource dataSource;
	
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
				.password(passwordEncoder().encode("password1"))//use of {noop} -> stores the passwords in memory as plain text instead of encoding it. Not a production grade practice
				.roles("USER")
				.build();
		 UserDetails admin= User.withUsername("admin")
				 .password(passwordEncoder().encode("adminPass"))
				 .roles("ADMIN")
				 .build();
		 
		 //For replacing in memory userDetailsManager with jdbcUserDetailsManager.
		 //This will make sure that our data is being stored in the database.
		 JdbcUserDetailsManager userDetailsManager
		 				=new JdbcUserDetailsManager(dataSource);
		 userDetailsManager.createUser(user1);
		 userDetailsManager.createUser(admin);
		 return userDetailsManager;
//		return new InMemoryUserDetailsManager(user1,admin);
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
