package com.kjh.security.basicsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

@SpringBootApplication
public class BasicsecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(BasicsecurityApplication.class, args);
	}

	/**
	 * 기본 유저생성되기
	 * @return
	 */

	@Bean
	public UserDetailsManager users() {

		UserDetails user = User.builder()
				.username("user")
				.password("{noop}1111")
				.roles("USER")
				.build();

		UserDetails sys = User.builder()
				.username("sys")
				.password("{noop}1111")
				.roles("SYS")
				.build();

		UserDetails admin = User.builder()
				.username("admin")
				.password("{noop}1111")
				.roles("ADMIN", "SYS", "USER")
				.build();

		return new InMemoryUserDetailsManager( user, sys, admin );
	}
}
