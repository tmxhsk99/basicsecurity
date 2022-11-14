package com.kjh.security.basicsecurity.configure;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        
        //인가 정책
        http
                .authorizeRequests()//요청에 대한 보안 검사를 실시
                .anyRequest().authenticated(); //어떤 요청도 인증을 받아야함

        //인증 정책
        http
                .formLogin();
        
        return http.build();
    }
}
