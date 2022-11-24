package com.kjh.security.basicsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //인가 정책
        http
                .authorizeRequests()//요청에 대한 보안 검사를 실시
                .anyRequest().authenticated(); //어떤 요청도 인증을 받아야함
        //인증 정책
        http
                .formLogin()
                //.loginPage("/loginPage") //아직 사용자 정의 로그인 페이지 없기 때문에 주석 처리함
                .defaultSuccessUrl("/")
                .failureUrl("/loginPage")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    //인증성공 시 처리 할 클래스
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    //인증 실패 시 처리
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                //remember-me 토큰 설정 (자동 로그인, Id 기억하기)
                .and()
                .rememberMe()
                .rememberMeParameter("remember") //default : remember-me
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService)
                ;
        //동시 세션 제어관련 처리 추가
        http
                .sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true) //세션이 초과될경우 : 로그인을 실패하게 만듬 true / 이전세션을 만료시킨다. false
        ;
        http
                .sessionManagement()
                //.sessionFixation().none(); // 새션을 새로 생성하지 않는다.(세션 고정 공격에 취약)
                .sessionFixation().changeSessionId(); // 새션 아이디를 새로 바꿔준다.


        //로그아웃 처리
        //스프링 시큐리티틑 원칙적으로 POST로만 로그아웃 구현 가능 하다.
        http
                .logout()
                .logoutUrl("/logout") //로그아웃 요청 url
                .logoutSuccessUrl("/login") //로그 아웃 성공시 이동 페이지
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();//세션해제
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        //logoutSuccessURl 은 페잊만 이동가능하지만 SuccessHandler는 여러가지 처리가 가능하다.
                        response.sendRedirect("/login");//일단 login 페이지 이동기능만 넣는다.
                    }
                })
                .deleteCookies("remember-me") //로그아웃할때 이 쿠키가 삭제한다.
        ;

        return http.build();
    }
}
