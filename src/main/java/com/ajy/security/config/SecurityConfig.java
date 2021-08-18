package com.ajy.security.config;

import com.ajy.security.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터체인 안에 등록이 된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //secured 어노테이션 활성화, preAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() //로그인 된 사용자만 접근 가능
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") //어드민 또는 매니저만 접근 가능
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')") //어드민만 접근 가능
                .anyRequest().permitAll() // 그외의 접근은 허용
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") //login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인 진행, form의 action과 일치
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService);
        //구글 로그인 완료된 뒤의 후처리가 필요함. Tip. 코드는 안 받고, 엑세스 토큰 + 사용자 프로필 정보를 받는다.
        //1. 코드받기(인증 - 로그인 된 사용자입니다.), 2. 엑세스토큰(권한이 생김), 3. 사용자 프로필 정보 가져옴. 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
        //4-2. 백화점이나 쇼핑물 같이 더 많은 사용자 정보를 요구한다면 추가 정보를 넣어야 함
    }
}
