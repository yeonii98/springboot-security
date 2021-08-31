package com.ajy.security.controller;

import com.ajy.security.auth.PrincipalDetails;
import com.ajy.security.model.User;
import com.ajy.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller //View를 리턴하겠다!!
public class IndexController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    //시큐리티 세션 Authentication -> userDetails(일반로그인), oAuth2User(oAuth 로그인)
    //PrincipalDetails 타입으로 묶는다.
    //시큐리티가 들고있는 세션 -> Authentication(OAuth2user, userDetails)
    @GetMapping("test/login")
    public @ResponseBody String testLogin(Authentication authentication,
                                           @AuthenticationPrincipal PrincipalDetails userDatails){
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principalDetails = " + principalDetails.getUser());
        System.out.println("userDatails = " + userDatails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("test/oauth/login")
    public @ResponseBody String testOAuthLogin(Authentication authentication,
                                               @AuthenticationPrincipal OAuth2User oAuth){
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("oAuth2User = " + oAuth2User.getAttributes());
        System.out.println("oAuth = " + oAuth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }


    @GetMapping({"","/"})
    public String index(){
        //머스테치 - 스프링에서 권장하는 템플릿 - 기본 폴더 : src/main/resources/
        //뷰리졸버 설정 : templates (prefix), mustache (suffix), mustache를 그래들에 등록해서 생략가능함
        return "index"; // 기본 경로 :  resources/templates/index.mustach
    }

    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails){
        System.out.println("principalDetails = " + principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public String manager(){
        return "manager";
    }

    @GetMapping("/loginForm")
    public String login(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user){
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user); //회원가입은 잘 되지만 시큐리티 로그인 할 수 없음 -> 패스워드 암호화를 해야함
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN") //특정 메소드에 간단하게 권한처리를 하고 싶을 때 사용하는 어노테이션
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }

   @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") //메소드 실행 전에 권한이 주어진다. 권한 여러개를 주고 싶을 때 주로 사용
   @GetMapping("/data")
    public @ResponseBody String data(){
        return "데이터정보";
    }

}




