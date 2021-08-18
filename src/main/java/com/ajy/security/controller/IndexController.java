package com.ajy.security.controller;

import com.ajy.security.model.User;
import com.ajy.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
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

    @GetMapping({"","/"})
    public String index(){
        //머스테치 - 스프링에서 권장하는 템플릿 - 기본 폴더 : src/main/resources/
        //뷰리졸버 설정 : templates (prefix), mustache (suffix), mustache를 그래들에 등록해서 생략가능함
        return "index"; // 기본 경로 :  resources/templates/index.mustach
    }

    @GetMapping("/user")
    public String user(){
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




