package com.ajy.security.auth;

//로그인 완료 -> 시큐리티 session을 만들어줍니다. (Security ContextHolder에 저장)
//세션에 들어갈 수 있는 오브젝트 -> Authentication 타입 객체
//Authentication 안에 User정보가 있어야 됨.
//User오브젝트 타입 -> UserDetails타입 객체

//시큐리티가 갖고 있는 Security Session에 세션 정보 저장
//Security Session에 들어갈 수 있는 객체 -> Authentication -> UserDetails

import com.ajy.security.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class PrincipalDetails implements UserDetails {

    private User user;

    public PrincipalDetails(User user){
        this.user = user;
    }

    //해당 User의 권한을 리턴하는 곳!!
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {

        //1년 동안 회원이 로그인 안 하면 휴먼 계정으로 하기로 함.
        //현재시간 - 로긴시간 => 1년을 초과하면 return false;
        return true;
    }
}
