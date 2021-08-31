package com.ajy.security.oauth;

import com.ajy.security.auth.PrincipalDetails;
import com.ajy.security.model.User;
import com.ajy.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    //구글로 부터 받은 userRequest 데이터에 대한 후처리 되는 함수
   @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
       // 구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료 -> code를 리턴(OAuth-Client 라이브러리가 받아줌) -> AccessToken 요청
       // userRequest 정보 -> loadUser 함수 호출 -> 구글로부터 회원프로필 받아준다.
       System.out.println("userRequest.getClientRegistration() = " + userRequest.getClientRegistration());//registrationId로 어떤 OAuth로 로그인 했는지 확인 가능
       //구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인을 완료 -> code를 리턴(OAuth-Client라이브러리) -> AccessToken요청
       //userRequest 정보 -> loadUser함수 호출 -> 구글로부터 회원프로필을 받아준다.
       System.out.println("super.loadUser(userRequest = " + super.loadUser(userRequest).getAttributes());
       System.out.println("userRequest.getAccessToken().getTokenValue() = " + userRequest.getAccessToken().getTokenValue());
       OAuth2User oAuth2User = super.loadUser(userRequest);
       String provider = userRequest.getClientRegistration().getClientId();
       String providerId = oAuth2User.getAttribute("sub");
       String username = provider+"_"+providerId;
       String email = oAuth2User.getAttribute("email");
       String password =bCryptPasswordEncoder.encode("겟인데어");
       String role = "ROLE_USER";

       User userEntity = userRepository.findByUsername(username);

       if(userEntity == null){
           userEntity = User.builder()
                   .username(username)
                   .password(password)
                   .email(email)
                   .role(role)
                   .provider(provider)
                   .providerId(providerId)
                   .build();
           userRepository.save(userEntity);
       }

       return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
