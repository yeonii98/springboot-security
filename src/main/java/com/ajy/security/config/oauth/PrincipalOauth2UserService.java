package com.ajy.security.config.oauth;

import com.ajy.security.config.auth.PrincipalDetails;
import com.ajy.security.config.oauth.provider.FacebookUserInfo;
import com.ajy.security.config.oauth.provider.GoogleUserInfo;
import com.ajy.security.config.oauth.provider.NaverUserInfo;
import com.ajy.security.config.oauth.provider.OAuth2UserInfo;
import com.ajy.security.model.User;
import com.ajy.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    //구글로 부터 받은 userRequest 데이터에 대한 후처리 되는 함수
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
   @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
       // 구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료 -> code를 리턴(OAuth-Client 라이브러리가 받아줌) -> AccessToken 요청
       // userRequest 정보 -> loadUser 함수 호출 -> 구글로부터 회원프로필 받아준다.
       System.out.println("userRequest.getClientRegistration() = " + userRequest.getClientRegistration());//registrationId로 어떤 OAuth로 로그인 했는지 확인 가능
       //구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인을 완료 -> code를 리턴(OAuth-Client라이브러리) -> AccessToken요청
       //userRequest 정보 -> loadUser함수 호출 -> 구글로부터 회원프로필을 받아준다.
       System.out.println("userRequest.getAccessToken().getTokenValue() = " + userRequest.getAccessToken().getTokenValue());

       OAuth2User oAuth2User = super.loadUser(userRequest);
       System.out.println("getAttributes = " + oAuth2User.getAttributes());

       OAuth2UserInfo oAuth2UserInfo = null;
       if(userRequest.getClientRegistration().getRegistrationId().equals("google")){
           System.out.println("구글 로그인 요청");
           oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
       }else if(userRequest.getClientRegistration().getRegistrationId().equals("google")){
           System.out.println("페이스북 로그인 요청");
           oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
       }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
           System.out.println("네이버 로그인 요청");
           oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
       }else{
           System.out.println("우리는 구글과 페이스북과 네이버만 지원해요 ㅎㅎ");
       }

       String provider = oAuth2UserInfo.getProvider();
       String providerId = oAuth2UserInfo.getProviderId();
       String username = provider+"_"+providerId;
       String email = oAuth2UserInfo.getEmail();
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
