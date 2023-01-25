package com.example.oauth2_jwt_key1.auth;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.time.ZoneId;
import java.util.Map;

/**
 * 토큰에 맞춤형 세부 정보 추가하기
 */
public class CustomTokenEnhancer implements TokenEnhancer {

    /**
     * 토큰을 받고 향상된 토큰을 반환하는 메서드 재정의
     */
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
        // 받은 토큰을 바탕으로 새 토큰 생성
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(oAuth2AccessToken);

        // 토큰에 추가할 세부 정보 맵으로 정의
        Map<String, Object> info = Map.of("generatedInZone", ZoneId.systemDefault().toString());

        // 토큰에 세부 정보 추가
        token.setAdditionalInformation(info);
        return token;
    }
}
