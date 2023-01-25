package com.example.oauth2_jwt_key1.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

/**
 * 권한 부여 서버를 시작해서 /oauth/token 을 호출하면
 * 액세스 토큰을 생성 가능한데,
 * 이 토큰의 서명을 검증하려면 공개 키를 이용해야 함
 */
@Configuration
@EnableAuthorizationServer
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {

    @Value("${password}")
    private String password;
    @Value("${privateKey}")
    private String privateKey;
    @Value("${alias}")
    private String alias;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();

        // classpath 에서 비밀 키 파일을 읽을 KeyStoreFactory
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
                new ClassPathResource(privateKey), password.toCharArray()
        );

        // KeyStoreFactory 를 이용해 키 쌍 가져오고,
        // 컨버터에 키 쌍 설정
        converter.setKeyPair(
                keyStoreKeyFactory.getKeyPair(alias)
        );

        return converter;
    }
}
