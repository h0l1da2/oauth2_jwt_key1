package com.example.oauth2_jwt_key1.config;

import com.example.oauth2_jwt_key1.auth.CustomTokenEnhancer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.util.List;

/**
 * 권한 부여 서버를 시작해서 /oauth/token 을 호출하면
 * 액세스 토큰을 생성 가능한데,
 * 이 토큰의 서명을 검증하려면 공개 키를 이용해야 함
 */
@Configuration
@EnableAuthorizationServer
public class AuthServerConfigB extends AuthorizationServerConfigurerAdapter {

    @Value("${password}")
    private String password;
    @Value("${privateKey}")
    private String privateKey;
    @Value("${alias}")
    private String alias;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();

        // 목록에 토큰 인핸서 객체 두개 추가
        List<TokenEnhancer> tokenEnhancers = List.of(new CustomTokenEnhancer(), jwtAccessTokenConverter());

        // 체인에 토큰 인핸서 목록 추가
        tokenEnhancerChain.setTokenEnhancers(tokenEnhancers);

        // 토큰 인핸서 객체 구성
        endpoints
                .authenticationManager(authenticationManager)
                .tokenStore(tokenStore())
                .tokenEnhancer(tokenEnhancerChain);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        clients.inMemory()
                .withClient("client")
                .secret("secret")
                .authorizedGrantTypes("password", "refresh_token")
                .scopes("read")

                .and()
                // 공개 키 엔드포인트 호출할 때 리소스 서버가 이용하는 자격증명
                .withClient("resourceserver")
                .secret("resourceserversecret");
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // 올바른 클라이언트 자격 증명으로 인증하고 요청할 때,
        // 공개 키를 제공하는 권한 부여 서버의 엔드 포인트
        security.tokenKeyAccess("isAuthenticated()");
    }

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
