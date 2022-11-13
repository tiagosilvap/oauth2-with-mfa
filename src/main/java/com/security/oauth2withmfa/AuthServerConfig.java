package com.security.oauth2withmfa;

import com.security.oauth2withmfa.mfa.MfaService;
import com.security.oauth2withmfa.mfa.MfaTokenGranter;
import com.security.oauth2withmfa.mfa.PasswordTokenGranter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableAuthorizationServer
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {
    
    private PasswordEncoder passwordEncoder;
    
    private AuthenticationManager authenticationManager;
    
    private MfaService mfaService;
    
    @Autowired
    public AuthServerConfig(PasswordEncoder passwordEncoder,
                            AuthenticationManager authenticationManager,
                            MfaService mfaService) {
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.mfaService = mfaService;
    }
    
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("client")
                .secret(passwordEncoder.encode("secret"))
                .authorizedGrantTypes("password", "mfa")
                .scopes("read");
    }
    
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("permitAll()");
    }
    
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.tokenGranter(tokenGranter(endpoints));
    }
    
    private TokenGranter tokenGranter(final AuthorizationServerEndpointsConfigurer endpoints) {
        List<TokenGranter> granters = new ArrayList<>(List.of(endpoints.getTokenGranter()));
        granters.add(new PasswordTokenGranter(endpoints, authenticationManager, mfaService));
        granters.add(new MfaTokenGranter(endpoints, authenticationManager, mfaService));
        return new CompositeTokenGranter(granters);
    }
}
