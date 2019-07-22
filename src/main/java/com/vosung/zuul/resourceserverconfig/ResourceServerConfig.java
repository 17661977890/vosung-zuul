package com.vosung.zuul.resourceserverconfig;

import com.vosung.authentication.authrizationserverconfig.CustomJwtAccessTokenConverter;
import com.vosung.zuul.properties.PermitAllUrlProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;

/**
 * 二、资源服务器配置
 * 用户请求资源，进行拦截->token校验->组装用户信息返回
 * 要访问资源服务器受保护的资源需要携带令牌（从授权服务器获得）
 * 资源服务器通过 @EnableResourceServer 注解来开启一个 OAuth2AuthenticationProcessingFilter 类型的过滤器
 */
@Slf4j
@Configuration
@EnableResourceServer
@Order(1)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private LoadBalancerClient loadBalancerClient;
    /**
     * OAuth2 为资源服务器配置提供了 ResourceServerProperties 类，
     * 该类会读取配置文件中对资源服务器得配置信息
     */
    @Autowired
    private ResourceServerProperties resource;

    @Autowired
    private PermitAllUrlProperties permitAllUrlProperties;

    /**
     * 通过配置指定什么请求不用登录即可访问,其余请求认证后才可以访问
     * 在网关配置文件配置（要加路由转发配置的前缀/authWebApp /ksfapp等）----设置以后，就不需要登录不需要携带Authorization请求头和token直接访问
     * @param http
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .requestMatchers().antMatchers("/**")
                .and()
                .authorizeRequests()
                .antMatchers(permitAllUrlProperties.getPermitallPatterns()).permitAll()
                .anyRequest().authenticated();
    }

    /**
     * 因为授权服务和资源服务分离，所以ResourceServerTokenServices必须知道令牌如何解码：
     * （1）使用RemoteTokenServices接口，资源服务器通过HTTP请求来解码令牌。
     *      每次都请求授权服务器的端点-/oauth/check_toke，以此来解码令牌，下面就是具体重写的逻辑。
     * 实现令牌token业务逻辑服务:
     * ResourceServerSecurityConfigurer 类中定义的ResourceServerTokenServices接口。
     * 自定义CustomRemoteTokenServices实现ResourceServerTokenServices------>定义了令牌加载、读取方法
     * @param resources
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        CustomRemoteTokenServices resourceServerTokenServices = new CustomRemoteTokenServices();
        resourceServerTokenServices.setCheckTokenEndpointUrl(resource.getTokenInfoUri());
        resourceServerTokenServices.setClientId(resource.getClientId());
        resourceServerTokenServices.setClientSecret(resource.getClientSecret());
        resourceServerTokenServices.setLoadBalancerClient(loadBalancerClient);
        resources.tokenServices(resourceServerTokenServices);
    }


    /**
     * 配置资源服务器使用公钥 解密
     * @return
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        CustomJwtAccessTokenConverter converter = new CustomJwtAccessTokenConverter();
        Resource resource = new ClassPathResource("public.cert");
        String publicKey;
        try {
            publicKey = new String(FileCopyUtils.copyToByteArray(resource.getInputStream()));
        } catch (IOException ex) {
            throw new RuntimeException();
        }
        converter.setVerifierKey(publicKey);
        log.info("================对token使用公钥进行解密=======================");
        return converter;
    }

}
