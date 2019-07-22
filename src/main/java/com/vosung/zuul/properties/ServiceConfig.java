package com.vosung.zuul.properties;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 配置文件配置,并实体化,用PermitAllUrlProperties类表示
 */
@Configuration
public class ServiceConfig {


    @Value("${server.port}")
    private int securePort;


    @Bean
    @ConfigurationProperties(prefix = "auth")
    public PermitAllUrlProperties getPermitAllUrlProperties() {
        return new PermitAllUrlProperties();
    }

}
