package com.vosung.zuul;

import com.vosung.zuul.apifilter.AccessFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;

/**
 * zuul 集成了ribbon和hystrix（拥有线程隔离和断路器的自我保护功能，以及对服务调用的客户端负载均衡功能）
 * @SpringCloudApplication 包含了 @SpringBootApplication @EnableDiscoveryClient等注解（可替换）
 * path/url 路由格式没有线程隔离和断路器保护，也没有负载均衡的能力
 */
@EnableZuulProxy
@EnableDiscoveryClient
@SpringBootApplication
public class ApiGateWayZuulApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApiGateWayZuulApplication.class, args);
	}

	/**
	 * 使过滤器生效
	 * @return
	 */
	@Bean
	public AccessFilter accessFilter(){
		return new AccessFilter();
	}


}
