package com.vosung.zuul.resourceserverconfig;



import com.vosung.zuul.constants.SecurityConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.Map;

/**
 * token检查：
 * ResourceServerTokenServices：用来实现令牌业务逻辑服务
 * 原理分析：当用户携带token 请求资源服务器的资源时, OAuth2AuthenticationProcessingFilter 拦截token，
 *          进行token 和userdetails 过程，把无状态的token 转化成用户信息
 */
public class CustomRemoteTokenServices implements ResourceServerTokenServices {

    //负载均衡的客户端
    private LoadBalancerClient loadBalancerClient;

    protected final Log logger = LogFactory.getLog(getClass());

    private RestOperations restTemplate;

    private String checkTokenEndpointUrl;

    private String clientId;

    private String clientSecret;

    private String tokenName = "token";

    private AccessTokenConverter tokenConverter = new DefaultAccessTokenConverter();
    /**
     * 实现对请求出现的异常进行判别处理，RestTemplate实例可以通过调用setErrorHandler方法设置ErrorHandler
     */
    public CustomRemoteTokenServices() {
        restTemplate = new RestTemplate();
        ((RestTemplate) restTemplate).setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            // Ignore 400
            public void handleError(ClientHttpResponse response) throws IOException {
                if (response.getRawStatusCode() != 400) {
                    super.handleError(response);
                }
            }
        });
    }

    public void setRestTemplate(RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void setCheckTokenEndpointUrl(String checkTokenEndpointUrl) {
        this.checkTokenEndpointUrl = checkTokenEndpointUrl;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public void setAccessTokenConverter(AccessTokenConverter accessTokenConverter) {
        this.tokenConverter = accessTokenConverter;
    }

    public void setTokenName(String tokenName) {
        this.tokenName = tokenName;
    }

    //set方式注入负载均衡客户端LoadBalancerClient
    public void setLoadBalancerClient(LoadBalancerClient loadBalancerClient) {
        this.loadBalancerClient = loadBalancerClient;
    }


    /**
     * /oauth/check_token 端点里边会调用ResourceServerTokenServices里的此方法 这里重写
     * （1）查询token的合法性---逻辑是我们在CustomRedisTokenStore中的重写的readAccessToken
     *      查redis
     * @param accessToken
     * @return
     */
    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
        throw new UnsupportedOperationException("Not supported: read access token");
    }
    /**
     * （2）跳转check_token 解码令牌：
     *  通过loadAuthentication将token转化成OAuth2Authentication，返回部分用户信息.流程：
     *      ->先去跳转到check_token端点，来检查token的合法性（即从redis查有无，以及过期与否）
     *      ->从http头中取出token值->封装成accessToken对象->解密为map对象
     *      ->通过DefaultAcccessTokenConverter进行解析map，转换成OAuth2Authentication对象
     * @param accessToken
     * @return
     * @throws AuthenticationException
     * @throws InvalidTokenException
     */
    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>(1);
        formData.add(tokenName, accessToken);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", getAuthorizationHeader(clientId, clientSecret));

        //选择服务实例，根据传入的服务名serviceId，从负载均衡器中挑选一个对应服务的实例。(选择认证授权服务)
        ServiceInstance serviceInstance = loadBalancerClient.choose(SecurityConstants.AUTH_SERVICE);
        if (serviceInstance == null) {
            throw new RuntimeException("Failed to choose an auth instance.");
        }
        //serviceInstance：认证授权权服务实例的基本信息存储在ServiceInstance中，拼接并跳转到check_token端点
        Map<String, Object> map = postForMap(serviceInstance.getUri().toString() + checkTokenEndpointUrl, formData, headers);

        if (map.containsKey("error")) {
            logger.debug("check_token returned error: " + map.get("error"));
            throw new InvalidTokenException(accessToken);
        }

        Assert.state(map.containsKey("client_id"), "Client id must be present in response from auth server");
        //解析组装服务端返回的信息（user用户信息）
        // 主要实现：（DefaultAccessTokenConverter里面userTokenConverter.extractAuthentication(map);很重要）
        return tokenConverter.extractAuthentication(map);
    }


    private String getAuthorizationHeader(String clientId, String clientSecret) {
        String creds = String.format("%s:%s", clientId, clientSecret);
        try {
            return new StringBuilder("Basic ").append(Base64.getEncoder().encodeToString(creds.getBytes("utf-8"))).toString();
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Could not convert String");
        }
    }

    //到达check_token端点
    private Map<String, Object> postForMap(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }
        @SuppressWarnings("rawtypes")
        Map map = restTemplate.exchange(path, HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData, headers), Map.class).getBody();
        @SuppressWarnings("unchecked")
        Map<String, Object> result = map;
        return result;
    }

}
