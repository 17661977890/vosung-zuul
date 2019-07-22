package com.vosung.zuul.commonconfig;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.cloud.netflix.zuul.filters.route.FallbackProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * 网关回退提醒
 * @author 彬
 * @Date 2019-06-03
 */
@Component
public class FallBack implements FallbackProvider  {

    @Override
    public String getRoute() {
        // 表明是为所有微服务提供回退，如果想指定某一个，写服务名
        return "*";
    }

	@Override
	public ClientHttpResponse fallbackResponse(String route, Throwable throwable) {
		return new ClientHttpResponse() {
			@Override
			public HttpStatus getStatusCode() throws IOException {
				return HttpStatus.OK;
			}

			@Override
			public int getRawStatusCode() throws IOException {
				return 200;
			}

			@Override
			public String getStatusText() throws IOException {
				return "OK";
			}

			@Override
			public void close() {

			}

			@Override
			public InputStream getBody() throws IOException {
				return new ByteArrayInputStream("服务不可用，请检查是否开启服务".getBytes());
			}

			@Override
			public HttpHeaders getHeaders() {
				HttpHeaders headers = new HttpHeaders();
				headers.setContentType(MediaType.APPLICATION_JSON);
				return headers;
			}
		};
	}
}