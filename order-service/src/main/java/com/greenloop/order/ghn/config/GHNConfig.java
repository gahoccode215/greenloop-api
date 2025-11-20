package com.greenloop.order.ghn.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class GHNConfig {

    private final GHNProperties ghnProperties;

    @Bean(name = "ghnRestTemplate")
    public RestTemplate ghnRestTemplate() {
        RestTemplate restTemplate = new RestTemplate();

        List<ClientHttpRequestInterceptor> interceptors = new ArrayList<>();
        interceptors.add(new GHNHeaderInterceptor());
        restTemplate.setInterceptors(interceptors);

        return restTemplate;
    }

    private class GHNHeaderInterceptor implements ClientHttpRequestInterceptor {

        @Override
        public ClientHttpResponse intercept(
                HttpRequest request,
                byte[] body,
                ClientHttpRequestExecution execution) throws IOException {

            HttpHeaders headers = request.getHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("Token", ghnProperties.getTokenApi());

            return execution.execute(request, body);
        }
    }
}
