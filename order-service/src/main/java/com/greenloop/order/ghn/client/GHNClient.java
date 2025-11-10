package com.greenloop.order.ghn.client;

import com.greenloop.order.ghn.config.GHNConfig;

import com.greenloop.order.ghn.dto.request.CreateShippingOrderRequest;
import com.greenloop.order.ghn.dto.response.GHNTrackingResponse;
import com.greenloop.order.ghn.dto.response.ShippingOrderResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import com.greenloop.order.ghn.dto.response.GHNResponse;

import java.time.Duration;

@Component
@Slf4j
//@RequiredArgsConstructor
public class GHNClient {

    private final RestTemplate ghnRestTemplate;
    private final GHNConfig ghnConfig;

    public GHNClient(RestTemplateBuilder builder, GHNConfig ghnConfig) {
        this.ghnConfig = ghnConfig;
        this.ghnRestTemplate = builder
                .build();
    }

    /**
     * Tạo đơn vận chuyển
     */
    public GHNResponse<ShippingOrderResponse> createShippingOrder(CreateShippingOrderRequest request) {
        String url = ghnConfig.getApi().getBaseUrl() + "/v2/shipping-order/create";

        HttpHeaders headers = buildHeaders();
        HttpEntity<CreateShippingOrderRequest> entity = new HttpEntity<>(request, headers);

        log.info("Creating GHN shipping order: {}", request);

        try {
            ResponseEntity<GHNResponse<ShippingOrderResponse>> response = ghnRestTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    entity,
                    new ParameterizedTypeReference<GHNResponse<ShippingOrderResponse>>() {}
            );

            log.info("GHN response: {}", response.getBody());
            return response.getBody();

        } catch (Exception e) {
            log.error("Failed to create GHN shipping order", e);
            throw new RuntimeException("GHN API call failed: " + e.getMessage());
        }
    }

    /**
     * Tracking đơn hàng GHN
     */
    public GHNTrackingResponse trackOrder(String orderCode) {
        String url = ghnConfig.getApi().getBaseUrl() + "/v2/shipping-order/detail";

        HttpHeaders headers = buildHeaders();

        String body = "{\"order_code\":\"" + orderCode + "\"}";
        HttpEntity<String> entity = new HttpEntity<>(body, headers);

        log.debug("Tracking GHN order: {}", orderCode);

        try {
            ResponseEntity<GHNResponse<GHNTrackingResponse>> response = ghnRestTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    entity,
                    new ParameterizedTypeReference<GHNResponse<GHNTrackingResponse>>() {}
            );

            if (response.getBody() != null && response.getBody().isSuccess()) {
                return response.getBody().getData();
            } else {
                log.warn("GHN tracking failed for order {}: {}",
                        orderCode, response.getBody().getMessage());
                return null;
            }

        } catch (Exception e) {
            log.error("Failed to track GHN order: {}", orderCode, e);
            return null;
        }
    }

    private HttpHeaders buildHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Token", ghnConfig.getApi().getToken());
        headers.set("ShopId", ghnConfig.getApi().getShopId().toString());
        return headers;
    }
}
