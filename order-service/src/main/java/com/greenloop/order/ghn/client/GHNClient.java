package com.greenloop.order.ghn.client;

import com.greenloop.order.ghn.config.GHNConfig;
import com.greenloop.order.ghn.dto.CreateShippingOrderRequest;
import com.greenloop.order.ghn.dto.ShippingOrderResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import com.greenloop.order.ghn.dto.GHNResponse;

@Component
@RequiredArgsConstructor
@Slf4j
public class GHNClient {

    private final RestTemplate ghnRestTemplate;
    private final GHNConfig ghnConfig;

    /**
     * Tạo đơn vận chuyển
     * Docs: https://api.ghn.vn/home/docs/detail?id=60
     */
    public GHNResponse<ShippingOrderResponse> createShippingOrder(CreateShippingOrderRequest request) {
        String url = ghnConfig.getBaseUrl() + "/v2/shipping-order/create";

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

    private HttpHeaders buildHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Token", ghnConfig.getToken());
        headers.set("ShopId", ghnConfig.getShopId().toString());
        return headers;
    }
}
