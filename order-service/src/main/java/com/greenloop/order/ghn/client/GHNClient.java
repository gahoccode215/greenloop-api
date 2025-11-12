package com.greenloop.order.ghn.client;

import com.greenloop.order.ghn.config.GHNConfig;

import com.greenloop.order.ghn.dto.request.CreateShippingOrderRequest;
import com.greenloop.order.ghn.dto.response.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.List;
import java.util.Map;

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

    /**
     * Lấy danh sách Quận/Huyện theo Province ID
     */
    public List<DistrictResponse> getDistricts(Integer provinceId) {
        String url = ghnConfig.getApi().getBaseUrl() + "/master-data/district";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Token", ghnConfig.getApi().getToken());

        // Request body chứa province_id
        Map<String, Object> body = Map.of("province_id", provinceId);
        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);

        log.debug("Getting districts for province: {}", provinceId);

        try {
            ResponseEntity<GHNResponse<List<DistrictResponse>>> response = ghnRestTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    entity,
                    new ParameterizedTypeReference<GHNResponse<List<DistrictResponse>>>() {}
            );

            if (response.getBody() != null && response.getBody().isSuccess()) {
                return response.getBody().getData();
            } else {
                log.warn("GHN get districts failed: {}", response.getBody().getMessage());
                return List.of();
            }

        } catch (Exception e) {
            log.error("Failed to get districts from GHN", e);
            return List.of();
        }
    }

    public List<WardResponse> getWards(Integer districtId) {
        String url = ghnConfig.getApi().getBaseUrl() + "/master-data/ward";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Token", ghnConfig.getApi().getToken());

        // Request body chứa district_id
        Map<String, Object> body = Map.of("district_id", districtId);
        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);

        log.debug("Getting wards for district: {}", districtId);

        try {
            ResponseEntity<GHNResponse<List<WardResponse>>> response = ghnRestTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    entity,
                    new ParameterizedTypeReference<GHNResponse<List<WardResponse>>>() {}
            );

            if (response.getBody() != null && response.getBody().isSuccess()) {
                return response.getBody().getData();
            } else {
                log.warn("GHN get wards failed: {}", response.getBody().getMessage());
                return List.of();
            }

        } catch (Exception e) {
            log.error("Failed to get wards from GHN", e);
            return List.of();
        }
    }

    public List<ProvinceResponse> getProvinces() {
        String url = ghnConfig.getApi().getBaseUrl() + "/master-data/province";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Token", ghnConfig.getApi().getToken());

        HttpEntity<Void> entity = new HttpEntity<>(headers);

        log.debug("Getting provinces from GHN");

        try {
            ResponseEntity<GHNResponse<List<ProvinceResponse>>> response = ghnRestTemplate.exchange(
                    url,
                    HttpMethod.GET,  // ← GHN dùng GET method
                    entity,
                    new ParameterizedTypeReference<GHNResponse<List<ProvinceResponse>>>() {}
            );

            if (response.getBody() != null && response.getBody().isSuccess()) {
                log.info("Successfully fetched {} provinces", response.getBody().getData().size());
                return response.getBody().getData();
            } else {
                log.warn("GHN get provinces failed: {}", response.getBody().getMessage());
                return List.of();
            }

        } catch (Exception e) {
            log.error("Failed to get provinces from GHN", e);
            return List.of();
        }
    }

    public List<CancelOrderResponse> cancelOrders(List<String> orderCodes) {
        String url = ghnConfig.getApi().getBaseUrl() + "/v2/switch-status/cancel";

        HttpHeaders headers = buildHeaders();

        // Request body chứa danh sách order_codes
        Map<String, Object> body = Map.of("order_codes", orderCodes);
        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);

        log.info("Cancelling GHN orders: {}", orderCodes);

        try {
            ResponseEntity<GHNResponse<List<CancelOrderResponse>>> response = ghnRestTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    entity,
                    new ParameterizedTypeReference<GHNResponse<List<CancelOrderResponse>>>() {}
            );

            if (response.getBody() != null && response.getBody().isSuccess()) {
                log.info("Successfully cancelled {} orders", orderCodes.size());
                return response.getBody().getData();
            } else {
                log.warn("GHN cancel order failed: {}", response.getBody().getMessage());
                throw new RuntimeException("GHN cancel failed: " + response.getBody().getMessage());
            }

        } catch (Exception e) {
            log.error("Failed to cancel GHN orders", e);
            throw new RuntimeException("Failed to cancel GHN orders: " + e.getMessage());
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
