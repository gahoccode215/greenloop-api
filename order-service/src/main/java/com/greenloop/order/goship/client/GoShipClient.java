package com.greenloop.order.goship.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.greenloop.order.goship.dto.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;

@Component
@Slf4j
public class GoShipClient {

    private final RestTemplate restTemplate;

    @Value("${goship.base-url}")
    private String baseUrl;

    public GoShipClient(@Qualifier("goshipRestTemplate") RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public List<CityDTO> getCities() {
        String url = baseUrl + "/cities";

        try {
            log.info("Fetching cities from GoShip API: {}", url);

            ResponseEntity<GoShipResponse<List<CityDTO>>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<GoShipResponse<List<CityDTO>>>() {}
            );

            GoShipResponse<List<CityDTO>> body = response.getBody();

            if (body != null && body.getCode() == 200 && "success".equals(body.getStatus()) && body.getData() != null) {
                log.info("Successfully fetched {} cities", body.getData().size());
                return body.getData();
            }

            throw new RuntimeException("Failed to fetch cities from GoShip");

        } catch (Exception e) {
            log.error("Error fetching cities: {}", e.getMessage(), e);
            throw new RuntimeException("Error fetching cities: " + e.getMessage());
        }
    }

    /**
     * Lấy tất cả districts (auto loop qua tất cả pages)
     */
    public List<DistrictDTO> getDistricts(String cityId) {
        List<DistrictDTO> allDistricts = new ArrayList<>();
        int currentPage = 1;
        boolean hasMorePages = true;

        try {
            log.info("Fetching all districts for city {} with pagination", cityId);

            while (hasMorePages) {
                // Sử dụng parameter 'page' thay vì 'page'
                String url = baseUrl + "/cities/" + cityId + "/districts?page=" + currentPage;

                log.info("Fetching districts page {}", currentPage);

                ResponseEntity<GoShipResponse<List<DistrictDTO>>> response = restTemplate.exchange(
                        url,
                        HttpMethod.GET,
                        null,
                        new ParameterizedTypeReference<GoShipResponse<List<DistrictDTO>>>() {}
                );

                GoShipResponse<List<DistrictDTO>> body = response.getBody();

                if (body != null && body.getCode() == 200 && "success".equals(body.getStatus())) {
                    if (body.getData() != null && !body.getData().isEmpty()) {
                        allDistricts.addAll(body.getData());
                        log.info("Added {} districts from page {}", body.getData().size(), currentPage);
                    }

                    if (body.getMeta() != null && body.getMeta().getPagination() != null) {
                        PaginationMeta.Pagination pagination = body.getMeta().getPagination();
                        hasMorePages = pagination.getCurrentPage() < pagination.getTotalPages();
                        currentPage++;
                    } else {
                        hasMorePages = false;
                    }
                } else {
                    log.error("Failed to fetch districts at page {}", currentPage);
                    break;
                }
            }

            log.info("Successfully fetched total {} districts for city {}", allDistricts.size(), cityId);
            return allDistricts;

        } catch (Exception e) {
            log.error("Error fetching districts: {}", e.getMessage(), e);
            throw new RuntimeException("Error fetching districts: " + e.getMessage());
        }
    }

    /**
     * Lấy districts theo page cụ thể - Dùng parameter 'size' thay vì 'per_page'
     */
    public GoShipResponse<List<DistrictDTO>> getDistrictsByPage(String cityId, int page, int size) {
        try {
            // Sử dụng 'size' thay vì 'per_page'
            String url = baseUrl + "/cities/" + cityId + "/districts?page=" + page + "&size=" + size;

            log.info("Fetching districts page {} with size {} for city {}", page, size, cityId);

            ResponseEntity<GoShipResponse<List<DistrictDTO>>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<GoShipResponse<List<DistrictDTO>>>() {}
            );

            GoShipResponse<List<DistrictDTO>> body = response.getBody();

            // Tạo meta nếu null
            if (body != null && body.getMeta() == null && body.getData() != null) {
                PaginationMeta.Pagination pagination = new PaginationMeta.Pagination();
                pagination.setCurrentPage(page);
                pagination.setPerPage(size);
                pagination.setCount(body.getData().size());
                pagination.setTotal(body.getData().size());
                pagination.setTotalPages(1);

                PaginationMeta.Links links = new PaginationMeta.Links();
                links.setNext(null);
                links.setPrevious(null);

                pagination.setLinks(links);

                PaginationMeta meta = new PaginationMeta();
                meta.setPagination(pagination);

                body.setMeta(meta);
            }

            return body;

        } catch (Exception e) {
            log.error("Error fetching districts page: {}", e.getMessage());
            throw new RuntimeException("Error fetching districts page: " + e.getMessage());
        }
    }

    /**
     * Lấy tất cả wards (auto loop qua tất cả pages)
     */
    public List<WardDTO> getWards(String districtId) {
        List<WardDTO> allWards = new ArrayList<>();
        int currentPage = 1;
        boolean hasMorePages = true;

        try {
            log.info("Fetching all wards for district {} with pagination", districtId);

            while (hasMorePages) {
                String url = baseUrl + "/districts/" + districtId + "/wards?page=" + currentPage;

                log.info("Fetching wards page {}", currentPage);

                ResponseEntity<GoShipResponse<List<WardDTO>>> response = restTemplate.exchange(
                        url,
                        HttpMethod.GET,
                        null,
                        new ParameterizedTypeReference<GoShipResponse<List<WardDTO>>>() {}
                );

                GoShipResponse<List<WardDTO>> body = response.getBody();

                if (body != null && body.getCode() == 200 && "success".equals(body.getStatus())) {
                    if (body.getData() != null && !body.getData().isEmpty()) {
                        allWards.addAll(body.getData());
                        log.info("Added {} wards from page {}", body.getData().size(), currentPage);
                    }

                    if (body.getMeta() != null && body.getMeta().getPagination() != null) {
                        PaginationMeta.Pagination pagination = body.getMeta().getPagination();
                        hasMorePages = pagination.getCurrentPage() < pagination.getTotalPages();
                        currentPage++;
                    } else {
                        hasMorePages = false;
                    }
                } else {
                    log.error("Failed to fetch wards at page {}", currentPage);
                    break;
                }
            }

            log.info("Successfully fetched total {} wards for district {}", allWards.size(), districtId);
            return allWards;

        } catch (Exception e) {
            log.error("Error fetching wards: {}", e.getMessage(), e);
            throw new RuntimeException("Error fetching wards: " + e.getMessage());
        }
    }

    /**
     * Lấy wards theo page cụ thể - Dùng parameter 'size'
     */
    public GoShipResponse<List<WardDTO>> getWardsByPage(String districtId, int page, int size) {
        try {
            String url = baseUrl + "/districts/" + districtId + "/wards?page=" + page + "&size=" + size;

            log.info("Fetching wards page {} with size {} for district {}", page, size, districtId);

            ResponseEntity<GoShipResponse<List<WardDTO>>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<GoShipResponse<List<WardDTO>>>() {}
            );

            GoShipResponse<List<WardDTO>> body = response.getBody();

            if (body != null && body.getMeta() == null && body.getData() != null) {
                PaginationMeta.Pagination pagination = new PaginationMeta.Pagination();
                pagination.setCurrentPage(page);
                pagination.setPerPage(size);
                pagination.setCount(body.getData().size());
                pagination.setTotal(body.getData().size());
                pagination.setTotalPages(1);

                PaginationMeta.Links links = new PaginationMeta.Links();
                links.setNext(null);
                links.setPrevious(null);

                pagination.setLinks(links);

                PaginationMeta meta = new PaginationMeta();
                meta.setPagination(pagination);

                body.setMeta(meta);
            }

            return body;

        } catch (Exception e) {
            log.error("Error fetching wards page: {}", e.getMessage());
            throw new RuntimeException("Error fetching wards page: " + e.getMessage());
        }
    }

    public List<RateResponse> calculateRates(CalculateRateRequest request) {
        try {
            String url = baseUrl + "/rates";

            log.info("═══════════════════════════════════════════════════");
            log.info("🚀 GoShip Calculate Rates");
            log.info("═══════════════════════════════════════════════════");
            log.info("📍 URL: {}", url);

            // ✅ CRITICAL: Log actual JSON being sent
            try {
                ObjectMapper mapper = new ObjectMapper();
                mapper.enable(SerializationFeature.INDENT_OUTPUT);
                String requestJson = mapper.writeValueAsString(request);
                log.info("📤 REQUEST JSON:\n{}", requestJson);
            } catch (Exception e) {
                log.warn("Cannot serialize request: {}", e.getMessage());
            }

            HttpEntity<CalculateRateRequest> httpEntity = new HttpEntity<>(request);

            ResponseEntity<GoShipResponse<List<RateResponse>>> response = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    httpEntity,
                    new ParameterizedTypeReference<GoShipResponse<List<RateResponse>>>() {}
            );

            GoShipResponse<List<RateResponse>> body = response.getBody();

            // ✅ Log response
            try {
                ObjectMapper mapper = new ObjectMapper();
                mapper.enable(SerializationFeature.INDENT_OUTPUT);
                String responseJson = mapper.writeValueAsString(body);
                log.info("📥 RESPONSE JSON:\n{}", responseJson);
            } catch (Exception e) {
                log.warn("Cannot serialize response: {}", e.getMessage());
            }

            if (body != null && body.getCode() == 200 && "success".equals(body.getStatus())) {
                List<RateResponse> rates = body.getData();

                if (rates != null && !rates.isEmpty()) {
                    log.info("✅ SUCCESS: Found {} shipping options", rates.size());
                    rates.forEach(rate ->
                            log.info("   💵 {}: {} - {}đ",
                                    rate.getCarrierName(),
                                    rate.getService(),
                                    rate.getTotalFee())
                    );
                    log.info("═══════════════════════════════════════════════════");
                    return rates;
                } else {
                    log.warn("⚠️  WARNING: Empty data array");
                    log.warn("═══════════════════════════════════════════════════");
                    return List.of();
                }
            }

            log.error("❌ ERROR: Invalid response");
            log.error("═══════════════════════════════════════════════════");
            return List.of();

        } catch (Exception e) {
            log.error("❌ EXCEPTION: {}", e.getMessage(), e);
            throw new RuntimeException("Lỗi khi tính cước phí: " + e.getMessage());
        }
    }


    /**
     * Tạo shipment
     * POST /api/v2/shipments
     */
    public ShipmentResponse createShipment(CreateShipmentRequest request) {
        try {
            String url = baseUrl + "/shipments";

            log.info("Creating shipment: {}", url);

            HttpEntity<CreateShipmentRequest> httpEntity = new HttpEntity<>(request);

            ResponseEntity<GoShipResponse<ShipmentResponse>> response = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    httpEntity,
                    new ParameterizedTypeReference<GoShipResponse<ShipmentResponse>>() {}
            );

            GoShipResponse<ShipmentResponse> body = response.getBody();

            if (body != null && body.getCode() == 200 && "success".equals(body.getStatus())) {
                log.info("Successfully created shipment: {}", body.getData().getTrackingCode());
                return body.getData();
            }

            throw new RuntimeException("Failed to create shipment from GoShip");

        } catch (Exception e) {
            log.error("Error creating shipment: {}", e.getMessage(), e);
            throw new RuntimeException("Error creating shipment: " + e.getMessage());
        }
    }

    /**
     * Lấy thông tin shipment
     * GET /api/v2/shipments/{id}
     */
    public ShipmentResponse getShipment(String shipmentId) {
        try {
            String url = baseUrl + "/shipments/" + shipmentId;

            log.info("Getting shipment: {}", url);

            ResponseEntity<GoShipResponse<ShipmentResponse>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<GoShipResponse<ShipmentResponse>>() {}
            );

            GoShipResponse<ShipmentResponse> body = response.getBody();

            if (body != null && body.getCode() == 200 && "success".equals(body.getStatus())) {
                return body.getData();
            }

            throw new RuntimeException("Failed to get shipment from GoShip");

        } catch (Exception e) {
            log.error("Error getting shipment: {}", e.getMessage(), e);
            throw new RuntimeException("Error getting shipment: " + e.getMessage());
        }
    }

    /**
     * Hủy shipment
     * DELETE /api/v2/shipments/{id}
     */
    public void cancelShipment(String shipmentId) {
        try {
            String url = baseUrl + "/shipments/" + shipmentId;

            log.info("Cancelling shipment: {}", url);

            ResponseEntity<GoShipResponse<Void>> response = restTemplate.exchange(
                    url,
                    HttpMethod.DELETE,
                    null,
                    new ParameterizedTypeReference<GoShipResponse<Void>>() {}
            );

            GoShipResponse<Void> body = response.getBody();

            if (body == null || body.getCode() != 200) {
                throw new RuntimeException("Failed to cancel shipment from GoShip");
            }

            log.info("Successfully cancelled shipment: {}", shipmentId);

        } catch (Exception e) {
            log.error("Error cancelling shipment: {}", e.getMessage(), e);
            throw new RuntimeException("Error cancelling shipment: " + e.getMessage());
        }
    }
}
