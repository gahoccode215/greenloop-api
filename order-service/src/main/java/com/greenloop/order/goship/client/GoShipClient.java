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


            HttpEntity<CalculateRateRequest> httpEntity = new HttpEntity<>(request);

            ResponseEntity<GoShipResponse<List<RateResponse>>> response = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    httpEntity,
                    new ParameterizedTypeReference<GoShipResponse<List<RateResponse>>>() {}
            );

            GoShipResponse<List<RateResponse>> body = response.getBody();


            if (body != null && body.getCode() == 200 && "success".equals(body.getStatus())) {
                List<RateResponse> rates = body.getData();

                if (rates != null && !rates.isEmpty()) {

                    return rates;
                } else {

                    return List.of();
                }
            }

            return List.of();

        } catch (Exception e) {
            throw new RuntimeException("Lỗi khi tính cước phí: " + e.getMessage());
        }
    }


    /**
     * Tạo vận đơn mới
     */
    public CreateShipmentResponse createShipment(CreateShipmentRequest request) {
        String url = baseUrl + "/shipments";

        try {
            log.info("Creating shipment for order: {}", request.getShipment().getOrderId());

            HttpEntity<CreateShipmentRequest> entity = new HttpEntity<>(request);

            ResponseEntity<CreateShipmentResponse> response = restTemplate.postForEntity(
                    url, entity, CreateShipmentResponse.class);

            CreateShipmentResponse body = response.getBody();

            if (body != null && body.getCode() == 200 && "success".equals(body.getStatus())) {
                log.info("Shipment created successfully - ID: {}, Tracking: {}",
                        body.getId(), body.getTrackingNumber());
                return body;
            }

            throw new RuntimeException("Failed to create shipment: " +
                    (body != null ? body.getMessage() : "Unknown error"));

        } catch (Exception e) {
            log.error("Error creating shipment: {}", e.getMessage(), e);
            throw new RuntimeException("Không thể tạo vận đơn: " + e.getMessage());
        }
    }

    /**
     * Hủy vận đơn
     */
    public void cancelShipment(String shipmentId) {
        String url = baseUrl + "/shipments/" + shipmentId;

        try {
            log.info("Cancelling shipment: {}", shipmentId);

            restTemplate.exchange(url, HttpMethod.DELETE, null, Void.class);

            log.info("Shipment cancelled successfully: {}", shipmentId);

        } catch (Exception e) {
            log.error("Error cancelling shipment {}: {}", shipmentId, e.getMessage(), e);
            throw new RuntimeException("Không thể hủy vận đơn: " + e.getMessage());
        }
    }

}
