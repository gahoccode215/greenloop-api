package com.greenloop.order.goship.client;

import com.greenloop.order.goship.dto.CityDTO;
import com.greenloop.order.goship.dto.DistrictDTO;
import com.greenloop.order.goship.dto.GoShipResponse;
import com.greenloop.order.goship.dto.WardDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class GoShipClient {

    @Qualifier("goshipRestTemplate")
    private final RestTemplate restTemplate;

    @Value("${goship.base-url}")
    private String baseUrl;

    /**
     * Lấy danh sách tỉnh/thành phố
     * GET /api/v2/cities
     */
    public List<CityDTO> getCities() {
        try {
            String url = baseUrl + "/cities";

            log.info("Fetching cities from GoShip API: {}", url);

            ResponseEntity<GoShipResponse<List<CityDTO>>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<GoShipResponse<List<CityDTO>>>() {}
            );

            GoShipResponse<List<CityDTO>> body = response.getBody();

            if (body != null && "Success".equals(body.getCode())) {
                log.info("Successfully fetched {} cities", body.getData().size());
                return body.getData();
            } else {
                log.error("Failed to fetch cities: {}", body != null ? body.getMessage() : "No response");
                throw new RuntimeException("Failed to fetch cities from GoShip");
            }

        } catch (Exception e) {
            log.error("Error fetching cities from GoShip: {}", e.getMessage(), e);
            throw new RuntimeException("Error fetching cities: " + e.getMessage());
        }
    }

    /**
     * Lấy danh sách quận/huyện theo cityId
     * GET /api/v2/cities/{cityId}/districts
     */
    public List<DistrictDTO> getDistricts(String cityId) {
        try {
            String url = baseUrl + "/cities/" + cityId + "/districts";

            log.info("Fetching districts for city {} from GoShip API", cityId);

            ResponseEntity<GoShipResponse<List<DistrictDTO>>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<GoShipResponse<List<DistrictDTO>>>() {}
            );

            GoShipResponse<List<DistrictDTO>> body = response.getBody();

            if (body != null && "Success".equals(body.getCode())) {
                log.info("Successfully fetched {} districts for city {}", body.getData().size(), cityId);
                return body.getData();
            } else {
                log.error("Failed to fetch districts: {}", body != null ? body.getMessage() : "No response");
                throw new RuntimeException("Failed to fetch districts from GoShip");
            }

        } catch (Exception e) {
            log.error("Error fetching districts from GoShip: {}", e.getMessage(), e);
            throw new RuntimeException("Error fetching districts: " + e.getMessage());
        }
    }

    /**
     * Lấy danh sách phường/xã theo districtId
     * GET /api/v2/districts/{districtId}/wards
     */
    public List<WardDTO> getWards(String districtId) {
        try {
            String url = baseUrl + "/districts/" + districtId + "/wards";

            log.info("Fetching wards for district {} from GoShip API", districtId);

            ResponseEntity<GoShipResponse<List<WardDTO>>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<GoShipResponse<List<WardDTO>>>() {}
            );

            GoShipResponse<List<WardDTO>> body = response.getBody();

            if (body != null && "Success".equals(body.getCode())) {
                log.info("Successfully fetched {} wards for district {}", body.getData().size(), districtId);
                return body.getData();
            } else {
                log.error("Failed to fetch wards: {}", body != null ? body.getMessage() : "No response");
                throw new RuntimeException("Failed to fetch wards from GoShip");
            }

        } catch (Exception e) {
            log.error("Error fetching wards from GoShip: {}", e.getMessage(), e);
            throw new RuntimeException("Error fetching wards: " + e.getMessage());
        }
    }
}
