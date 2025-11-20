package com.greenloop.order.ghn.client;

import com.greenloop.order.ghn.config.GHNProperties;
import com.greenloop.order.ghn.dto.*;
import com.greenloop.order.ghn.exception.GHNException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class GHNClient {

    private final RestTemplate ghnRestTemplate;
    private final GHNProperties ghnProperties;

    private static final String PROVINCE_ENDPOINT = "/shiip/public-api/master-data/province";
    private static final String DISTRICT_ENDPOINT = "/shiip/public-api/master-data/district";
    private static final String WARD_ENDPOINT = "/shiip/public-api/master-data/ward";

    public List<GHNProvinceDTO> getProvinces() {
        String url = ghnProperties.getBaseUrl() + PROVINCE_ENDPOINT;
        log.info("Calling GHN API: GET {}", url);

        try {
            ResponseEntity<GHNResponse<List<GHNProvinceDTO>>> response = ghnRestTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<GHNResponse<List<GHNProvinceDTO>>>() {}
            );

            return handleResponse(response, "provinces");

        } catch (Exception e) {
            log.error("Error calling GHN API: {}", e.getMessage(), e);
            throw new GHNException("Failed to get provinces from GHN");
        }
    }

    public List<GHNDistrictDTO> getDistricts(Integer provinceId) {
        String url = ghnProperties.getBaseUrl() + DISTRICT_ENDPOINT;
        log.info("Calling GHN API: POST {} with provinceId: {}", url, provinceId);

        try {
            GHNDistrictRequest request = new GHNDistrictRequest(provinceId);
            HttpEntity<GHNDistrictRequest> httpEntity = new HttpEntity<>(request);

            ResponseEntity<GHNResponse<List<GHNDistrictDTO>>> response = ghnRestTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    httpEntity,
                    new ParameterizedTypeReference<GHNResponse<List<GHNDistrictDTO>>>() {}
            );

            return handleResponse(response, "districts");

        } catch (Exception e) {
            log.error("Error calling GHN API: {}", e.getMessage(), e);
            throw new GHNException("Failed to get districts from GHN");
        }
    }

    public List<GHNWardDTO> getWards(Integer districtId) {
        String url = ghnProperties.getBaseUrl() + WARD_ENDPOINT;
        log.info("Calling GHN API: POST {} with districtId: {}", url, districtId);

        try {
            GHNWardRequest request = new GHNWardRequest(districtId);
            HttpEntity<GHNWardRequest> httpEntity = new HttpEntity<>(request);

            ResponseEntity<GHNResponse<List<GHNWardDTO>>> response = ghnRestTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    httpEntity,
                    new ParameterizedTypeReference<GHNResponse<List<GHNWardDTO>>>() {}
            );

            return handleResponse(response, "wards");

        } catch (Exception e) {
            log.error("Error calling GHN API: {}", e.getMessage(), e);
            throw new GHNException("Failed to get wards from GHN");
        }
    }

    private <T> List<T> handleResponse(ResponseEntity<GHNResponse<List<T>>> response, String resourceName) {
        GHNResponse<List<T>> body = response.getBody();

        if (body == null) {
            throw new GHNException("Response body is null");
        }

        if (body.isError()) {
            throw new GHNException(body.getCode(), body.getMessage());
        }

        log.info("Successfully retrieved {} {} from GHN", body.getData().size(), resourceName);
        return body.getData();
    }
}
