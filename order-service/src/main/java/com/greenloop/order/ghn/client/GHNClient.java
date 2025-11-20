package com.greenloop.order.ghn.client;

import com.greenloop.order.ghn.config.GHNProperties;
import com.greenloop.order.ghn.dto.GHNProvinceDTO;
import com.greenloop.order.ghn.dto.GHNResponse;
import com.greenloop.order.ghn.exception.GHNException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
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

            GHNResponse<List<GHNProvinceDTO>> body = response.getBody();

            if (body == null) {
                throw new GHNException("Response body is null");
            }

            if (body.isError()) {
                throw new GHNException(body.getCode(), body.getMessage());
            }

            log.info("Successfully retrieved {} provinces from GHN", body.getData().size());
            return body.getData();

        } catch (Exception e) {
            log.error("Error calling GHN API: {}", e.getMessage(), e);
            throw new GHNException("Failed to get provinces from GHN");
        }
    }
}
