package com.greenloop.order.client;

import com.greenloop.order.dto.request.AddEcoPointsRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "reward-service", path = "/api/v1/internal/rewards")
public interface RewardClient {

    @PostMapping("/eco-points/add")
    ApiResponseDTO<Void> addEcoPoints(@RequestBody AddEcoPointsRequest request);
}
