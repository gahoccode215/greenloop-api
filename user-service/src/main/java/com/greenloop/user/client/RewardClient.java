package com.greenloop.user.client;

import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.EcoPointResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "reward-service")
public interface RewardClient {

  @GetMapping("/api/v1/internal/eco-point-users/my-eco-points")
  ApiResponseDTO<EcoPointResponse> getMyEcoPoints(@RequestParam("userId") Long userId);
}
