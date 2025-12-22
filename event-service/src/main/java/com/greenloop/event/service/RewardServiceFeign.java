package com.greenloop.event.service;

import com.greenloop.event.dto.response.EcoPointTransactionDTO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "reward-service")
public interface RewardServiceFeign {

  @PostMapping(
      value = "/api/v1/eco-point-users/internal/update-eco-point-user",
      headers = "API_SECRET_HEADER=greenloopsecret")
  Boolean updateEcoPoints(@RequestBody EcoPointTransactionDTO request);
}
