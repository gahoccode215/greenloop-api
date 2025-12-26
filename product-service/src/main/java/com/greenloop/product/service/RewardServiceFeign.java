package com.greenloop.product.service;


import com.greenloop.product.dto.event.EcoPointTransactionDTO;
import com.greenloop.product.dto.request.EcoPointInfoRequest;
import com.greenloop.product.dto.response.EcoPointResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "reward-service")
public interface RewardServiceFeign {
    @PostMapping(value = "/api/v1/eco-points/internal", headers = "API_SECRET_HEADER=greenloopsecret")
    EcoPointResponse getEcoPoint(@RequestBody EcoPointInfoRequest request);

    @PostMapping(value = "/api/v1/eco-point-users/internal/update-eco-point-user", headers = "API_SECRET_HEADER=greenloopsecret")
    Boolean updateEcoPoints(@RequestBody EcoPointTransactionDTO request);
}
