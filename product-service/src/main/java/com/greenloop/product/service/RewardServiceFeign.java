package com.greenloop.product.service;


import com.greenloop.product.dto.request.EcoPointInfoRequest;
import com.greenloop.product.dto.response.EcoPointResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-service")
public interface RewardServiceFeign {
    @GetMapping(value = "/api/v1/eco-points/internal", headers = "API_SECRET_HEADER=greenloopsecret")
    EcoPointResponse getEcoPoint(@RequestBody EcoPointInfoRequest request);
}
