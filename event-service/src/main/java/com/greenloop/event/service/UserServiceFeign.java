package com.greenloop.event.service;

import com.greenloop.event.dto.response.UserInfoResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name = "user-service")
public interface UserServiceFeign {
  @GetMapping(value = "/api/users/{id}/info", headers = "API_SECRET_HEADER=greenloopsecret")
  UserInfoResponse getUserInfoById(Long id);
}
