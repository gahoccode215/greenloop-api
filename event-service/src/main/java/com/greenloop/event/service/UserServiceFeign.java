package com.greenloop.event.service;

import com.greenloop.event.dto.response.UserProfileResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;

@FeignClient(name = "user-service")
public interface UserServiceFeign {
  @GetMapping(value = "/api/v1/users/{id}/info", headers = "API_SECRET_HEADER=greenloopsecret")
  UserProfileResponse getUserInfoById(@PathVariable("id") Long id);

  @GetMapping(value = "/api/v1/internal/users/all-ids", headers = "API_SECRET_HEADER=greenloopsecret")
  List<Long> getAllUserIds();
}
