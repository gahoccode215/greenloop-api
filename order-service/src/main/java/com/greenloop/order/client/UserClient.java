package com.greenloop.order.client;

import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.UserProfileResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "user-service", path = "/api/v1/internal/users")
public interface UserClient {

    @GetMapping("/detail/{id}")
    ApiResponseDTO<UserProfileResponse> getUserDetailById(
            @PathVariable("id") Long id);
}
