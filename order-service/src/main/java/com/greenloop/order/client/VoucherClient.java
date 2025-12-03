package com.greenloop.order.client;

import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.UserVoucherResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

@FeignClient(name = "reward-service", path = "/api/v1/internal")
public interface VoucherClient {

    @PostMapping("/vouchers/validate/{voucherUserId}")
    ApiResponseDTO<UserVoucherResponse> validateVoucherForUser(
            @PathVariable("voucherUserId") Long voucherUserId);
}
