package com.greenloop.order.client;

import com.greenloop.order.dto.request.VoucherUsedRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.UserVoucherResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "reward-service", path = "/api/v1/internal/vouchers")
public interface VoucherClient {

    @PostMapping("/validate/{voucherUserId}")
    ApiResponseDTO<UserVoucherResponse> validateVoucherForUser(
            @PathVariable("voucherUserId") Long voucherUserId);

    @PostMapping("/mark-used")
    ApiResponseDTO<Void> markVoucherAsUsed(@RequestBody VoucherUsedRequest request);
}
