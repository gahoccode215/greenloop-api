package com.greenloop.order.client;

import com.greenloop.order.dto.request.AddEcoPointsRequest;
import com.greenloop.order.dto.request.VoucherUsedRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.UserVoucherResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "reward-service", path = "/api/v1")
public interface RewardClient {

    @PostMapping("/internal/vouchers/validate/{voucherUserId}")
    ApiResponseDTO<UserVoucherResponse> validateVoucherForUser(
            @PathVariable("voucherUserId") Long voucherUserId);

    @PostMapping("/internal/vouchers/mark-used")
    ApiResponseDTO<Void> markVoucherAsUsed(@RequestBody VoucherUsedRequest request);

    @PostMapping("/internal/rewards/eco-points/add")
    ApiResponseDTO<Void> addEcoPoints(@RequestBody AddEcoPointsRequest request);
}
