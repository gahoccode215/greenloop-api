package com.greenloop.order.ghn.controller;

import com.greenloop.order.dto.ApiResponseDTO;
import com.greenloop.order.ghn.dto.request.CreateShippingRequest;
import com.greenloop.order.ghn.dto.response.*;
import com.greenloop.order.ghn.service.GHNService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@Slf4j
@RequestMapping("/api/v1/orders/ghn")
@Tag(name = "GHN")
@RequiredArgsConstructor
public class GHNController {

    private final GHNService ghnService;

    @GetMapping("/master-data/provinces")
    @Operation(summary = "Lấy danh sách Tỉnh/Thành")
    public ResponseEntity<ApiResponseDTO<List<ProvinceResponse>>> getProvinces() {

        List<ProvinceResponse> provinces = ghnService.getProvinces();

        return ResponseEntity.ok(ApiResponseDTO.success(
                "Lấy danh sách tỉnh/thành thành công",
                provinces,
                HttpStatus.OK
        ));
    }

    @GetMapping("/master-data/districts")
    @Operation(summary = "Lấy danh sách Quận/Huyện theo Tỉnh/Thành")
    public ResponseEntity<ApiResponseDTO<List<DistrictResponse>>> getDistricts(
            @RequestParam Integer provinceId) {

        List<DistrictResponse> districts = ghnService.getDistricts(provinceId);

        return ResponseEntity.ok(ApiResponseDTO.success(
                "Lấy danh sách quận/huyện thành công",
                districts,
                HttpStatus.OK
        ));
    }

    @GetMapping("/master-data/wards")
    @Operation(summary = "Lấy danh sách Phường/Xã theo Quận/Huyện")
    public ResponseEntity<ApiResponseDTO<List<WardResponse>>> getWards(
            @RequestParam Integer districtId) {
        List<WardResponse> wards = ghnService.getWards(districtId);
        return ResponseEntity.ok(ApiResponseDTO.success(
                "Lấy danh sách phường/xã thành công",
                wards,
                HttpStatus.OK
        ));
    }

    @DeleteMapping("/{orderId}/shipping")
    @Operation(summary = "Hủy vận đơn GHN")
    public ResponseEntity<ApiResponseDTO<CancelOrderResponse>> cancelShipping(
            @PathVariable String orderId) {

        CancelOrderResponse response = ghnService.cancelOrder(orderId);

        return ResponseEntity.ok(ApiResponseDTO.success(
                "Hủy vận đơn thành công",
                response,
                HttpStatus.OK
        ));
    }

    @PostMapping("/{orderId}/shipping")
    public ResponseEntity<ApiResponseDTO<ShippingOrderResponse>> createShipping(
            @PathVariable String orderId,
            @Valid @RequestBody CreateShippingRequest createShippingRequest) {

        ShippingOrderResponse response = ghnService.createShippingOrder(
                orderId,
                createShippingRequest
        );

        return ResponseEntity.ok(ApiResponseDTO.success(
                "Tạo vận đơn thành công",
                response,
                HttpStatus.OK
        ));
    }



}
