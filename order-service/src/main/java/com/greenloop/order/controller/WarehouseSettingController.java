package com.greenloop.order.controller;

import com.greenloop.order.dto.request.WarehouseSettingRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.WarehouseSettingResponse;
import com.greenloop.order.entity.WarehouseSetting;
import com.greenloop.order.service.WarehouseSettingService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/warehouse-setting")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Warehouse Setting", description = "Warehouse Management APIs for Admin")
public class WarehouseSettingController {

    private final WarehouseSettingService warehouseSettingService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'STAFF','MANAGER')")
    public ResponseEntity<ApiResponseDTO<WarehouseSettingResponse>> getWarehouse() {
        WarehouseSettingResponse warehouse = warehouseSettingService.getWarehouseResponse();
        return ResponseEntity.ok(ApiResponseDTO.success(
                "Lấy thông tin kho thành công",
                warehouse,
                HttpStatus.OK
        ));
    }


    @PutMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponseDTO<WarehouseSettingResponse>> updateWarehouse(
            @Valid @RequestBody WarehouseSettingRequest request) {
        WarehouseSetting warehouse = WarehouseSetting.builder()
                .name(request.getName())
                .phone(request.getPhone())
                .address(request.getAddress())
                .wardCode(request.getWardCode())
                .wardName(request.getWardName())
                .districtId(request.getDistrictId())
                .districtName(request.getDistrictName())
                .cityId(request.getCityId())
                .cityName(request.getCityName())
                .build();
        WarehouseSettingResponse updated = warehouseSettingService.updateWarehouse(warehouse);
        return ResponseEntity.ok(ApiResponseDTO.success(
                "Cập nhật thông tin kho thành công",
                updated,
                HttpStatus.OK
        ));
    }
}
