package com.greenloop.order.ghn.controller;

import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.ghn.dto.GHNDistrictDTO;
import com.greenloop.order.ghn.dto.GHNProvinceDTO;
import com.greenloop.order.ghn.dto.GHNWardDTO;
import com.greenloop.order.ghn.service.GHNService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/ghn/addresses")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "GHN Address Controller", description = "GHN Address Controller")
public class GHNController {

    private final GHNService ghnService;

    @GetMapping("/provinces")
    public ResponseEntity<ApiResponseDTO<List<GHNProvinceDTO>>> getProvinces() {
        log.info("Getting provinces list from GHN");
        List<GHNProvinceDTO> provinces = ghnService.getAllProvinces();
        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy danh sách tỉnh/thành phố thành công",
                        provinces,
                        HttpStatus.OK
                )
        );
    }

    @GetMapping("/provinces/{provinceId}/districts")
    public ResponseEntity<ApiResponseDTO<List<GHNDistrictDTO>>> getDistricts(
            @PathVariable Integer provinceId) {
        log.info("Getting districts for province ID: {}", provinceId);
        List<GHNDistrictDTO> districts = ghnService.getDistrictsByProvinceId(provinceId);
        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy danh sách quận/huyện thành công",
                        districts,
                        HttpStatus.OK
                )
        );
    }

    @GetMapping("/districts/{districtId}/wards")
    public ResponseEntity<ApiResponseDTO<List<GHNWardDTO>>> getWards(
            @PathVariable Integer districtId) {
        log.info("Getting wards for district ID: {}", districtId);
        List<GHNWardDTO> wards = ghnService.getWardsByDistrictId(districtId);
        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy danh sách phường/xã thành công",
                        wards,
                        HttpStatus.OK
                )
        );
    }
}
