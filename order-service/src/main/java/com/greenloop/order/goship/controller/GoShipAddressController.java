package com.greenloop.order.goship.controller;

import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.goship.client.GoShipClient;
import com.greenloop.order.goship.dto.CityDTO;
import com.greenloop.order.goship.dto.DistrictDTO;
import com.greenloop.order.goship.dto.GoShipResponse;
import com.greenloop.order.goship.dto.WardDTO;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/orders/goship/addresses")
@RequiredArgsConstructor
@Slf4j
public class GoShipAddressController {

    private final GoShipClient goShipClient;

    @GetMapping("/cities")
    public ResponseEntity<ApiResponseDTO<List<CityDTO>>> getCities(HttpServletRequest request) {
        try {
            log.info("Getting cities list");
            List<CityDTO> cities = goShipClient.getCities();
            return ResponseEntity.ok(
                    ApiResponseDTO.success(
                            "Lấy danh sách tỉnh/thành phố thành công",
                            cities,
                            HttpStatus.OK
                    )
            );
        } catch (Exception e) {
            log.error("Error getting cities: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    ApiResponseDTO.error(
                            "Lỗi lấy danh sách tỉnh/thành phố: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            request.getRequestURI()
                    )
            );
        }
    }

    /**
     * Lấy districts - Nếu có page param thì lấy theo page, không thì lấy hết
     */
    @GetMapping("/cities/{cityId}/districts")
    public ResponseEntity<?> getDistricts(
            @PathVariable String cityId,
            @RequestParam(required = false) Integer page,
            @RequestParam(required = false, defaultValue = "25") Integer size,
            HttpServletRequest request) {
        try {
            // Nếu có page param -> lấy theo page
            if (page != null) {
                log.info("Getting districts page {} with size {} for city: {}", page, size, cityId);
                GoShipResponse<List<DistrictDTO>> response = goShipClient.getDistrictsByPage(cityId, page, size);
                return ResponseEntity.ok(
                        ApiResponseDTO.success(
                                "Lấy danh sách quận/huyện thành công",
                                response,
                                HttpStatus.OK
                        )
                );
            } else {
                // Không có page param -> lấy hết (auto pagination)
                log.info("Getting all districts for city: {}", cityId);
                List<DistrictDTO> districts = goShipClient.getDistricts(cityId);
                return ResponseEntity.ok(
                        ApiResponseDTO.success(
                                "Lấy danh sách quận/huyện thành công",
                                districts,
                                HttpStatus.OK
                        )
                );
            }
        } catch (Exception e) {
            log.error("Error getting districts: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    ApiResponseDTO.error(
                            "Lỗi lấy danh sách quận/huyện: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            request.getRequestURI()
                    )
            );
        }
    }

    /**
     * Lấy wards - Nếu có page param thì lấy theo page, không thì lấy hết
     */
    @GetMapping("/districts/{districtId}/wards")
    public ResponseEntity<?> getWards(
            @PathVariable String districtId,
            @RequestParam(required = false) Integer page,
            @RequestParam(required = false, defaultValue = "25") Integer size,
            HttpServletRequest request) {
        try {
            // Nếu có page param -> lấy theo page
            if (page != null) {
                log.info("Getting wards page {} with size {} for district: {}", page, size, districtId);
                GoShipResponse<List<WardDTO>> response = goShipClient.getWardsByPage(districtId, page, size);
                return ResponseEntity.ok(
                        ApiResponseDTO.success(
                                "Lấy danh sách phường/xã thành công",
                                response,
                                HttpStatus.OK
                        )
                );
            } else {
                // Không có page param -> lấy hết (auto pagination)
                log.info("Getting all wards for district: {}", districtId);
                List<WardDTO> wards = goShipClient.getWards(districtId);
                return ResponseEntity.ok(
                        ApiResponseDTO.success(
                                "Lấy danh sách phường/xã thành công",
                                wards,
                                HttpStatus.OK
                        )
                );
            }
        } catch (Exception e) {
            log.error("Error getting wards: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    ApiResponseDTO.error(
                            "Lỗi lấy danh sách phường/xã: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            request.getRequestURI()
                    )
            );
        }
    }
}
