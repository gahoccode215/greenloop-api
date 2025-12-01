package com.greenloop.user.controller;

import com.greenloop.user.dto.request.AddressRequest;
import com.greenloop.user.dto.response.AddressResponse;
import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.service.AddressService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/addresses")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Address Management", description = "APIs for managing user shipping addresses")
public class AddressController {

  private final AddressService addressService;

  @PostMapping
  public ResponseEntity<ApiResponseDTO<AddressResponse>> createAddress(
      @Valid @RequestBody AddressRequest request) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());
    AddressResponse response = addressService.createAddress(userId, request);
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(ApiResponseDTO.success("Thêm địa chỉ thành công", response, HttpStatus.CREATED));
  }

  @GetMapping
  public ResponseEntity<ApiResponseDTO<List<AddressResponse>>> getAllAddresses() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());
    List<AddressResponse> addresses = addressService.getAllAddresses(userId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy danh sách địa chỉ thành công", addresses, HttpStatus.OK));
  }

  @GetMapping("/{addressId}")
  public ResponseEntity<ApiResponseDTO<AddressResponse>> getAddressById(
      @PathVariable Long addressId) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());
    AddressResponse response = addressService.getAddressById(userId, addressId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy thông tin địa chỉ thành công", response, HttpStatus.OK));
  }

  @GetMapping("/default")
  public ResponseEntity<ApiResponseDTO<AddressResponse>> getDefaultAddress() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());
    AddressResponse response = addressService.getDefaultAddress(userId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy địa chỉ mặc định thành công", response, HttpStatus.OK));
  }

  @PutMapping("/{addressId}")
  public ResponseEntity<ApiResponseDTO<AddressResponse>> updateAddress(
      @PathVariable Long addressId, @Valid @RequestBody AddressRequest request) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());
    AddressResponse response = addressService.updateAddress(userId, addressId, request);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Cập nhật địa chỉ thành công", response, HttpStatus.OK));
  }

  @PutMapping("/{addressId}/set-default")
  public ResponseEntity<ApiResponseDTO<AddressResponse>> setDefaultAddress(
      @PathVariable Long addressId) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());
    AddressResponse response = addressService.setDefaultAddress(userId, addressId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Đặt địa chỉ mặc định thành công", response, HttpStatus.OK));
  }

  @DeleteMapping("/{addressId}")
  public ResponseEntity<ApiResponseDTO<Void>> deleteAddress(
      @AuthenticationPrincipal String userId, @PathVariable Long addressId) {
    Long controllerUserId = Long.valueOf(userId);
    //        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    //        Long userId = Long.valueOf(auth.getName());
    addressService.deleteAddress(controllerUserId, addressId);
    return ResponseEntity.ok(ApiResponseDTO.success("Xóa địa chỉ thành công", null, HttpStatus.OK));
  }
}
