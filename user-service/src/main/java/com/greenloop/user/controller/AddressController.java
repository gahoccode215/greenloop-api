package com.greenloop.user.controller;

import com.greenloop.user.dto.request.AddressRequest;
import com.greenloop.user.dto.response.AddressResponse;
import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.service.AddressService;
import io.swagger.v3.oas.annotations.Operation;
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

  @Operation(
      summary = "Create new address",
      description = "Create a new shipping address for the authenticated user")
  @PostMapping
  public ResponseEntity<ApiResponseDTO<AddressResponse>> createAddress(
      @Valid @RequestBody AddressRequest request) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());
    AddressResponse response = addressService.createAddress(userId, request);
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(ApiResponseDTO.success("Thêm địa chỉ thành công", response, HttpStatus.CREATED));
  }

  @Operation(
      summary = "Get all addresses",
      description = "Retrieve all shipping addresses of the authenticated user")
  @GetMapping
  public ResponseEntity<ApiResponseDTO<List<AddressResponse>>> getAllAddresses() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());
    List<AddressResponse> addresses = addressService.getAllAddresses(userId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy danh sách địa chỉ thành công", addresses, HttpStatus.OK));
  }

  @Operation(summary = "Get address by ID", description = "Retrieve a specific address by its ID")
  @GetMapping("/{addressId}")
  public ResponseEntity<ApiResponseDTO<AddressResponse>> getAddressById(
      @PathVariable Long addressId) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());
    AddressResponse response = addressService.getAddressById(userId, addressId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy thông tin địa chỉ thành công", response, HttpStatus.OK));
  }

  @Operation(
      summary = "Get default address",
      description = "Retrieve the default shipping address of the authenticated user")
  @GetMapping("/default")
  public ResponseEntity<ApiResponseDTO<AddressResponse>> getDefaultAddress() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());
    AddressResponse response = addressService.getDefaultAddress(userId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy địa chỉ mặc định thành công", response, HttpStatus.OK));
  }

  @Operation(summary = "Update address", description = "Update an existing shipping address")
  @PutMapping("/{addressId}")
  public ResponseEntity<ApiResponseDTO<AddressResponse>> updateAddress(
      @PathVariable Long addressId, @Valid @RequestBody AddressRequest request) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());
    AddressResponse response = addressService.updateAddress(userId, addressId, request);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Cập nhật địa chỉ thành công", response, HttpStatus.OK));
  }

  @Operation(
      summary = "Set default address",
      description = "Set a specific address as the default shipping address")
  @PutMapping("/{addressId}/set-default")
  public ResponseEntity<ApiResponseDTO<AddressResponse>> setDefaultAddress(
      @PathVariable Long addressId) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.valueOf(auth.getName());
    log.info("Setting default address {} for user: {}", addressId, userId);
    AddressResponse response = addressService.setDefaultAddress(userId, addressId);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Đặt địa chỉ mặc định thành công", response, HttpStatus.OK));
  }

  @Operation(summary = "Delete address", description = "Delete a shipping address")
  @DeleteMapping("/{addressId}")
  public ResponseEntity<ApiResponseDTO<Void>> deleteAddress(
      @AuthenticationPrincipal String userId, @PathVariable Long addressId) {
    Long controllerUserId = Long.valueOf(userId);
    //        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    //        Long userId = Long.valueOf(auth.getName());
    log.info("Deleting address {} for user: {}", addressId, userId);
    addressService.deleteAddress(controllerUserId, addressId);
    return ResponseEntity.ok(ApiResponseDTO.success("Xóa địa chỉ thành công", null, HttpStatus.OK));
  }
}
