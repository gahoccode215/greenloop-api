package com.greenloop.order.controller;

import com.greenloop.order.dto.request.AddToCartRequest;
import com.greenloop.order.dto.request.UpdateCartItemRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.CartResponse;
import com.greenloop.order.service.CartService;
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
@RequestMapping("/api/v1/carts")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Cart", description = "Shopping Cart APIs")
public class CartController {

    private final CartService cartService;

    @GetMapping
    @Operation(summary = "Get customer cart")
    @PreAuthorize("hasRole('CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<CartResponse>> getCart(
            @RequestHeader("X-User-ID") Long userId) {

        CartResponse cart = cartService.getCart(userId);

        return ResponseEntity.ok(ApiResponseDTO.success(
                "Lấy giỏ hàng thành công",
                cart,
                HttpStatus.OK
        ));
    }

    @PostMapping("/items")
    @Operation(summary = "Add product to cart")
    @PreAuthorize("hasRole('CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<CartResponse>> addToCart(
            @RequestHeader("X-User-ID") Long userId,
            @Valid @RequestBody AddToCartRequest request) {

        CartResponse cart = cartService.addToCart(userId, request);

        return ResponseEntity.ok(ApiResponseDTO.success(
                "Thêm sản phẩm vào giỏ hàng thành công",
                cart,
                HttpStatus.OK
        ));
    }

    @PutMapping("/items/{cartItemId}")
    @Operation(summary = "Update cart item quantity")
    @PreAuthorize("hasRole('CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<CartResponse>> updateCartItem(
            @RequestHeader("X-User-ID") Long userId,
            @PathVariable Long cartItemId,
            @Valid @RequestBody UpdateCartItemRequest request) {

        CartResponse cart = cartService.updateCartItem(userId, cartItemId, request);

        return ResponseEntity.ok(ApiResponseDTO.success(
                "Cập nhật giỏ hàng thành công",
                cart,
                HttpStatus.OK
        ));
    }

    @DeleteMapping("/items/{cartItemId}")
    @Operation(summary = "Remove item from cart")
    @PreAuthorize("hasRole('CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<CartResponse>> removeCartItem(
            @RequestHeader("X-User-ID") Long userId,
            @PathVariable Long cartItemId) {

        CartResponse cart = cartService.removeCartItem(userId, cartItemId);

        return ResponseEntity.ok(ApiResponseDTO.success(
                "Xóa sản phẩm khỏi giỏ hàng thành công",
                cart,
                HttpStatus.OK
        ));
    }

    @DeleteMapping
    @Operation(summary = "Clear cart")
    @PreAuthorize("hasRole('CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<Object>> clearCart(
            @RequestHeader("X-User-ID") Long userId) {

        cartService.clearCart(userId);

        return ResponseEntity.ok(ApiResponseDTO.success(
                "Xóa giỏ hàng thành công",
                null,
                HttpStatus.OK
        ));
    }
}
