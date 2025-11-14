package com.greenloop.order.controller;

import com.greenloop.order.dto.request.AddToCartRequest;
import com.greenloop.order.dto.request.CheckoutRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.CartResponse;
import com.greenloop.order.dto.response.CheckoutResponse;
import com.greenloop.order.service.CartService;
import com.greenloop.order.service.OrderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/carts")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Cart", description = "Shopping Cart APIs")
public class CartController {

    private final CartService cartService;
    private final OrderService orderService;

    @GetMapping
    @Operation(summary = "Get customer cart")
    @PreAuthorize("hasRole('CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<CartResponse>> getCart() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long userId = Long.valueOf(auth.getName());
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
            @Valid @RequestBody AddToCartRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long userId = Long.valueOf(auth.getName());
        CartResponse cart = cartService.addToCart(userId, request);

        return ResponseEntity.ok(ApiResponseDTO.success(
                "Thêm sản phẩm vào giỏ hàng thành công",
                cart,
                HttpStatus.OK
        ));
    }

    @DeleteMapping("/items/{cartItemId}")
    @Operation(summary = "Remove item from cart")
    @PreAuthorize("hasRole('CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<CartResponse>> removeCartItem(
            @PathVariable Long cartItemId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long userId = Long.valueOf(auth.getName());
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
    public ResponseEntity<ApiResponseDTO<Object>> clearCart() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long userId = Long.valueOf(auth.getName());
        cartService.clearCart(userId);

        return ResponseEntity.ok(ApiResponseDTO.success(
                "Xóa giỏ hàng thành công",
                null,
                HttpStatus.OK
        ));
    }

    @PostMapping("/checkout")
    @Operation(summary = "Checkout and create order")
    @PreAuthorize("hasRole('CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<CheckoutResponse>> checkout(
            @Valid @RequestBody CheckoutRequest request,
            HttpServletRequest httpRequest)  {
        String clientIp = getClientIp(httpRequest);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long userId = Long.valueOf(auth.getName());
        CheckoutResponse response = orderService.checkout(userId, request, clientIp);

        return ResponseEntity.ok(ApiResponseDTO.success(
                response.getMessage(),
                response,
                HttpStatus.OK
        ));
    }

    private String getClientIp(HttpServletRequest request) {
        String clientIp = request.getHeader("X-Forwarded-For");
        if (clientIp == null || clientIp.isEmpty()) {
            clientIp = request.getRemoteAddr();
        }
        return clientIp;
    }

}
