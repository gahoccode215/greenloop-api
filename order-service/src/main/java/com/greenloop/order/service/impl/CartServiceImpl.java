package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.ParcelDimensionDTO;
import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.request.AddToCartRequest;
import com.greenloop.order.dto.request.EstimateShippingFeeRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.CartItemResponse;
import com.greenloop.order.dto.response.CartResponse;
import com.greenloop.order.dto.response.ShippingEstimateResponse;
import com.greenloop.order.entity.Cart;
import com.greenloop.order.entity.CartItem;
import com.greenloop.order.exception.*;
import com.greenloop.order.goship.dto.CalculateRateRequest;
import com.greenloop.order.goship.dto.RateResponse;
import com.greenloop.order.repository.CartItemRepository;
import com.greenloop.order.repository.CartRepository;
import com.greenloop.order.service.CartService;
import com.greenloop.order.service.ShippingCalculationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class CartServiceImpl implements CartService {

    private final CartRepository cartRepository;
    private final CartItemRepository cartItemRepository;
    private final ProductClient productClient;
    private final ShippingCalculationService shippingCalculationService;

    @Override
    public ShippingEstimateResponse estimateShippingFee(Long customerId, EstimateShippingFeeRequest request) {
        log.info("Ước tính phí vận chuyển cho khách hàng: {}", customerId);

        Cart cart = cartRepository.findByCustomerId(customerId)
                .orElseThrow(() -> new CartNotFoundException(customerId));

        if (cart.getItems().isEmpty()) {
            throw new EmptyCartException();
        }

        return shippingCalculationService.calculateShippingFee(
                cart.getItems(),
                cart.getTotalAmount(),
                request.getCityCode(),
                request.getDistrictCode()
        );
    }

    @Override
    public CartResponse getCart(Long customerId) {
        Cart cart = cartRepository.findByCustomerId(customerId)
                .orElseGet(() -> createNewCart(customerId));

        return mapToCartResponse(cart);
    }

    @Override
    @Transactional
    public CartResponse addToCart(Long customerId, AddToCartRequest request) {
        log.info("Adding product {} to cart for customer {}", request.getProductId(), customerId);

        Cart cart = cartRepository.findByCustomerId(customerId)
                .orElseGet(() -> createNewCart(customerId));

        ApiResponseDTO<ProductDTO> response = productClient.getProductById(request.getProductId());

        if (!response.isSuccess() || response.getData() == null) {
            throw new ProductNotFoundException(request.getProductId());
        }

        ProductDTO product = response.getData();

        if (!ProductStatusConstant.AVAILABLE.equals(product.getStatus())) {
            throw new ProductNotAvailableException(product.getId());
        }

        boolean existsInCart = cartItemRepository
                .findByCartIdAndProductId(cart.getId(), request.getProductId())
                .isPresent();

        if (existsInCart) {
            throw new ProductAlreadyInCartException();
        }

        String imageUrl = (product.getImageUrls() != null && !product.getImageUrls().isEmpty())
                ? product.getImageUrls().get(0)
                : null;

        int weight = (product.getWeight() > 0)
                ? product.getWeight() : 200;  // Default 200g

        int length = (product.getLength() > 0)
                ? product.getLength() : 20;   // Default 20cm

        int width = (product.getWidth() > 0)
                ? product.getWidth() : 15;    // Default 15cm

        int height = (product.getHeight() > 0)
                ? product.getHeight() : 5;    // Default 5cm

        log.info("Product {} dimensions - Weight: {}g, Size: {}x{}x{} cm (L×W×H)",
                product.getId(), weight, length, width, height);

        CartItem newItem = CartItem.builder()
                .cart(cart)
                .productId(product.getId())
                .productName(product.getName())
                .productImage(imageUrl)
                .price(product.getPrice())
                .weight(weight)
                .length(length)
                .width(width)
                .height(height)
                .build();

        cart.addItem(newItem);
        cart.recalculateTotal();
        cartRepository.save(cart);

        log.info("Product {} added to cart successfully for customer {}", request.getProductId(), customerId);
        return mapToCartResponse(cart);
    }


    @Override
    @Transactional
    public CartResponse removeCartItem(Long customerId, Long cartItemId) {
        Cart cart = cartRepository.findByCustomerId(customerId)
                .orElseThrow(() -> new CartNotFoundException(customerId));

        CartItem item = cartItemRepository.findById(cartItemId)
                .orElseThrow(() -> new CartItemNotFoundException(cartItemId));

        if (!item.getCart().getId().equals(cart.getId())) {
            throw new UnauthorizedCartAccessException();
        }

        cart.removeItem(item);
        cartItemRepository.delete(item);
        cartRepository.save(cart);

        return mapToCartResponse(cart);
    }

    @Override
    @Transactional
    public void clearCart(Long customerId) {
        Cart cart = cartRepository.findByCustomerId(customerId)
                .orElseThrow(() -> new CartNotFoundException(customerId));

        cart.getItems().clear();
        cart.recalculateTotal();
        cartRepository.save(cart);
    }

    private Cart createNewCart(Long customerId) {
        Cart cart = Cart.builder()
                .customerId(customerId)
                .totalAmount(BigDecimal.ZERO)
                .totalItems(0)
                .build();
        return cartRepository.save(cart);
    }

    private CartResponse mapToCartResponse(Cart cart) {
        List<CartItemResponse> items = cart.getItems().stream()
                .map(this::mapToCartItemResponse)
                .collect(Collectors.toList());

        return CartResponse.builder()
                .id(cart.getId())
                .customerId(cart.getCustomerId())
                .items(items)
                .totalAmount(cart.getTotalAmount())
                .totalItems(cart.getTotalItems())
                .createdAt(cart.getCreatedAt())
                .updatedAt(cart.getUpdatedAt())
                .build();
    }

    private CartItemResponse mapToCartItemResponse(CartItem item) {
        return CartItemResponse.builder()
                .id(item.getId())
                .productId(item.getProductId())
                .productName(item.getProductName())
                .productImage(item.getProductImage())
                .price(item.getPrice())
                .createdAt(item.getCreatedAt())
                .weight(item.getWeight())
                .length(item.getLength())
                .width(item.getWidth())
                .height(item.getHeight())
                .build();
    }
}
