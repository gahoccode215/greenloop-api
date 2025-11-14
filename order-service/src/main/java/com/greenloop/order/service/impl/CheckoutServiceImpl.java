package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.command.CreateOrderCommand;
import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.request.CheckoutRequest;
import com.greenloop.order.dto.request.OrderItemRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.CheckoutResponse;
import com.greenloop.order.entity.Cart;
import com.greenloop.order.entity.CartItem;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.exception.*;
import com.greenloop.order.repository.CartRepository;
import com.greenloop.order.service.CartService;
import com.greenloop.order.service.CheckoutService;
import com.greenloop.order.util.OrderCodeGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class CheckoutServiceImpl implements CheckoutService {

    private final CartRepository cartRepository;
    private final ProductClient productClient;
    private final CommandGateway commandGateway;
    private final CartService cartService;

    @Override
    @Transactional
    public CheckoutResponse checkout(CheckoutRequest request) {
        log.info("Starting checkout for customer {} with payment method {}",
                request.getCustomerId(), request.getPaymentMethod());

        // 1. Lấy giỏ hàng
        Cart cart = cartRepository.findByCustomerId(request.getCustomerId())
                .orElseThrow(() -> new CartNotFoundException(request.getCustomerId()));

        if (cart.getItems().isEmpty()) {
            throw new EmptyCartException();
        }

        List<OrderItemRequest> orderItems = cart.getItems().stream()
                .map(this::validateAndMapCartItem)
                .collect(Collectors.toList());

        BigDecimal totalPrice = orderItems.stream()
                .map(OrderItemRequest::getPrice)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        String orderId = UUID.randomUUID().toString();
        String orderCode = OrderCodeGenerator.generateOrderCode();

        CreateOrderCommand command = CreateOrderCommand.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .customerId(request.getCustomerId())
                .totalPrice(totalPrice)
                .orderStatus(OrderStatus.PENDING)
                .orderItems(orderItems)
                .shippingAddress(request.getShippingAddress())
//                .paymentMethod(request.getPaymentMethod())
                .build();

        commandGateway.sendAndWait(command);

        // 6. Xóa giỏ hàng sau khi đặt hàng thành công
        cartService.clearCart(request.getCustomerId());

        // 7. Mock payment response (tất cả đều thành công)
        String message = buildSuccessMessage(request.getPaymentMethod());
        String mockPaymentUrl = buildMockPaymentUrl(request.getPaymentMethod(), orderId);

        log.info("Checkout completed successfully for order {}", orderCode);

        return CheckoutResponse.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .paymentUrl(mockPaymentUrl)
                .message(message)
                .createdAt(LocalDateTime.now())
                .build();
    }

    private OrderItemRequest validateAndMapCartItem(CartItem cartItem) {
        ApiResponseDTO<ProductDTO> response = productClient.getProductById(cartItem.getProductId());

        if (!response.isSuccess() || response.getData() == null) {
            throw new ProductNotFoundException(cartItem.getProductId());
        }

        ProductDTO product = response.getData();

        if (!"AVAILABLE".equals(product.getStatus())) {
            throw new ProductNotAvailableException(product.getId());
        }

        return OrderItemRequest.builder()
                .productId(cartItem.getProductId())
                .quantity(1)
                .price(cartItem.getPrice())
                .build();
    }

    private String buildSuccessMessage(PaymentMethod paymentMethod) {
        switch (paymentMethod) {
            case COD:
                return "Đặt hàng thành công! Bạn sẽ thanh toán khi nhận hàng.";
            case VNPAY:
                return "Đặt hàng thành công! Thanh toán VNPAY đã được xử lý.";
            case PAYOS:
                return "Đặt hàng thành công! Thanh toán PayOS đã được xử lý.";
            default:
                return "Đặt hàng thành công!";
        }
    }

    private String buildMockPaymentUrl(PaymentMethod paymentMethod, String orderId) {
        if (paymentMethod == PaymentMethod.COD) {
            return null;
        }
        return String.format("http://localhost:8080/api/v1/orders/%s/payment-success", orderId);
    }
}
