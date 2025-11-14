package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.command.CreateOrderCommand;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.OrderDTO;
import com.greenloop.order.dto.OrderItemDTO;
import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.request.CheckoutRequest;
import com.greenloop.order.dto.request.OrderItemRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.CheckoutResponse;
import com.greenloop.order.entity.Cart;
import com.greenloop.order.entity.CartItem;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.CartNotFoundException;
import com.greenloop.order.exception.EmptyCartException;
import com.greenloop.order.exception.ProductNotAvailableException;
import com.greenloop.order.exception.ProductNotFoundException;
import com.greenloop.order.repository.CartRepository;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.service.CartService;
import com.greenloop.order.service.OrderService;
import com.greenloop.order.util.OrderCodeGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class OrderServiceImpl implements OrderService {

    private final OrderRepository orderRepository;
    private final CartRepository cartRepository;
    private final ProductClient productClient;
    private final CommandGateway commandGateway;
    private final CartService cartService;
    private final PaymentService paymentService;

    @Override
    @Transactional
    public void createOrder(Order order) {
        orderRepository.save(order);
        log.info("Created order: {}", order.getOrderId());
    }

    @Override
    @Transactional
    public void updateOrderStatus(String orderId, OrderStatus newStatus) {
        orderRepository.findById(orderId).ifPresent(order -> {
            order.setOrderStatus(newStatus);
            orderRepository.save(order);
            log.info("Updated order {} status to {}", orderId, newStatus.getDescription());
        });
    }

    @Override
    public Optional<OrderDTO> fetchOrder(String orderId) {
        return orderRepository.findById(orderId)
                .map(order -> {
                    OrderDTO dto = OrderDTO.builder()
                            .orderId(order.getOrderId())
                            .orderCode(order.getOrderCode())
                            .customerId(order.getCustomerId())
                            .totalPrice(order.getTotalPrice())
                            .orderStatus(order.getOrderStatus())
                            .build();

                    if (order.getOrderItems() != null && !order.getOrderItems().isEmpty()) {
                        List<OrderItemDTO> itemDTOs = order.getOrderItems().stream()
                                .map(item -> OrderItemDTO.builder()
                                        .orderItemId(item.getOrderItemId())
                                        .productId(item.getProductId())
                                        .quantity(item.getQuantity())
                                        .price(item.getPrice())
                                        .build())
                                .collect(Collectors.toList());
                        dto.setOrderItems(itemDTOs);
                    }

                    return dto;
                });
    }

    @Override
    @Transactional
    public CheckoutResponse checkout(Long userId, CheckoutRequest request, String ipAddress) {
        log.info("Starting checkout for customer {} with payment method {}", userId, request.getPaymentMethod());

        Cart cart = cartRepository.findByCustomerId(userId)
                .orElseThrow(() -> new CartNotFoundException(userId));

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
                .customerId(userId)
                .totalPrice(totalPrice)
                .orderStatus(OrderStatus.PENDING)
                .paymentStatus(PaymentStatus.UNPAID)
                .orderItems(orderItems)
                .shippingAddress(request.getShippingAddress())
                .paymentMethod(request.getPaymentMethod())
                .build();

        commandGateway.sendAndWait(command);

        cartService.clearCart(userId);

        CheckoutResponse.CheckoutResponseBuilder responseBuilder = CheckoutResponse.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .createdAt(LocalDateTime.now());

        if (request.getPaymentMethod() == PaymentMethod.COD) {
            responseBuilder.paymentUrl(null)
                    .message("Đặt hàng thành công! Bạn sẽ thanh toán khi nhận hàng.");
        } else if (request.getPaymentMethod() == PaymentMethod.VNPAY) {
            String paymentUrl = paymentService.createPaymentUrl(orderId, totalPrice, ipAddress);
            responseBuilder.paymentUrl(paymentUrl)
                    .message("Vui lòng thanh toán để hoàn tất đơn hàng.");
        }

        log.info("Checkout completed for order {}", orderCode);
        return responseBuilder.build();
    }

    private OrderItemRequest validateAndMapCartItem(CartItem cartItem) {
        ApiResponseDTO<ProductDTO> response = productClient.getProductById(cartItem.getProductId());

        if (!response.isSuccess() || response.getData() == null) {
            throw new ProductNotFoundException(cartItem.getProductId());
        }

        ProductDTO product = response.getData();

        if (!ProductStatusConstant.AVAILABLE.equals(product.getStatus())) {
            throw new ProductNotAvailableException(product.getId());
        }

        return OrderItemRequest.builder()
                .productId(cartItem.getProductId())
                .quantity(1)
                .price(cartItem.getPrice())
                .build();
    }

}
