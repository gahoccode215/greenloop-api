package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.command.CreateOrderCommand;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.OrderDTO;
import com.greenloop.order.dto.OrderItemDTO;
import com.greenloop.order.dto.ParcelDimensionDTO;
import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.request.CheckoutRequest;
import com.greenloop.order.dto.request.OrderItemRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.CheckoutResponse;
import com.greenloop.order.dto.response.PayOSPaymentResponse;
import com.greenloop.order.dto.response.ShippingEstimateResponse;
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
import com.greenloop.order.goship.dto.CalculateRateRequest;
import com.greenloop.order.goship.dto.RateResponse;
import com.greenloop.order.goship.service.GoShipService;
import com.greenloop.order.repository.CartRepository;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.service.CartService;
import com.greenloop.order.service.OrderService;
import com.greenloop.order.service.PayOSPaymentService;
import com.greenloop.order.service.ShippingCalculationService;
import com.greenloop.order.util.OrderCodeGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.springframework.beans.factory.annotation.Value;
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
    private final PayOSPaymentService payOSPaymentService;
    private final ShippingCalculationService shippingCalculationService;




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
                            .goshipShipmentId(order.getGoshipShipmentId())
                            .goshipTrackingCode(order.getGoshipTrackingCode())
                            .carrier(order.getCarrier())
                            .shippingFee(order.getShippingFee())
                            .expectedDeliveryTime(order.getExpectedDeliveryTime())
                            .shippingStatus(order.getShippingStatus())
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
    public CheckoutResponse checkout(Long userId, CheckoutRequest request) {
        log.info("Bắt đầu thanh toán cho khách hàng {} với phương thức {}", userId, request.getPaymentMethod());

        // 1. Get cart
        Cart cart = cartRepository.findByCustomerId(userId)
                .orElseThrow(() -> new CartNotFoundException(userId));

        if (cart.getItems().isEmpty()) {
            throw new EmptyCartException();
        }

        // 2. Validate và map order items
        List<OrderItemRequest> orderItems = cart.getItems().stream()
                .map(this::validateAndMapCartItem)
                .collect(Collectors.toList());

        BigDecimal productTotal = orderItems.stream()
                .map(OrderItemRequest::getPrice)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        log.info("Tổng tiền sản phẩm: {}đ", productTotal);

        // 3. Tính phí vận chuyển (delegate to ShippingCalculationService)
        ShippingEstimateResponse shippingEstimate;

        try {
            shippingEstimate = shippingCalculationService.calculateShippingFee(
                    cart.getItems(),
                    productTotal,
                    String.valueOf(request.getShippingAddress().getCityId()),
                    String.valueOf(request.getShippingAddress().getCityId())
            );

            log.info("✅ Phí vận chuyển: {}đ - Đơn vị: {}",
                    shippingEstimate.getShippingFee(),
                    shippingEstimate.getSelectedCarrier());

        } catch (Exception e) {

            shippingEstimate = ShippingEstimateResponse.builder()
                    .productTotal(productTotal)
                    .shippingFee(BigDecimal.valueOf(30000))
                    .totalPrice(productTotal.add(BigDecimal.valueOf(30000)))
                    .selectedCarrier("Vận chuyển tiêu chuẩn")
                    .estimatedDelivery("3-5 ngày")
                    .availableOptions(List.of())
                    .build();
        }

        // 4. Tính tổng tiền
        BigDecimal totalPrice = shippingEstimate.getTotalPrice();

        log.info("💰 Tổng đơn hàng: {}đ (Sản phẩm: {}đ + Vận chuyển: {}đ)",
                totalPrice, productTotal, shippingEstimate.getShippingFee());

        // 5. Tạo order
        String orderId = UUID.randomUUID().toString();
        String orderCode = OrderCodeGenerator.generateOrderCode();

        CreateOrderCommand.CreateOrderCommandBuilder command = CreateOrderCommand.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .customerId(userId)
                .totalPrice(totalPrice)
                .shippingFee(shippingEstimate.getShippingFee())
                .orderStatus(OrderStatus.PENDING)
                .paymentStatus(PaymentStatus.UNPAID)
                .orderItems(orderItems)
                .shippingAddress(request.getShippingAddress())
                .paymentMethod(request.getPaymentMethod());

        // 6. Build response
        CheckoutResponse.CheckoutResponseBuilder responseBuilder = CheckoutResponse.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .productTotal(productTotal)
                .shippingFee(shippingEstimate.getShippingFee())
                .totalPrice(totalPrice)
                .selectedCarrier(shippingEstimate.getSelectedCarrier())
                .estimatedDelivery(shippingEstimate.getEstimatedDelivery())
                .createdAt(LocalDateTime.now());

        // 7. Handle payment method
        if (request.getPaymentMethod() == PaymentMethod.COD) {
            responseBuilder.paymentUrl(null)
                    .message("Đặt hàng thành công! Tổng thanh toán: " +
                            totalPrice + "đ khi nhận hàng.");
        } else if (request.getPaymentMethod() == PaymentMethod.PAYOS) {
            PayOSPaymentResponse paymentResponse = payOSPaymentService.createPaymentUrl(orderId, totalPrice);
            command.paymentOrderCode(paymentResponse.getPaymentOrderCode());
            log.info("Tạo link thanh toán - OrderId: {}, PaymentOrderCode: {}",
                    orderId, paymentResponse.getPaymentOrderCode());
            responseBuilder.paymentUrl(paymentResponse.getCheckoutUrl())
                    .message("Vui lòng thanh toán " + totalPrice + "đ để hoàn tất đơn hàng.");
        }

        // 8. Send command
        commandGateway.sendAndWait(command.build());

        // 9. Clear cart
        cartService.clearCart(userId);

        log.info("✅ Hoàn tất thanh toán cho đơn hàng {}", orderCode);
        return responseBuilder.build();
    }


    @Override
    public String findOrderIdByPaymentOrderCode(Long paymentOrderCode) {
        return orderRepository.findByPaymentOrderCode(paymentOrderCode)
                .map(Order::getOrderId)
                .orElse(null);
    }

    @Override
    @Transactional
    public void updatePaymentStatus(String orderId, PaymentStatus status) {
        orderRepository.findById(orderId).ifPresent(order -> {
            order.setPaymentStatus(status);
            orderRepository.save(order);
            log.info("Updated payment status to {} for order {}", status, orderId);
        });
    }

    @Override
    @Transactional
    public void updatePaymentTransactionId(String orderId, String transactionId) {
        orderRepository.findById(orderId).ifPresent(order -> {
            order.setPaymentTransactionId(transactionId);
            orderRepository.save(order);
        });
    }

    @Override
    @Transactional
    public void updateShippingInfo(String orderId, String shipmentId, String trackingCode,
                                   String carrier, BigDecimal shippingFee, LocalDateTime expectedDeliveryTime) {
        orderRepository.findById(orderId).ifPresent(order -> {
            order.setGoshipShipmentId(shipmentId);
            order.setGoshipTrackingCode(trackingCode);
            order.setCarrier(carrier);
            order.setShippingFee(shippingFee);
            order.setExpectedDeliveryTime(expectedDeliveryTime);
            orderRepository.save(order);
            log.info("Updated shipping info for order {}: shipmentId={}, trackingCode={}",
                    orderId, shipmentId, trackingCode);
        });
    }

    @Override
    @Transactional
    public void updateShippingStatus(String orderId, String shippingStatus) {
        orderRepository.findById(orderId).ifPresent(order -> {
            order.setShippingStatus(shippingStatus);
            orderRepository.save(order);
            log.info("Updated shipping status to {} for order {}", shippingStatus, orderId);
        });
    }

    @Override
    public Optional<Order> findById(String orderId) {
        return orderRepository.findById(orderId);
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
