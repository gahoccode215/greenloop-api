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
import com.greenloop.order.goship.dto.RateResponse;
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
        log.info("Checkout for user: {} with payment method: {}", userId, request.getPaymentMethod());

        // 1. Get and validate cart
        Cart cart = cartRepository.findByCustomerId(userId)
                .orElseThrow(() -> new CartNotFoundException(userId));

        if (cart.getItems().isEmpty()) {
            throw new EmptyCartException();
        }

        // 2. Validate products and build order items
        List<OrderItemRequest> orderItems = cart.getItems().stream()
                .map(this::validateAndMapCartItem)
                .collect(Collectors.toList());

        BigDecimal productTotal = orderItems.stream()
                .map(OrderItemRequest::getPrice)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        log.info("Product total: {}đ", productTotal);

        // 3. Get selected shipping rate
        RateResponse selectedRate;
        try {
            ShippingEstimateResponse estimate = shippingCalculationService.calculateShippingFee(
                    cart.getItems(),
                    productTotal,
                    String.valueOf(request.getShippingAddress().getCityId()),
                    String.valueOf(request.getShippingAddress().getDistrictId())
            );

            if (estimate.getAvailableOptions().isEmpty()) {
                log.warn("No shipping options available, using fallback");
                selectedRate = RateResponse.builder()
                        .id("FALLBACK")
                        .carrierName("Vận chuyển tiêu chuẩn")
                        .service("Tiêu chuẩn")
                        .totalFee(BigDecimal.valueOf(30000))  // ✅ FIXED
                        .expected("3-5 ngày")
                        .build();
            } else {
                // Find selected rate by rateId or use cheapest
                if (request.getSelectedRateId() != null && !request.getSelectedRateId().isBlank()) {
                    ShippingEstimateResponse.ShippingOption selected = estimate.getAvailableOptions().stream()
                            .filter(option -> option.getRateId().equals(request.getSelectedRateId()))
                            .findFirst()
                            .orElseGet(() -> {
                                log.warn("Selected rate {} not found, using cheapest", request.getSelectedRateId());
                                return estimate.getAvailableOptions().get(0);
                            });

                    selectedRate = RateResponse.builder()
                            .id(selected.getRateId())
                            .carrierName(selected.getCarrierName())
                            .carrierLogo(selected.getCarrierLogo())
                            .service(selected.getService())
                            .totalFee(selected.getFee())  // ✅ FIXED
                            .expected(selected.getEstimatedDelivery())
                            .build();
                } else {
                    log.info("No rate selected, using cheapest option");
                    ShippingEstimateResponse.ShippingOption cheapest = estimate.getAvailableOptions().get(0);
                    selectedRate = RateResponse.builder()
                            .id(cheapest.getRateId())
                            .carrierName(cheapest.getCarrierName())
                            .carrierLogo(cheapest.getCarrierLogo())
                            .service(cheapest.getService())
                            .totalFee(cheapest.getFee())  // ✅ FIXED
                            .expected(cheapest.getEstimatedDelivery())
                            .build();
                }
            }
        } catch (Exception e) {
            log.error("Error calculating shipping fee: {}", e.getMessage(), e);
            selectedRate = RateResponse.builder()
                    .id("FALLBACK")
                    .carrierName("Vận chuyển tiêu chuẩn")
                    .service("Tiêu chuẩn")
                    .totalFee(BigDecimal.valueOf(30000))  // ✅ FIXED
                    .expected("3-5 ngày")
                    .build();
        }

        BigDecimal shippingFee = selectedRate.getTotalFee();  // ✅ FIXED
        BigDecimal totalPrice = productTotal.add(shippingFee);

        log.info("💰 Order summary - Products: {}đ | Shipping: {}đ ({}) | Total: {}đ",
                productTotal, shippingFee, selectedRate.getCarrierName(), totalPrice);

        // 4. Parse expected delivery time
        LocalDateTime expectedDeliveryTime;
        try {
            String numberStr = selectedRate.getExpected().replaceAll("[^0-9]", "");
            if (!numberStr.isEmpty()) {
                int days = Integer.parseInt(numberStr);
                expectedDeliveryTime = LocalDateTime.now().plusDays(days);
            } else {
                expectedDeliveryTime = LocalDateTime.now().plusDays(3);
            }
        } catch (Exception e) {
            log.warn("Failed to parse expected delivery: {}", selectedRate.getExpected());
            expectedDeliveryTime = LocalDateTime.now().plusDays(3);
        }

        // 5. Generate order identifiers
        String orderId = UUID.randomUUID().toString();
        String orderCode = OrderCodeGenerator.generateOrderCode();

        // 6. Build create order command
        CreateOrderCommand.CreateOrderCommandBuilder commandBuilder = CreateOrderCommand.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .customerId(userId)
                .totalPrice(totalPrice)
                .shippingFee(shippingFee)
                .orderStatus(OrderStatus.PENDING)
                .paymentStatus(PaymentStatus.UNPAID)
                .orderItems(orderItems)
                .shippingAddress(request.getShippingAddress())
                .paymentMethod(request.getPaymentMethod())
                .selectedRateId(request.getSelectedRateId())
                .carrier(selectedRate.getCarrierName())
                .expectedDeliveryTime(expectedDeliveryTime);

        // 7. Build checkout response
        CheckoutResponse.CheckoutResponseBuilder responseBuilder = CheckoutResponse.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .productTotal(productTotal)
                .shippingFee(shippingFee)
                .totalPrice(totalPrice)
                .selectedCarrier(selectedRate.getCarrierName())
                .estimatedDelivery(selectedRate.getExpected())
                .createdAt(LocalDateTime.now());

        // 8. Handle payment method
        if (request.getPaymentMethod() == PaymentMethod.COD) {
            responseBuilder
                    .paymentUrl(null)
                    .message(String.format("Đặt hàng thành công! Tổng thanh toán: %,dđ khi nhận hàng.",
                            totalPrice.longValue()));

            log.info("COD order created: {}", orderCode);

        } else if (request.getPaymentMethod() == PaymentMethod.PAYOS) {
            PayOSPaymentResponse paymentResponse = payOSPaymentService.createPaymentUrl(orderId, totalPrice);
            commandBuilder.paymentOrderCode(paymentResponse.getPaymentOrderCode());

            responseBuilder
                    .paymentUrl(paymentResponse.getCheckoutUrl())
                    .message(String.format("Vui lòng thanh toán %,dđ để hoàn tất đơn hàng.",
                            totalPrice.longValue()));

            log.info("PayOS order created - OrderId: {}, PaymentCode: {}",
                    orderId, paymentResponse.getPaymentOrderCode());
        }

        // 9. Send command to create order
        commandGateway.sendAndWait(commandBuilder.build());

        // 10. Clear cart after successful checkout
        cartService.clearCart(userId);
        log.info("✅ Checkout completed for order: {}", orderCode);

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
