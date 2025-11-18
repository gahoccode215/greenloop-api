package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.command.CreateOrderCommand;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.OrderDTO;
import com.greenloop.order.dto.OrderItemDTO;
import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.ShippingAddressDTO;
import com.greenloop.order.dto.request.CheckoutRequest;
import com.greenloop.order.dto.request.OrderFilterRequest;
import com.greenloop.order.dto.request.OrderItemRequest;
import com.greenloop.order.dto.response.*;
import com.greenloop.order.entity.Cart;
import com.greenloop.order.entity.CartItem;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.*;
import com.greenloop.order.goship.dto.RateResponse;
import com.greenloop.order.repository.CartRepository;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.repository.specification.OrderSpecification;
import com.greenloop.order.service.CartService;
import com.greenloop.order.service.OrderService;
import com.greenloop.order.service.PayOSPaymentService;
import com.greenloop.order.service.ShippingCalculationService;
import com.greenloop.order.util.OrderCodeGenerator;
import com.greenloop.order.util.PageResponseUtil;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
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
                selectedRate = RateResponse.builder()
                        .id("FALLBACK")
                        .carrierName("Vận chuyển tiêu chuẩn")
                        .service("Tiêu chuẩn")
                        .totalFee(BigDecimal.valueOf(30000))
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
                            .totalFee(selected.getFee())
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
                            .totalFee(cheapest.getFee())
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
                    .totalFee(BigDecimal.valueOf(30000))
                    .expected("3-5 ngày")
                    .build();
        }

        BigDecimal shippingFee = selectedRate.getTotalFee();
        BigDecimal totalPrice = productTotal.add(shippingFee);

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

        } else if (request.getPaymentMethod() == PaymentMethod.PAYOS) {
            PayOSPaymentResponse paymentResponse = payOSPaymentService.createPaymentUrl(orderId, totalPrice);
            commandBuilder.paymentOrderCode(paymentResponse.getPaymentOrderCode());

            responseBuilder
                    .paymentUrl(paymentResponse.getCheckoutUrl())
                    .message(String.format("Vui lòng thanh toán %,dđ để hoàn tất đơn hàng.",
                            totalPrice.longValue()));
        }

        // 9. Send command to create order
        commandGateway.sendAndWait(commandBuilder.build());

        // 10. Clear cart after successful checkout
        cartService.clearCart(userId);

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
    @Transactional(readOnly = true)
    public OrderResponse getOrderById(String orderId) {
        log.info("Getting order by ID: {}", orderId);

        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));

        return mapToOrderResponse(order);
    }

    @Override
    @Transactional(readOnly = true)
    public PageResponseDTO<OrderResponse> getAllOrders(Long requestingUserId, OrderFilterRequest filter) {
        log.info("Getting orders - UserId: {}, Filter: {}", requestingUserId, filter);

        // Build Specification
        Specification<Order> spec = OrderSpecification.filterOrders(requestingUserId, filter);

        // Build Pageable
        Sort sort = Sort.by(
                "DESC".equalsIgnoreCase(filter.getSortDirection())
                        ? Sort.Direction.DESC
                        : Sort.Direction.ASC,
                filter.getSortBy()
        );

        Pageable pageable = PageRequest.of(
                filter.getPage() != null ? filter.getPage() : 0,
                filter.getSize() != null ? filter.getSize() : 10,
                sort
        );

        // Query with Specification
        Page<Order> orderPage = orderRepository.findAll(spec, pageable);

        // Map to Response DTO
        Page<OrderResponse> responsePage = orderPage.map(this::mapToOrderResponse);

        return PageResponseUtil.toPageResponse(responsePage);
    }


    private OrderResponse mapToOrderResponse(Order order) {
        OrderResponse response = OrderResponse.builder()
                .orderId(order.getOrderId())
                .orderCode(order.getOrderCode())
                .customerId(order.getCustomerId())
                .totalPrice(order.getTotalPrice())
                .shippingFee(order.getShippingFee())
                .orderStatus(order.getOrderStatus())
                .paymentStatus(order.getPaymentStatus())
                .paymentMethod(order.getPaymentMethod())
                .paymentOrderCode(order.getPaymentOrderCode())
                .paymentTransactionId(order.getPaymentTransactionId())
                .carrier(order.getCarrier())
                .expectedDeliveryTime(order.getExpectedDeliveryTime())
                .shippingStatus(order.getShippingStatus())
                .goshipShipmentId(order.getGoshipShipmentId())
                .goshipTrackingCode(order.getGoshipTrackingCode())
                .createdAt(order.getCreatedAt())
                .updatedAt(order.getUpdatedAt())
                .build();

        // Map shipping address
        if (order.getShippingAddress() != null) {
            ShippingAddressDTO addressDTO = ShippingAddressDTO.builder()
                    .receiverName(order.getShippingAddress().getReceiverName())
                    .receiverPhone(order.getShippingAddress().getReceiverPhone())
                    .receiverAddress(order.getShippingAddress().getReceiverAddress())
                    .receiverWardName(order.getShippingAddress().getReceiverWardName())
                    .receiverWardCode(order.getShippingAddress().getReceiverWardCode())
                    .receiverDistrictName(order.getShippingAddress().getReceiverDistrictName())
                    .receiverDistrictId(order.getShippingAddress().getReceiverDistrictId())
                    .receiverCityName(order.getShippingAddress().getReceiverCityName())
                    .receiverCityId(order.getShippingAddress().getReceiverCityId())
                    .warehouseName(order.getShippingAddress().getWarehouseName())
                    .warehousePhone(order.getShippingAddress().getWarehousePhone())
                    .warehouseAddress(order.getShippingAddress().getWarehouseAddress())
                    .warehouseWardName(order.getShippingAddress().getWarehouseWardName())
                    .warehouseWardCode(order.getShippingAddress().getWarehouseWardCode())
                    .warehouseDistrictName(order.getShippingAddress().getWarehouseDistrictName())
                    .warehouseDistrictId(order.getShippingAddress().getWarehouseDistrictId())
                    .warehouseCityName(order.getShippingAddress().getWarehouseCityName())
                    .warehouseCityId(order.getShippingAddress().getWarehouseCityId())
                    .note(order.getShippingAddress().getNote())
                    .build();

            response.setShippingAddress(addressDTO);
        }

        // Map order items
        if (order.getOrderItems() != null && !order.getOrderItems().isEmpty()) {
            List<OrderItemDTO> itemDTOs = order.getOrderItems().stream()
                    .map(item -> OrderItemDTO.builder()
                            .orderItemId(item.getOrderItemId())
                            .productId(item.getProductId())
                            .quantity(item.getQuantity())
                            .price(item.getPrice())
                            .build())
                    .collect(Collectors.toList());

            response.setOrderItems(itemDTOs);
        }

        return response;
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
