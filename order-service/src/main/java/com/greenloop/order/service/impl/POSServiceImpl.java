package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.event.OrderCheckedOutEvent;
import com.greenloop.order.dto.request.order.offline.CreatePOSOrderRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.order.offline.POSOrderResponse;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.OrderItem;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.*;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.service.POSService;
import com.greenloop.order.util.OrderCodeGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class POSServiceImpl implements POSService {

    private final OrderRepository orderRepository;
    private final ProductClient productClient;
    private final StreamBridge streamBridge;

    private static final BigDecimal ECO_POINT_TO_MONEY_RATE = BigDecimal.valueOf(1000);

    @Override
    @Transactional
    public POSOrderResponse createPOSOrder(CreatePOSOrderRequest request) {
        log.info("Creating POS order - Event: {}, Staff: {}, Payment: {}",
                request.getEventLocationId(), request.getStaffId(), request.getPaymentMethod());

        // 1. Validate request
        request.validate();

        // 2. Fetch và validate products
        List<ProductDTO> products = new ArrayList<>();
        BigDecimal totalAmount = BigDecimal.ZERO;
        int totalEcoPointsEarned = 0;

        for (Long productId : request.getProductIds()) {
            ApiResponseDTO<ProductDTO> response = productClient.getProductById(productId);

            if (!response.isSuccess() || response.getData() == null) {
                throw new ProductNotFoundException(productId);
            }

            ProductDTO product = response.getData();

            if (!ProductStatusConstant.AVAILABLE.equals(product.getStatus())) {
                throw new ProductNotAvailableException(productId);
            }

            products.add(product);
            totalAmount = totalAmount.add(product.getPrice());
            totalEcoPointsEarned += (product.getEcoPointValue() != null ? product.getEcoPointValue() : 0);
        }

        log.info("Order total: {}đ, Eco points to earn: {}", totalAmount, totalEcoPointsEarned);

        // 3. Validate payment
        validatePayment(request, totalAmount);

        // 4. Create Order
        String orderId = UUID.randomUUID().toString();
        String orderCode = OrderCodeGenerator.generateOrderCode();

        Order order = Order.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .customerId(request.getCustomerId())
                .customerPhoneTemp(request.getCustomerPhone())
                .customerNameTemp(request.getCustomerName())
                .eventLocationId(request.getEventLocationId())
                .orderType(OrderType.OFFLINE)
                .orderStatus(OrderStatus.COMPLETED)
                .paymentStatus(PaymentStatus.PAID)
                .paymentMethod(request.getPaymentMethod())
                .totalPrice(totalAmount)
                .cashAmount(request.getCashAmount())
                .ecoPointsUsed(request.getEcoPointsUsed())
                .ecoPointsEarned(totalEcoPointsEarned)
                .posStaffId(request.getStaffId())
                .isGuestPurchase(request.getCustomerId() == null)
                .build();

        // 5. Create OrderItems
        for (ProductDTO product : products) {
            String imageUrl = (product.getImageUrls() != null && !product.getImageUrls().isEmpty())
                    ? product.getImageUrls().get(0).getProductAssetUrl()
                    : null;

            OrderItem item = OrderItem.builder()
                    .order(order)
                    .productId(product.getId())
                    .productName(product.getName())
                    .productImage(imageUrl)
                    .quantity(1)
                    .price(product.getPrice())
                    .build();

            order.getOrderItems().add(item);
        }

        // 6. Save Order
        order = orderRepository.save(order);
        log.info("POS order created - ID: {}, Code: {}", order.getOrderId(), order.getOrderCode());

        // 7. Publish event
        publishOrderEvent(order, products);

        // 8. Return response
        return mapToResponse(order, products);
    }

    @Override
    @Transactional(readOnly = true)
    public POSOrderResponse getPOSOrderById(String orderId) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));

        if (order.getOrderType() != OrderType.OFFLINE) {
            throw new InvalidOrderTypeException(orderId, OrderType.OFFLINE, order.getOrderType());
        }

        // Fetch lại products
        List<ProductDTO> products = new ArrayList<>();
        for (OrderItem item : order.getOrderItems()) {
            try {
                ApiResponseDTO<ProductDTO> response = productClient.getProductById(item.getProductId());
                if (response.isSuccess() && response.getData() != null) {
                    products.add(response.getData());
                }
            } catch (Exception e) {
                log.warn("Cannot fetch product {}: {}", item.getProductId(), e.getMessage());
            }
        }

        return mapToResponse(order, products);
    }

    // ==================== PAYMENT VALIDATION ====================

    private void validatePayment(CreatePOSOrderRequest request, BigDecimal totalAmount) {
        PaymentMethod method = request.getPaymentMethod();

        if (method == PaymentMethod.CASH) {
            if (request.getCashAmount() == null) {
                request.setCashAmount(totalAmount);
            } else if (request.getCashAmount().compareTo(totalAmount) < 0) {
                throw new InvalidPaymentException(
                        String.format("Số tiền mặt không đủ. Cần: %,dđ, Có: %,dđ",
                                totalAmount.longValue(), request.getCashAmount().longValue())
                );
            }

        } else if (method == PaymentMethod.ECO_POINT) {
            int requiredPoints = totalAmount.divide(ECO_POINT_TO_MONEY_RATE, 0, RoundingMode.UP).intValue();

            if (request.getEcoPointsUsed() < requiredPoints) {
                throw new InsufficientEcoPointsException(
                        request.getCustomerId(),
                        requiredPoints,
                        request.getEcoPointsUsed()
                );
            }

            // TODO: Call Reward Service to check and deduct points
            // rewardClient.deductPoints(request.getCustomerId(), request.getEcoPointsUsed());

        } else if (method == PaymentMethod.MIXED) {
            BigDecimal cashAmount = request.getCashAmount();
            BigDecimal pointsValue = BigDecimal.valueOf(request.getEcoPointsUsed())
                    .multiply(ECO_POINT_TO_MONEY_RATE);
            BigDecimal totalPaid = cashAmount.add(pointsValue);

            if (totalPaid.compareTo(totalAmount) != 0) {
                throw new InvalidPaymentException(
                        String.format("Tổng thanh toán không khớp. Cần: %,dđ, Có: %,dđ (tiền: %,dđ + điểm: %,d)",
                                totalAmount.longValue(), totalPaid.longValue(),
                                cashAmount.longValue(), request.getEcoPointsUsed())
                );
            }

            // TODO: Call Reward Service to deduct points
            // rewardClient.deductPoints(request.getCustomerId(), request.getEcoPointsUsed());
        }
    }

    // ==================== EVENT PUBLISHING ====================

    private void publishOrderEvent(Order order, List<ProductDTO> products) {
        List<OrderCheckedOutEvent.ProductStatusChange> statusChanges = products.stream()
                .map(product -> OrderCheckedOutEvent.ProductStatusChange.builder()
                        .productId(product.getId())
                        .newStatus(ProductStatusConstant.SOLD)
                        .ecoPointValue(product.getEcoPointValue())
                        .build())
                .collect(Collectors.toList());

        OrderCheckedOutEvent event = OrderCheckedOutEvent.builder()
                .orderId(order.getOrderId())
                .customerId(order.getCustomerId())
                .totalAmount(order.getTotalPrice())
                .checkedOutAt(LocalDateTime.now())
                .productStatusChanges(statusChanges)
                .totalEcoPoints(order.getEcoPointsEarned())
                .build();

        streamBridge.send("orderCheckedOut-out-0", event);
        log.info("Published OrderCheckedOutEvent for order: {}", order.getOrderCode());
    }

    // ==================== RESPONSE MAPPING ====================

    private POSOrderResponse mapToResponse(Order order, List<ProductDTO> products) {
        List<POSOrderResponse.ProductInOrder> productInfos = products.stream()
                .map(product -> {
                    String imageUrl = (product.getImageUrls() != null && !product.getImageUrls().isEmpty())
                            ? product.getImageUrls().get(0).getProductAssetUrl()
                            : null;

                    return POSOrderResponse.ProductInOrder.builder()
                            .productId(product.getId())
                            .productName(product.getName())
                            .productImage(imageUrl)
                            .price(product.getPrice())
                            .ecoPointValue(product.getEcoPointValue())
                            .quantity(1)
                            .build();
                })
                .collect(Collectors.toList());

        BigDecimal pointsValueInMoney = order.getEcoPointsUsed() != null
                ? BigDecimal.valueOf(order.getEcoPointsUsed()).multiply(ECO_POINT_TO_MONEY_RATE)
                : BigDecimal.ZERO;

        POSOrderResponse.PaymentInfo paymentInfo = POSOrderResponse.PaymentInfo.builder()
                .method(order.getPaymentMethod())
                .totalAmount(order.getTotalPrice())
                .cashAmount(order.getCashAmount())
                .ecoPointsUsed(order.getEcoPointsUsed())
                .ecoPointsValueInMoney(pointsValueInMoney)
                .build();

        String customerName = order.getCustomerId() != null
                ? "Customer #" + order.getCustomerId() // TODO: Fetch from User Service
                : order.getCustomerNameTemp();

        String customerPhone = order.getCustomerId() != null
                ? null // TODO: Fetch from User Service
                : order.getCustomerPhoneTemp();

        return POSOrderResponse.builder()
                .orderId(order.getOrderId())
                .orderCode(order.getOrderCode())
                .customerId(order.getCustomerId())
                .customerName(customerName)
                .customerPhone(customerPhone)
                .eventLocationId(order.getEventLocationId())
                .orderType(order.getOrderType())
                .orderStatus(order.getOrderStatus())
                .totalAmount(order.getTotalPrice())
                .products(productInfos)
                .payment(paymentInfo)
                .ecoPointsEarned(order.getEcoPointsEarned())
                .processedByStaffId(order.getPosStaffId())
                .createdAt(order.getCreatedAt())
                .build();
    }
}
