package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.event.OrderOfflineCreatedEvent;
import com.greenloop.order.dto.request.CreateOrderOfflineRequest;
import com.greenloop.order.dto.request.OrderItemOfflineRequest;
import com.greenloop.order.dto.request.ProductValidationRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.OrderItemResponse;
import com.greenloop.order.dto.response.OrderOfflineResponse;
import com.greenloop.order.dto.response.VoucherDiscountResult;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.OrderItem;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.ProductValidationException;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.service.OrderOfflineService;
import com.greenloop.order.service.VoucherDiscountService;
import com.greenloop.order.util.OrderCodeGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class OrderOfflineServiceImpl implements OrderOfflineService {

    private final OrderRepository orderRepository;
    private final OrderCodeGenerator orderCodeGenerator;
    private final VoucherDiscountService voucherDiscountService;
    private final StreamBridge streamBridge;
    private final ProductClient productClient;

    @Override
    @Transactional
    public OrderOfflineResponse createOrderOffline(CreateOrderOfflineRequest request) {

        // 1. Validate products thuộc event
        validateProductsInEvent(request);

        // 2. Lấy thông tin Product từ Product Service (bao gồm ecoPointValue)
        Map<Long, ProductDTO> productDetailsMap = fetchProductDetails(request);

        // 3. Tính subtotal
        BigDecimal subtotal = calculateSubtotal(request.getItems());

        // 4. Validate và tính discount từ voucher
        VoucherDiscountResult voucherResult =
                voucherDiscountService.validateAndCalculate(
                        request.getVoucherUserId(), subtotal);

        BigDecimal discountAmount = voucherResult.getDiscountAmount();
        BigDecimal totalPrice = subtotal.subtract(discountAmount);

        // 5. Tính tổng eco points từ Product Service
        Integer earnedEcoPoints = calculateEcoPoints(request, productDetailsMap);

        // 6. Tạo Order entity
        String orderId = UUID.randomUUID().toString();
        String orderCode = orderCodeGenerator.generateOrderOfflineCode();

        Order order = Order.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .customerId(request.getCustomerId())
                .eventId(request.getEventId())
                .voucherUserId(request.getVoucherUserId())
                .voucherCode(voucherResult.getVoucherCode())
                .discountAmount(discountAmount)
                .guestName(request.getGuestName())
                .guestPhone(request.getGuestPhone())
                .isGuestPurchase(request.getIsGuestPurchase())
                .subTotal(subtotal)
                .totalPrice(totalPrice)
                .earnedEcoPoints(earnedEcoPoints)
                .orderType(OrderType.OFFLINE)
                .orderStatus(OrderStatus.COMPLETED)
                .paymentStatus(PaymentStatus.PAID)
                .paymentMethod(PaymentMethod.valueOf(request.getPaymentMethod()))
                .note(request.getNote())
                .createdAt(LocalDateTime.now())
                .createdBy(getCreatedBy())
                .build();

        // 7. Tạo OrderItems với ecoPoint từ Product Service
        List<OrderItem> orderItems = request.getItems().stream()
                .map(item -> {
                    ProductDTO productDetail = productDetailsMap.get(item.getProductId());
                    Integer ecoPoint = getEcoPointFromProduct(productDetail);

                    return OrderItem.builder()
                            .productId(item.getProductId())
                            .productName(item.getProductName())
                            .productImage(item.getProductImage())
                            .price(item.getPrice())
                            .ecoPoint(ecoPoint)
                            .order(order)
                            .build();
                })
                .collect(Collectors.toList());

        order.setOrderItems(orderItems);

        // 8. Lưu vào database
        Order savedOrder = orderRepository.save(order);

        log.info("Order created successfully with code: {}, earnedEcoPoints: {}",
                orderCode, earnedEcoPoints);

        // 9. Publish event
        publishOrderOfflineCreatedEvent(savedOrder);

        // 10. Trả response
        return buildResponseFromEntity(savedOrder, voucherResult);
    }

    /**
     * Lấy thông tin chi tiết Product từ Product Service
     * Trả về Map<ProductId, ProductDTO> để dễ lookup
     */
    private Map<Long, ProductDTO> fetchProductDetails(CreateOrderOfflineRequest request) {
        Map<Long, ProductDTO> productDetailsMap = new HashMap<>();

        for (OrderItemOfflineRequest item : request.getItems()) {
            try {
                ApiResponseDTO<ProductDTO> response =
                        productClient.getProductById(item.getProductId());

                if (response.isSuccess() && response.getData() != null) {
                    ProductDTO productDTO = response.getData();
                    productDetailsMap.put(item.getProductId(), productDTO);

                    log.debug("Fetched product: id={}, name={}, ecoPointValue={}",
                            productDTO.getId(),
                            productDTO.getName(),
                            productDTO.getEcoPointValue());
                } else {
                    log.warn("Failed to fetch product details for productId: {}",
                            item.getProductId());

                    // Fallback: tạo ProductDTO với ecoPointValue = 0
                    productDetailsMap.put(item.getProductId(),
                            createFallbackProductDTO(item.getProductId()));
                }
            } catch (Exception e) {
                log.error("Error fetching product details for productId: {}. Error: {}",
                        item.getProductId(), e.getMessage());

                // Fallback: ecoPointValue = 0
                productDetailsMap.put(item.getProductId(),
                        createFallbackProductDTO(item.getProductId()));
            }
        }

        return productDetailsMap;
    }

    /**
     * Tạo ProductDTO fallback khi không lấy được từ Product Service
     */
    private ProductDTO createFallbackProductDTO(Long productId) {
        return ProductDTO.builder()
                .id(productId)
                .ecoPointValue(0)
                .build();
    }

    /**
     * Lấy ecoPointValue từ ProductDTO, xử lý null safety
     */
    private Integer getEcoPointFromProduct(ProductDTO productDTO) {
        if (productDTO == null) {
            return 0;
        }

        Integer ecoPointValue = productDTO.getEcoPointValue();
        return ecoPointValue != null ? ecoPointValue : 0;
    }

    /**
     * Tính tổng eco points từ Product Service
     * Chỉ tính cho customer (isGuestPurchase = false)
     */
    private Integer calculateEcoPoints(
            CreateOrderOfflineRequest request,
            Map<Long, ProductDTO> productDetailsMap) {

        // Guest không nhận điểm
        if (Boolean.TRUE.equals(request.getIsGuestPurchase())) {
            log.debug("Guest purchase - no eco points earned");
            return 0;
        }

        // Tính tổng điểm từ Product Service
        Integer totalPoints = request.getItems().stream()
                .map(item -> {
                    ProductDTO productDTO = productDetailsMap.get(item.getProductId());
                    return getEcoPointFromProduct(productDTO);
                })
                .reduce(0, Integer::sum);

        log.debug("Customer purchase - total eco points: {}", totalPoints);
        return totalPoints;
    }

    /**
     * Publish event OrderOfflineCreated
     */
    private void publishOrderOfflineCreatedEvent(Order order) {
        try {
            List<OrderOfflineCreatedEvent.ProductStatusChange> productStatusChanges =
                    order.getOrderItems().stream()
                            .map(item -> OrderOfflineCreatedEvent.ProductStatusChange.builder()
                                    .productId(item.getProductId())
                                    .newStatus(ProductStatusConstant.SOLD)
                                    .build())
                            .collect(Collectors.toList());

            OrderOfflineCreatedEvent event = OrderOfflineCreatedEvent.builder()
                    .orderId(order.getOrderId())
                    .orderCode(order.getOrderCode())
                    .eventId(order.getEventId())
                    .customerId(order.getCustomerId())
                    .isGuestPurchase(order.getIsGuestPurchase())
                    .totalAmount(order.getTotalPrice())
                    .earnedEcoPoints(order.getEarnedEcoPoints())
                    .createdAt(order.getCreatedAt())
                    .productStatusChanges(productStatusChanges)
                    .build();

            streamBridge.send("orderOfflineCreated-out-0", event);

            log.info("Published OrderOfflineCreatedEvent for order: {}, earnedEcoPoints: {}",
                    order.getOrderCode(), order.getEarnedEcoPoints());

        } catch (Exception e) {
            log.error("Failed to publish OrderOfflineCreatedEvent for order: {}. Error: {}",
                    order.getOrderCode(), e.getMessage(), e);
        }
    }

    /**
     * Build response từ entity đã lưu
     */
    private OrderOfflineResponse buildResponseFromEntity(
            Order order,
            VoucherDiscountResult voucherResult) {

        List<OrderItemResponse> itemResponses = order.getOrderItems().stream()
                .map(item -> OrderItemResponse.builder()
                        .orderItemId(item.getOrderItemId())
                        .productId(item.getProductId())
                        .productName(item.getProductName())
                        .productImage(item.getProductImage())
                        .price(item.getPrice())
                        .ecoPoint(item.getEcoPoint())
                        .build())
                .collect(Collectors.toList());

        return OrderOfflineResponse.builder()
                .orderId(order.getOrderId())
                .orderCode(order.getOrderCode())
                .eventId(order.getEventId())
                .customerId(order.getCustomerId())
                .isGuestPurchase(order.getIsGuestPurchase())
                .items(itemResponses)
                .subtotal(order.getSubTotal())
                .discountAmount(voucherResult.getDiscountAmount())
                .totalPrice(order.getTotalPrice())
                .voucherCode(voucherResult.getVoucherCode())
                .paymentMethod(order.getPaymentMethod().name())
                .earnedEcoPoints(order.getEarnedEcoPoints())
                .createdAt(order.getCreatedAt())
                .createdBy(order.getCreatedBy())
                .build();
    }

    /**
     * Validate products thuộc event
     */
    private void validateProductsInEvent(CreateOrderOfflineRequest request) {
        List<Long> productIds = request.getItems().stream()
                .map(OrderItemOfflineRequest::getProductId)
                .collect(Collectors.toList());

        try {
            productClient.validateProductsForOfflineOrder(
                    ProductValidationRequest.builder()
                            .eventId(request.getEventId())
                            .productIds(productIds)
                            .build()
            );
        } catch (Exception e) {
            log.error("Product validation failed for event {}: {}",
                    request.getEventId(), e.getMessage());
            throw new ProductValidationException();
        }
    }

    /**
     * Tính subtotal từ các items
     */
    private BigDecimal calculateSubtotal(List<OrderItemOfflineRequest> items) {
        return items.stream()
                .map(OrderItemOfflineRequest::getPrice)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
    }

    /**
     * Lấy thông tin user đang tạo order
     */
    private String getCreatedBy() {
        Authentication authentication = SecurityContextHolder
                .getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            return authentication.getName();
        }
        return "anonymous";
    }
}
