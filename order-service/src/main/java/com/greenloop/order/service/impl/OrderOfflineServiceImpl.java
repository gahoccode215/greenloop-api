package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.client.RewardClient;
import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.redis.PendingOrderRedis;
import com.greenloop.order.dto.request.*;
import com.greenloop.order.dto.response.*;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.OrderItem;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.ProductValidationException;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.service.*;
import com.greenloop.order.util.OrderCodeGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class OrderOfflineServiceImpl implements OrderOfflineService {

    private final OrderRepository orderRepository;
    private final OrderCodeGenerator orderCodeGenerator;
    private final VoucherDiscountService voucherDiscountService;
    private final ProductClient productClient;
    private final RewardClient rewardClient;
    private final PayOSPaymentService payOSPaymentService;
    private final PendingOrderCacheService pendingOrderCacheService;
    private final TransactionService transactionService;

    @Override
    @Transactional
    public OrderOfflineResponse createOrderOffline(
            CreateOrderOfflineRequest request,
            MultipartFile paymentProofImage) {
        validateProductsInEvent(request);
        Map<Long, ProductDTO> productDetailsMap = fetchProductDetailsForOrder(request);
        enrichItemsWithEcoPoints(request.getItems(), productDetailsMap);
        BigDecimal subtotal = calculateSubtotal(request.getItems());
        VoucherDiscountResult voucherResult =
                voucherDiscountService.validateAndCalculateOffline(
                        request.getVoucherUserId(), subtotal);

        BigDecimal discountAmount = voucherResult.getDiscountAmount();
        BigDecimal totalPrice = subtotal.subtract(discountAmount);

        Integer earnedEcoPoints = calculateEcoPoints(request);

        String orderId = UUID.randomUUID().toString();
        String orderCode = orderCodeGenerator.generateOrderOfflineCode();

        if ("CASH".equals(request.getPaymentMethod())) {
            return handleCashPayment(
                    orderId, orderCode, request,
                    productDetailsMap,
                    subtotal, totalPrice, discountAmount,
                    voucherResult, earnedEcoPoints
            );

        } else if ("BANK_TRANSFER".equals(request.getPaymentMethod())) {
            return handleBankTransferPayment(
                    orderId, orderCode, request,
                    productDetailsMap,
                    subtotal, totalPrice, discountAmount,
                    voucherResult, earnedEcoPoints
            );
        }

        throw new IllegalArgumentException("Phương thức thanh toán không hợp lệ");
    }

    private OrderOfflineResponse handleCashPayment(
            String orderId,
            String orderCode,
            CreateOrderOfflineRequest request,
            Map<Long, ProductDTO> productDetailsMap,
            BigDecimal subtotal,
            BigDecimal totalPrice,
            BigDecimal discountAmount,
            VoucherDiscountResult voucherResult,
            Integer earnedEcoPoints) {
        Order order = buildOfflineOrder(
                orderId, orderCode, request,
                subtotal, totalPrice, discountAmount,
                voucherResult, earnedEcoPoints,
                OrderStatus.COMPLETED,
                PaymentStatus.PAID,
                PaymentMethod.CASH,
                null
        );
        List<OrderItem> orderItems = request.getItems().stream()
                .map(item -> OrderItem.builder()
                        .productId(item.getProductId())
                        .productName(item.getProductName())
                        .productImage(item.getProductImage())
                        .price(item.getPrice())
                        .ecoPoint(item.getEcoPoint())
                        .order(order)
                        .build())
                .collect(Collectors.toList());

        order.setOrderItems(orderItems);
        Order savedOrder = orderRepository.save(order);
        transactionService.createTransactionForOfflineOrder(savedOrder);

        processCompletedOfflineOrder(savedOrder);

        return buildResponseFromEntity(savedOrder, voucherResult, null);
    }

    private OrderOfflineResponse handleBankTransferPayment(
            String orderId,
            String orderCode,
            CreateOrderOfflineRequest request,
            Map<Long, ProductDTO> productDetailsMap,
            BigDecimal subtotal,
            BigDecimal totalPrice,
            BigDecimal discountAmount,
            VoucherDiscountResult voucherResult,
            Integer earnedEcoPoints) {

        String platform = request.getPlatform() != null ? request.getPlatform() : "web";
        PayOSPaymentResponse paymentResponse = payOSPaymentService.createPaymentUrl(
                orderId, totalPrice, platform, true);
        List<OrderItemRequest> orderItemsForRedis = request.getItems().stream()
                .map(item -> OrderItemRequest.builder()
                        .productId(item.getProductId())
                        .productName(item.getProductName())
                        .productImage(item.getProductImage())
                        .price(item.getPrice())
                        .ecoPoint(item.getEcoPoint())
                        .build())
                .collect(Collectors.toList());

        PendingOrderRedis pendingOrder = PendingOrderRedis.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .customerId(request.getCustomerId())
                .eventId(request.getEventId())
                .orderType(OrderType.OFFLINE)
                .paymentMethod(PaymentMethod.BANK_TRANSFER)
                .paymentOrderCode(paymentResponse.getPaymentOrderCode())
                .paymentUrl(paymentResponse.getCheckoutUrl())
                .subTotal(subtotal)
                .discountAmount(discountAmount)
                .totalPrice(totalPrice)
                .voucherUserId(request.getVoucherUserId())
                .voucherCode(voucherResult.getVoucherCode())
                .items(orderItemsForRedis)
                .isGuestPurchase(request.getIsGuestPurchase())
                .guestName(request.getGuestName())
                .guestPhone(request.getGuestPhone())
                .earnedEcoPoints(earnedEcoPoints)
                .note(request.getNote())
                .createdAt(LocalDateTime.now())
                .build();

        try {
            pendingOrderCacheService.savePendingOrder(pendingOrder);
        } catch (Exception e) {
        }
        return OrderOfflineResponse.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .eventId(request.getEventId())
                .customerId(request.getCustomerId())
                .isGuestPurchase(request.getIsGuestPurchase())
                .items(convertToItemResponses(orderItemsForRedis))
                .subtotal(subtotal)
                .discountAmount(discountAmount)
                .totalPrice(totalPrice)
                .voucherCode(voucherResult.getVoucherCode())
                .paymentMethod(PaymentMethod.BANK_TRANSFER.name())
                .earnedEcoPoints(earnedEcoPoints)
                .paymentUrl(paymentResponse.getCheckoutUrl())
                .message("Vui lòng quét mã QR để thanh toán " + totalPrice.longValue() + "đ")
                .createdAt(LocalDateTime.now())
                .createdBy(getCreatedBy())
                .build();
    }


    private void processCompletedOfflineOrder(Order order) {
        markOfflineProductsAsSoldViaFeign(order);
        int totalEcoPoints = order.getEarnedEcoPoints() != null ? order.getEarnedEcoPoints() : 0;
        if (totalEcoPoints > 0 && !Boolean.TRUE.equals(order.getIsGuestPurchase())) {
            addEcoPointsViaFeign(order, totalEcoPoints);
        }
        if (order.getVoucherUserId() != null) {
            markVoucherAsUsedViaFeign(order);
        }
    }

    private void addEcoPointsViaFeign(Order order, int totalEcoPoints) {
        AddEcoPointsRequest request = AddEcoPointsRequest.builder()
                .orderId(order.getOrderId())
                .orderCode(order.getOrderCode())
                .customerId(order.getCustomerId())
                .ecoPoints(totalEcoPoints)
                .orderAmount(order.getTotalPrice())
                .earnedAt(LocalDateTime.now())
                .build();

        try {
            ApiResponseDTO<Void> response = rewardClient.addEcoPoints(request);
            if (!response.isSuccess()) {
                log.error("Failed to add eco points for OFFLINE order: {}", order.getOrderCode());
            } else {
                log.info("Added {} eco points successfully for OFFLINE order: {}",
                        totalEcoPoints, order.getOrderCode());
            }
        } catch (Exception e) {
            log.error("Error calling reward service to add eco points", e);
        }
    }

    private void markOfflineProductsAsSoldViaFeign(Order order) {

        List<MarkOfflineProductsSoldRequest.ProductSold> products = order.getOrderItems().stream()
                .map(item -> MarkOfflineProductsSoldRequest.ProductSold.builder()
                        .productId(item.getProductId())
                        .build())
                .collect(Collectors.toList());

        MarkOfflineProductsSoldRequest request = MarkOfflineProductsSoldRequest.builder()
                .orderId(order.getOrderId())
                .eventId(order.getEventId())
                .products(products)
                .build();

        try {
            ApiResponseDTO<Void> response = productClient.markOfflineProductsAsSold(request);
            if (!response.isSuccess()) {
                log.error("Failed to mark offline products as SOLD for order: {}",
                        order.getOrderCode());
            } else {
                log.info("Marked {} offline products as SOLD and mapping as SOLD_OUT for order: {}",
                        products.size(), order.getOrderCode());
            }
        } catch (Exception e) {
            log.error("Error calling product service to mark offline products as SOLD", e);
        }
    }


    private void markVoucherAsUsedViaFeign(Order order) {
        VoucherUsedRequest request = VoucherUsedRequest.builder()
                .orderId(order.getOrderId())
                .orderCode(order.getOrderCode())
                .customerId(order.getCustomerId())
                .voucherUserId(order.getVoucherUserId())
                .voucherCode(order.getVoucherCode())
                .discountValue(order.getDiscountAmount())
                .usedAt(order.getCreatedAt())
                .build();
        try {
            ApiResponseDTO<Void> response = rewardClient.markVoucherAsUsed(request);
            if (!response.isSuccess()) {
                log.error("Failed to mark voucher as used for offline order: {}",
                        order.getOrderCode());
            } else {
                log.info("Voucher marked as used successfully for offline order: {}",
                        order.getOrderCode());
            }
        } catch (Exception e) {
            log.error("Error calling reward service to mark voucher as used", e);
        }
    }
    private Order buildOfflineOrder(
            String orderId,
            String orderCode,
            CreateOrderOfflineRequest request,
            BigDecimal subtotal,
            BigDecimal totalPrice,
            BigDecimal discountAmount,
            VoucherDiscountResult voucherResult,
            Integer earnedEcoPoints,
            OrderStatus orderStatus,
            PaymentStatus paymentStatus,
            PaymentMethod paymentMethod,
            Long paymentOrderCode) {
        return Order.builder()
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
                .orderStatus(orderStatus)
                .paymentStatus(paymentStatus)
                .paymentMethod(paymentMethod)
                .paymentOrderCode(paymentOrderCode)
                .note(request.getNote())
                .createdAt(LocalDateTime.now())
                .createdBy(getCreatedBy())
                .build();
    }

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
            throw new ProductValidationException();
        }
    }

    private Map<Long, ProductDTO> fetchProductDetailsForOrder(CreateOrderOfflineRequest request) {
        Map<Long, ProductDTO> productDetailsMap = new HashMap<>();

        for (OrderItemOfflineRequest item : request.getItems()) {
            try {
                ApiResponseDTO<ProductDTO> response =
                        productClient.getProductDetailById(item.getProductId());

                if (response.isSuccess() && response.getData() != null) {
                    productDetailsMap.put(item.getProductId(), response.getData());
                } else {
                    log.warn("Failed to fetch product details for productId: {}",
                            item.getProductId());
                    productDetailsMap.put(item.getProductId(),
                            createFallbackProductDTO(item.getProductId()));
                }
            } catch (Exception e) {
                log.error("Error fetching product details for productId: {}",
                        item.getProductId());
                productDetailsMap.put(item.getProductId(),
                        createFallbackProductDTO(item.getProductId()));
            }
        }

        return productDetailsMap;
    }

    private ProductDTO createFallbackProductDTO(Long productId) {
        return ProductDTO.builder()
                .id(productId)
                .ecoPointValue(0)
                .build();
    }

    private void enrichItemsWithEcoPoints(
            List<OrderItemOfflineRequest> items,
            Map<Long, ProductDTO> productDetailsMap) {

        items.forEach(item -> {
            ProductDTO productDTO = productDetailsMap.get(item.getProductId());
            Integer ecoPoint = getEcoPointFromProduct(productDTO);
            item.setEcoPoint(ecoPoint);
        });
    }

    private Integer getEcoPointFromProduct(ProductDTO productDTO) {
        if (productDTO == null || productDTO.getEcoPointValue() == null) {
            return 0;
        }
        return productDTO.getEcoPointValue();
    }

    private Integer calculateEcoPoints(CreateOrderOfflineRequest request) {
        if (Boolean.TRUE.equals(request.getIsGuestPurchase())) {
            return 0;
        }

        return request.getItems().stream()
                .map(OrderItemOfflineRequest::getEcoPoint)
                .filter(Objects::nonNull)
                .reduce(0, Integer::sum);
    }

    private BigDecimal calculateSubtotal(List<OrderItemOfflineRequest> items) {
        return items.stream()
                .map(OrderItemOfflineRequest::getPrice)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
    }

    private String getCreatedBy() {
        Authentication authentication = SecurityContextHolder
                .getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            return authentication.getName();
        }
        return "anonymous";
    }

    private List<OrderItemResponse> convertToItemResponses(List<OrderItemRequest> items) {
        return items.stream()
                .map(item -> OrderItemResponse.builder()
                        .productId(item.getProductId())
                        .productName(item.getProductName())
                        .productImage(item.getProductImage())
                        .price(item.getPrice())
                        .ecoPoint(item.getEcoPoint())
                        .build())
                .collect(Collectors.toList());
    }

    private OrderOfflineResponse buildResponseFromEntity(
            Order order,
            VoucherDiscountResult voucherResult,
            PayOSPaymentResponse paymentResponse) {

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

        OrderOfflineResponse.OrderOfflineResponseBuilder responseBuilder =
                OrderOfflineResponse.builder()
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
                        .createdBy(order.getCreatedBy());

        if (paymentResponse != null) {
            responseBuilder
                    .paymentUrl(paymentResponse.getCheckoutUrl())
                    .message("Vui lòng quét mã QR để thanh toán " +
                            order.getTotalPrice().longValue() + "đ");
        } else {
            responseBuilder
                    .paymentUrl(null)
                    .message("Đơn hàng đã hoàn thành");
        }

        return responseBuilder.build();
    }
}
