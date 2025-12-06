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
import com.greenloop.order.service.CloudinaryService;
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
import org.springframework.web.multipart.MultipartFile;

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
    private final CloudinaryService cloudinaryService;

    @Override
    @Transactional
    public OrderOfflineResponse createOrderOffline(
            CreateOrderOfflineRequest request,
            MultipartFile paymentProofImage) {

        log.info("Creating offline order for event: {}, paymentMethod: {}",
                request.getEventId(), request.getPaymentMethod());

        // 1. Validate products trong event
        validateProductsInEvent(request);

        // 2. Lấy thông tin Product
        Map<Long, ProductDTO> productDetailsMap = fetchProductDetailsForOrder(request);

        // 3. Tính subtotal
        BigDecimal subtotal = calculateSubtotal(request.getItems());

        // 4. Validate và tính discount từ voucher
        VoucherDiscountResult voucherResult =
                voucherDiscountService.validateAndCalculate(
                        request.getVoucherUserId(), subtotal);

        BigDecimal discountAmount = voucherResult.getDiscountAmount();
        BigDecimal totalPrice = subtotal.subtract(discountAmount);

        // 5. Tính eco points
        Integer earnedEcoPoints = calculateEcoPoints(request, productDetailsMap);

        // 6. Upload ảnh bill nếu là BANK_TRANSFER
        String paymentProofImageUrl = null;
        if ("BANK_TRANSFER".equals(request.getPaymentMethod()) && paymentProofImage != null) {
            paymentProofImageUrl = handlePaymentProofUpload(paymentProofImage);
        }

        // 7. Tạo Order
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
                .paymentProofImageUrl(paymentProofImageUrl)
                .note(request.getNote())
                .createdAt(LocalDateTime.now())
                .createdBy(getCreatedBy())
                .build();

        // 8. Tạo OrderItems
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

        // 9. Lưu vào database
        Order savedOrder = orderRepository.save(order);

        log.info("Order created successfully: orderCode={}, totalPrice={}, earnedEcoPoints={}",
                orderCode, totalPrice, earnedEcoPoints);

        // 10. Publish event
        publishOrderOfflineCreatedEvent(savedOrder);

        // 11. Trả response
        return buildResponseFromEntity(savedOrder, voucherResult);
    }

    /**
     * Upload ảnh bill thanh toán lên Cloudinary
     */
    private String handlePaymentProofUpload(MultipartFile file) {
        try {
            Map<String, String> uploadResult = cloudinaryService.uploadImage(
                    file.getBytes(),
                    "GreenLoop/Orders/PaymentProofs"
            );

            String imageUrl = cloudinaryService.getImageUrl(uploadResult.get("asset_id"));

            log.info("Payment proof image uploaded successfully");

            return imageUrl;

        } catch (Exception e) {
            log.error("Failed to upload payment proof image: {}", e.getMessage());
            throw new RuntimeException("Không thể upload ảnh chứng từ thanh toán", e);
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
                    log.warn("Failed to fetch product details for productId: {}", item.getProductId());
                    productDetailsMap.put(item.getProductId(), createFallbackProductDTO(item.getProductId()));
                }
            } catch (Exception e) {
                log.error("Error fetching product details for productId: {}", item.getProductId());
                productDetailsMap.put(item.getProductId(), createFallbackProductDTO(item.getProductId()));
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

    private Integer getEcoPointFromProduct(ProductDTO productDTO) {
        if (productDTO == null || productDTO.getEcoPointValue() == null) {
            return 0;
        }
        return productDTO.getEcoPointValue();
    }

    private Integer calculateEcoPoints(
            CreateOrderOfflineRequest request,
            Map<Long, ProductDTO> productDetailsMap) {

        if (Boolean.TRUE.equals(request.getIsGuestPurchase())) {
            return 0;
        }

        return request.getItems().stream()
                .map(item -> {
                    ProductDTO productDTO = productDetailsMap.get(item.getProductId());
                    return getEcoPointFromProduct(productDTO);
                })
                .reduce(0, Integer::sum);
    }

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

            log.info("Published OrderOfflineCreatedEvent for order: {}", order.getOrderCode());

        } catch (Exception e) {
            log.error("Failed to publish OrderOfflineCreatedEvent for order: {}",
                    order.getOrderCode());
        }
    }

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
                .paymentProofImageUrl(order.getPaymentProofImageUrl())
                .earnedEcoPoints(order.getEarnedEcoPoints())
                .createdAt(order.getCreatedAt())
                .createdBy(order.getCreatedBy())
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
            log.error("Product validation failed for event {}", request.getEventId());
            throw new ProductValidationException();
        }
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
}
