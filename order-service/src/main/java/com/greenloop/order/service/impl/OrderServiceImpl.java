package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.client.UserClient;
import com.greenloop.order.client.RewardClient;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.constant.RoleConstant;
import com.greenloop.order.dto.ParcelDimensionDTO;
import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.event.NotificationEvent;
import com.greenloop.order.dto.feign.UnreserveProductsRequest;
import com.greenloop.order.dto.redis.PendingOrderRedis;
import com.greenloop.order.dto.request.*;
import com.greenloop.order.dto.response.*;
import com.greenloop.order.entity.*;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.*;
import com.greenloop.order.goship.dto.CreateShipmentResponse;
import com.greenloop.order.goship.service.GoShipService;
import com.greenloop.order.repository.CartRepository;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.repository.specification.OrderSpecification;
import com.greenloop.order.service.*;
import com.greenloop.order.util.OrderCodeGenerator;
import com.greenloop.order.util.PageResponseUtil;
import com.greenloop.order.util.ShippingStatusMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Collections;
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
    private final CartService cartService;
    private final PayOSPaymentService payOSPaymentService;
    private final ShippingCalculationService shippingCalculationService;
    private final GoShipService goShipService;
    private final VoucherDiscountService voucherDiscountService;
    private final OrderCodeGenerator orderCodeGenerator;
    private final PendingOrderCacheService pendingOrderCacheService;
    private final WarehouseSettingService warehouseSettingService;
    private final UserClient userClient;
    private final RewardClient rewardClient;
    private final TransactionService transactionService;
    private final NotificationProducer notificationProducer;

    @Override
    @Transactional
    public CheckoutResponse checkout(Long userId, CheckoutRequest request) {
        if (request.getSelectedRateId() == null || request.getSelectedRateId().isBlank()) {
            throw new IllegalArgumentException("Vui lòng chọn đơn vị vận chuyển");
        }
        Cart cart = cartRepository.findByCustomerId(userId)
                .orElseThrow(() -> new CartNotFoundException(userId));
        if (cart.getItems().isEmpty()) {
            throw new EmptyCartException();
        }
        List<OrderItemRequest> orderItems = cart.getItems().stream()
                .map(cartItem -> {
                    ApiResponseDTO<ProductDTO> response = productClient.getProductDetailById(cartItem.getProductId());
                    if (!response.isSuccess() || response.getData() == null) {
                        throw new ProductNotFoundException(cartItem.getProductId());
                    }
                    ProductDTO product = response.getData();
                    if (!ProductStatusConstant.AVAILABLE.equals(product.getStatus())) {
                        throw new ProductNotAvailableException(product.getId());
                    }
                    Integer ecoPoint = product.getEcoPointValue() != null
                            ? product.getEcoPointValue()
                            : 0;
                    return OrderItemRequest.builder()
                            .productId(cartItem.getProductId())
                            .price(cartItem.getPrice())
                            .productName(cartItem.getProductName())
                            .productImage(cartItem.getProductImage())
                            .ecoPoint(ecoPoint)
                            .build();
                })
                .collect(Collectors.toList());
        BigDecimal productTotal = orderItems.stream()
                .map(OrderItemRequest::getPrice)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
        ShippingEstimateResponse estimate = shippingCalculationService.calculateShippingFee(
                cart.getItems(),
                productTotal,
                String.valueOf(request.getShippingAddress().getCityId()),
                String.valueOf(request.getShippingAddress().getDistrictId())
        );

        if (estimate.getAvailableOptions().isEmpty()) {
            throw new ShippingRateNotFoundException("Không tìm thấy đơn vị vận chuyển phù hợp");
        }

        ShippingEstimateResponse.ShippingOption selectedOption = estimate.getAvailableOptions().stream()
                .filter(option -> option.getRateId().equals(request.getSelectedRateId()))
                .findFirst()
                .orElseThrow(() -> new InvalidShippingRateException(request.getSelectedRateId()));

        BigDecimal originalShippingFee = selectedOption.getFee();

        VoucherDiscountResult voucherResult = voucherDiscountService.validateAndCalculateOnline(
                request.getVoucherUserId(),
                productTotal,
                originalShippingFee
        );

        BigDecimal productDiscount = voucherResult.getDiscountAmount() != null
                ? voucherResult.getDiscountAmount()
                : BigDecimal.ZERO;

        BigDecimal shippingDiscount = voucherResult.getShippingDiscount() != null
                ? voucherResult.getShippingDiscount()
                : BigDecimal.ZERO;

        BigDecimal finalShippingFee = originalShippingFee.subtract(shippingDiscount);
        if (finalShippingFee.compareTo(BigDecimal.ZERO) < 0) {
            finalShippingFee = BigDecimal.ZERO;
        }

        BigDecimal subtotalAfterDiscount = productTotal.subtract(productDiscount);

        BigDecimal totalPrice = subtotalAfterDiscount.add(finalShippingFee);

        LocalDateTime expectedDeliveryTime;
        try {
            String numberStr = selectedOption.getEstimatedDelivery().replaceAll("[^0-9]", "");
            if (!numberStr.isEmpty()) {
                int days = Integer.parseInt(numberStr);
                expectedDeliveryTime = LocalDateTime.now().plusDays(days);
            } else {
                expectedDeliveryTime = LocalDateTime.now().plusDays(3);
            }
        } catch (Exception e) {
            log.warn("Failed to parse delivery time: {}", selectedOption.getEstimatedDelivery());
            expectedDeliveryTime = LocalDateTime.now().plusDays(3);
        }

        ParcelDimensionDTO parcelDimensions = shippingCalculationService
                .calculateParcelDimensions(cart.getItems());
        String orderId = UUID.randomUUID().toString();
        String orderCode = orderCodeGenerator.generateOrderOnlineCode();
        CheckoutResponse.CheckoutResponseBuilder responseBuilder = CheckoutResponse.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .productTotal(productTotal)
                .originalShippingFee(originalShippingFee)
                .productDiscount(productDiscount)
                .shippingDiscount(shippingDiscount)
                .discountAmount(productDiscount.add(shippingDiscount))
                .voucherCode(voucherResult.getVoucherCode())
                .isFreeShip(voucherResult.getIsFreeShip())
                .subtotalAfterDiscount(subtotalAfterDiscount)
                .shippingFee(finalShippingFee)
                .totalPrice(totalPrice)
                .selectedCarrier(selectedOption.getCarrierName())
                .estimatedDelivery(selectedOption.getEstimatedDelivery())
                .createdAt(LocalDateTime.now());

        if (request.getPaymentMethod() == PaymentMethod.COD) {
            handleCODCheckout(
                    userId, orderId, orderCode, request, orderItems,
                    productTotal, finalShippingFee, totalPrice,
                    productDiscount.add(shippingDiscount), voucherResult,
                    selectedOption, expectedDeliveryTime, parcelDimensions, false
            );

            String message = String.format(
                    "Đặt hàng thành công! Tổng thanh toán: %,dđ khi nhận hàng.",
                    totalPrice.longValue()
            );

            responseBuilder.paymentUrl(null).message(message);

        } else if (request.getPaymentMethod() == PaymentMethod.PAYOS) {
            String paymentUrl = handlePayOSCheckout(
                    userId, orderId, orderCode, request, orderItems,
                    productTotal, finalShippingFee, totalPrice,
                    productDiscount.add(shippingDiscount), voucherResult,
                    selectedOption, expectedDeliveryTime, parcelDimensions
            );

            String message = String.format(
                    "Vui lòng thanh toán %,dđ để hoàn tất đơn hàng.",
                    totalPrice.longValue()
            );

            responseBuilder.paymentUrl(paymentUrl).message(message);
        }

        return responseBuilder.build();
    }


    @Override
    @Transactional
    public Order buildAndSaveOrder(CreateOrderRequest request) {
        if (request.getTotalPrice().compareTo(BigDecimal.ZERO) <= 0) {
            throw new InvalidOrderPriceException();
        }
        Order order = Order.builder()
                .orderId(request.getOrderId())
                .orderCode(request.getOrderCode())
                .customerId(request.getCustomerId())
                .subTotal(request.getSubTotal())
                .discountAmount(request.getDiscountAmount())
                .originalShippingFee(request.getOriginalShippingFee())
                .totalPrice(request.getTotalPrice())
                .shippingFee(request.getShippingFee())
                .voucherUserId(request.getVoucherUserId())
                .voucherCode(request.getVoucherCode())
                .orderStatus(request.getOrderStatus())
                .paymentStatus(request.getPaymentStatus())
                .paymentMethod(request.getPaymentMethod())
                .paymentOrderCode(request.getPaymentOrderCode())
                .paymentTransactionId(request.getPaymentTransactionId())
                .selectedRateId(request.getSelectedRateId())
                .orderType(OrderType.ONLINE)
                .carrier(request.getCarrier())
                .expectedDeliveryTime(request.getExpectedDeliveryTime())
                .shippingStatus(request.getShippingStatus())
                .parcelWeight(request.getParcelWeight())
                .parcelWidth(request.getParcelWidth())
                .parcelHeight(request.getParcelHeight())
                .parcelLength(request.getParcelLength())
                .createdAt(LocalDateTime.now())
                .build();
        if (request.getShippingAddress() != null) {
            WarehouseSetting warehouse = warehouseSettingService.getWarehouse();
            ShippingAddress shippingAddress = ShippingAddress.builder()
                    .receiverName(request.getShippingAddress().getReceiverName())
                    .receiverPhone(request.getShippingAddress().getReceiverPhone())
                    .receiverAddress(request.getShippingAddress().getAddress())
                    .receiverWardCode(request.getShippingAddress().getWardCode())
                    .receiverWardName(request.getShippingAddress().getWard())
                    .receiverDistrictName(request.getShippingAddress().getDistrictName())
                    .receiverCityName(request.getShippingAddress().getCityName())
                    .receiverDistrictId(request.getShippingAddress().getDistrictId())
                    .receiverCityId(request.getShippingAddress().getCityId())
                    .note(request.getShippingAddress().getNote())
                    .warehouseName(warehouse.getName())
                    .warehousePhone(warehouse.getPhone())
                    .warehouseAddress(warehouse.getAddress())
                    .warehouseWardCode(warehouse.getWardCode())
                    .warehouseWardName(warehouse.getWardName())
                    .warehouseDistrictId(warehouse.getDistrictId())
                    .warehouseDistrictName(warehouse.getDistrictName())
                    .warehouseCityName(warehouse.getCityName())
                    .warehouseCityId(warehouse.getCityId())
                    .build();
            order.setShippingAddress(shippingAddress);
        }
        if (request.getOrderItems() != null && !request.getOrderItems().isEmpty()) {
            List<OrderItem> orderItems = request.getOrderItems().stream()
                    .map(itemReq -> OrderItem.builder()
                            .productId(itemReq.getProductId())
                            .price(itemReq.getPrice())
                            .productName(itemReq.getProductName())
                            .productImage(itemReq.getProductImage())
                            .ecoPoint(itemReq.getEcoPoint())
                            .order(order)
                            .build())
                    .collect(Collectors.toList());
            order.setOrderItems(orderItems);
        }
        Order savedOrder = orderRepository.save(order);
        return savedOrder;
    }

    @Override
    @Transactional(readOnly = true)
    public OrderResponse getOrderById(String orderId) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));

        return mapToOrderResponse(order);
    }

    @Override
    @Transactional(readOnly = true)
    public PageResponseDTO<OrderResponse> getAllOrders(Long requestingUserId, OrderFilterRequest filter) {
        Specification<Order> spec = OrderSpecification.filterOrders(requestingUserId, filter);
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
        Page<Order> orderPage = orderRepository.findAll(spec, pageable);
        Page<OrderResponse> responsePage = orderPage.map(this::mapToOrderResponse);
        return PageResponseUtil.toPageResponse(responsePage);
    }

    @Override
    @Transactional
    public ShipmentInfoResponse shipOrder(String orderId, CreateShipmentRequestDTO request) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));
        OrderStatus oldStatus = order.getOrderStatus();
        if (!oldStatus.canTransitionTo(OrderStatus.READY_TO_SHIP)) {
            throw new InvalidOrderStatusException(
                    oldStatus.getDescription(),
                    OrderStatus.READY_TO_SHIP.getDescription()
            );
        }
        CreateShipmentResponse shipmentResponse = goShipService.createShipmentForOrder(orderId, request);
        order.setOrderStatus(OrderStatus.READY_TO_SHIP);
        order.setGoshipShipmentId(shipmentResponse.getId());
        order.setGoshipTrackingUrl(shipmentResponse.getTrackingNumber());
        order.setCarrier(shipmentResponse.getCarrier());
        order.setUpdatedAt(LocalDateTime.now());
        order.setShippingStatus(901);
        orderRepository.save(order);
        if (order.getCustomerId() != null) {
            try {
                notificationProducer.sendNotificationMessage(
                        NotificationEvent.builder()
                                .userId(order.getCustomerId())
                                .title(String.format("Đơn hàng %s sẵn sàng giao", order.getOrderCode()))
                                .message(String.format("Đơn hàng %s đã sẵn sàng để giao. Đơn vị vận chuyển %s sẽ sớm lấy hàng.",
                                        order.getOrderCode(), shipmentResponse.getCarrier()))
                                .build()
                );
                log.info("Sent notification for order {} status change to READY_TO_SHIP", order.getOrderCode());
            } catch (Exception e) {
                log.error("Failed to send notification for order {}", order.getOrderCode(), e);
            }
        }
        return ShipmentInfoResponse.builder()
                .shipmentId(shipmentResponse.getId())
                .trackingNumber(shipmentResponse.getTrackingNumber())
                .carrier(shipmentResponse.getCarrier())
                .fee(shipmentResponse.getFee())
                .createdAt(shipmentResponse.getCreatedAt())
                .build();
    }

    @Override
    @Transactional
    public void completeOrder(String orderId, String reason) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));
        OrderStatus oldStatus = order.getOrderStatus();
        if (!oldStatus.canTransitionTo(OrderStatus.COMPLETED)) {
            throw new InvalidOrderStatusException(
                    oldStatus.getDescription(),
                    OrderStatus.COMPLETED.getDescription());
        }
        completeOrderInternal(order, "STAFF:" + (reason != null ? reason : "No reason"));
    }

    @Override
    @Transactional
    public void completeOrderByCustomer(String orderId, Long customerId) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));
        if (!order.getCustomerId().equals(customerId)) {
            throw new UnauthorizedOrderAccessException(orderId, customerId);
        }
        if (order.getOrderStatus() != OrderStatus.DELIVERED) {
            throw new InvalidOrderStatusException(
                    order.getOrderStatus().getDescription(),
                    "Chỉ có thể hoàn thành đơn hàng ở trạng thái Đã giao hàng"
            );
        }
        if (order.getDeliveredAt() == null) {
            throw new OrderNotDeliveredException(orderId);
        }
        LocalDateTime deadline = order.getDeliveredAt().plusDays(7);
        LocalDateTime now = LocalDateTime.now();
        if (now.isAfter(deadline)) {
            throw new OrderCompletionExpiredException(orderId, 7);
        }
        completeOrderInternal(order, "CUSTOMER:" + customerId);
    }


    @Override
    @Transactional
    public void completeOrderInternal(Order order, String completedBy) {
        int totalEcoPoints = order.getOrderItems().stream()
                .mapToInt(item -> item.getEcoPoint() != null ? item.getEcoPoint() : 0)
                .sum();
        order.setEarnedEcoPoints(totalEcoPoints);
        order.setOrderStatus(OrderStatus.COMPLETED);
        order.setCompletedAt(LocalDateTime.now());
        order.setCanCreateReturnRequest(false);
        order.setUpdatedAt(LocalDateTime.now());
        orderRepository.save(order);
        transactionService.createTransactionForOnlineOrder(order);
        markProductsAsSoldViaFeign(order);
        if (totalEcoPoints > 0) {
            addEcoPointsViaFeign(order, totalEcoPoints);
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
                log.error("Failed to add eco points for order: {}", order.getOrderCode());
            } else {
                log.info("Added {} eco points successfully for order: {}",
                        totalEcoPoints, order.getOrderCode());
            }
        } catch (Exception e) {
            log.error("Error calling reward service to add eco points", e);
        }
    }

    @Override
    @Transactional
    public void processOrder(String orderId, String reason) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));
        OrderStatus oldStatus = order.getOrderStatus();
        if (!oldStatus.canTransitionTo(OrderStatus.PROCESSING)) {
            throw new InvalidOrderStatusException(
                    oldStatus.getDescription(),
                    OrderStatus.PROCESSING.getDescription()
            );
        }
        order.setOrderStatus(OrderStatus.PROCESSING);
        order.setUpdatedAt(LocalDateTime.now());
        orderRepository.save(order);
        if (order.getCustomerId() != null) {
            try {
                notificationProducer.sendNotificationMessage(
                        NotificationEvent.builder()
                                .userId(order.getCustomerId())
                                .title(String.format("Đơn hàng %s đang được xử lý", order.getOrderCode()))
                                .message(String.format("Đơn hàng %s đang được xử lý. Chúng tôi sẽ sớm giao hàng cho bạn.",
                                        order.getOrderCode()))
                                .build()
                );
                log.info("Sent notification for order {} status change to PROCESSING", order.getOrderCode());
            } catch (Exception e) {
                log.error("Failed to send notification for order {}", order.getOrderCode(), e);
            }
        }

    }

    @Override
    @Transactional
    public void confirmOrder(String orderId, String reason) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));
        OrderStatus oldStatus = order.getOrderStatus();
        if (!oldStatus.canTransitionTo(OrderStatus.CONFIRMED)) {
            throw new InvalidOrderStatusException(
                    oldStatus.getDescription(),
                    OrderStatus.CONFIRMED.getDescription()
            );
        }
        order.setOrderStatus(OrderStatus.CONFIRMED);
        order.setUpdatedAt(LocalDateTime.now());
        orderRepository.save(order);
        if (order.getCustomerId() != null) {
            try {
                notificationProducer.sendNotificationMessage(
                        NotificationEvent.builder()
                                .userId(order.getCustomerId())
                                .title(String.format("Đơn hàng %s đã được xác nhận", order.getOrderCode()))
                                .message(String.format("Đơn hàng %s đã được xác nhận. Chúng tôi đang chuẩn bị sản phẩm cho bạn.",
                                        order.getOrderCode()))
                                .build()
                );
                log.info("Sent notification for order {} status change to CONFIRMED", order.getOrderCode());
            } catch (Exception e) {
                log.error("Failed to send notification for order {}", order.getOrderCode(), e);
            }
        }
    }

    @Override
    @Transactional
    public void cancelOrder(String orderId, String reason, Long requestingUserId, String userRole) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));
        OrderStatus oldStatus = order.getOrderStatus();
        validateCancelPermission(order, oldStatus, requestingUserId, userRole);
        if (!oldStatus.canTransitionTo(OrderStatus.CANCELLED)) {
            throw new InvalidOrderStatusException(
                    oldStatus.getDescription(),
                    OrderStatus.CANCELLED.getDescription()
            );
        }
        order.setOrderStatus(OrderStatus.CANCELLED);
        order.setUpdatedAt(LocalDateTime.now());
        orderRepository.save(order);
        unreserveProductsViaFeign(order);
    }


    @Override
    @Transactional
    public CheckoutResponse directCheckout(Long userId, DirectCheckoutRequest request) {
        ProductDTO product = validateAndGetProduct(request.getProductId());
        OrderItemRequest orderItem = buildOrderItemFromProduct(product);
        List<OrderItemRequest> orderItems = Collections.singletonList(orderItem);
        BigDecimal productTotal = product.getPrice();
        CartItem tempCartItem = buildTempCartItemFromProduct(product);
        List<CartItem> tempCartItems = Collections.singletonList(tempCartItem);
        ShippingEstimateResponse estimate = shippingCalculationService.calculateShippingFee(
                tempCartItems,
                productTotal,
                String.valueOf(request.getShippingAddress().getCityId()),
                String.valueOf(request.getShippingAddress().getDistrictId())
        );
        if (estimate.getAvailableOptions().isEmpty()) {
            throw new ShippingRateNotFoundException("Không tìm thấy đơn vị vận chuyển phù hợp");
        }
        ShippingEstimateResponse.ShippingOption selectedOption = estimate.getAvailableOptions().stream()
                .filter(option -> option.getRateId().equals(request.getSelectedRateId()))
                .findFirst()
                .orElseThrow(() -> new InvalidShippingRateException(request.getSelectedRateId()));
        BigDecimal originalShippingFee = selectedOption.getFee();
        VoucherDiscountResult voucherResult = voucherDiscountService.validateAndCalculateOnline(
                request.getVoucherUserId(),
                productTotal,
                originalShippingFee
        );

        BigDecimal productDiscount = voucherResult.getDiscountAmount() != null
                ? voucherResult.getDiscountAmount()
                : BigDecimal.ZERO;
        BigDecimal shippingDiscount = voucherResult.getShippingDiscount() != null
                ? voucherResult.getShippingDiscount()
                : BigDecimal.ZERO;
        BigDecimal finalShippingFee = originalShippingFee.subtract(shippingDiscount);
        if (finalShippingFee.compareTo(BigDecimal.ZERO) < 0) {
            finalShippingFee = BigDecimal.ZERO;
        }
        BigDecimal subtotalAfterDiscount = productTotal.subtract(productDiscount);
        BigDecimal totalPrice = subtotalAfterDiscount.add(finalShippingFee);
        LocalDateTime expectedDeliveryTime = calculateExpectedDeliveryTime(
                selectedOption.getEstimatedDelivery());
        ParcelDimensionDTO parcelDimensions = shippingCalculationService
                .calculateParcelDimensions(tempCartItems);
        String orderId = UUID.randomUUID().toString();
        String orderCode = orderCodeGenerator.generateOrderOnlineCode();
        CheckoutResponse.CheckoutResponseBuilder responseBuilder = CheckoutResponse.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .productTotal(productTotal)
                .originalShippingFee(originalShippingFee)
                .productDiscount(productDiscount)
                .shippingDiscount(shippingDiscount)
                .discountAmount(productDiscount.add(shippingDiscount))
                .voucherCode(voucherResult.getVoucherCode())
                .isFreeShip(voucherResult.getIsFreeShip())
                .subtotalAfterDiscount(subtotalAfterDiscount)
                .shippingFee(finalShippingFee)
                .totalPrice(totalPrice)
                .selectedCarrier(selectedOption.getCarrierName())
                .estimatedDelivery(selectedOption.getEstimatedDelivery())
                .createdAt(LocalDateTime.now());
        if (request.getPaymentMethod() == PaymentMethod.COD) {
            handleCODCheckout(
                    userId, orderId, orderCode,
                    convertToCheckoutRequest(request),
                    orderItems, productTotal, finalShippingFee, totalPrice,
                    productDiscount.add(shippingDiscount),
                    voucherResult, selectedOption, expectedDeliveryTime, parcelDimensions, true
            );
            String message = String.format("Đặt hàng thành công! Tổng thanh toán: %,d đ khi nhận hàng.",
                    totalPrice.longValue());
            responseBuilder.paymentUrl(null).message(message);

        } else if (request.getPaymentMethod() == PaymentMethod.PAYOS) {
            String paymentUrl = handlePayOSCheckout(
                    userId, orderId, orderCode,
                    convertToCheckoutRequest(request),
                    orderItems, productTotal, finalShippingFee, totalPrice,
                    productDiscount.add(shippingDiscount),
                    voucherResult, selectedOption, expectedDeliveryTime, parcelDimensions
            );
            String message = String.format("Vui lòng thanh toán %,d đ để hoàn tất đơn hàng.",
                    totalPrice.longValue());
            responseBuilder.paymentUrl(paymentUrl).message(message);
        }
        return responseBuilder.build();
    }


    @Override
    public ShippingEstimateResponse estimateShippingForDirectCheckout(
            DirectShippingEstimateRequest request) {
        ProductDTO product = validateAndGetProduct(request.getProductId());
        CartItem tempCartItem = buildTempCartItemFromProduct(product);
        return shippingCalculationService.calculateShippingFee(
                Collections.singletonList(tempCartItem),
                product.getPrice(),
                String.valueOf(request.getCityId()),
                String.valueOf(request.getDistrictId())
        );
    }

    private OrderResponse mapToOrderResponse(Order order) {
        OrderResponse response = OrderResponse.builder()
                .orderId(order.getOrderId())
                .orderCode(order.getOrderCode())
                .customerId(order.getCustomerId())
                .subTotal(order.getSubTotal())
                .discountAmount(order.getDiscountAmount())
                .voucherCode(order.getVoucherCode())
                .totalPrice(order.getTotalPrice())
                .shippingFee(order.getShippingFee())
                .orderStatus(order.getOrderStatus())
                .paymentStatus(order.getPaymentStatus())
                .paymentMethod(order.getPaymentMethod())
                .guestName(order.getGuestName())
                .guestPhone(order.getGuestPhone())
                .isGuestPurchase(order.getIsGuestPurchase())
                .orderType(order.getOrderType())
                .paymentOrderCode(order.getPaymentOrderCode())
                .paymentTransactionId(order.getPaymentTransactionId())
                .carrier(order.getCarrier())
                .expectedDeliveryTime(order.getExpectedDeliveryTime())
                .shippingStatus(order.getShippingStatus())
                .goshipShipmentId(order.getGoshipShipmentId())
                .shippingStatusText(ShippingStatusMapper.getStatusText(order.getShippingStatus()))
                .goshipTrackingUrl(order.getGoshipTrackingUrl())
                .createdAt(order.getCreatedAt())
                .updatedAt(order.getUpdatedAt())
                .deliveredAt(order.getDeliveredAt())
                .completedAt(order.getCompletedAt())
                .earnedEcoPoints(order.getEarnedEcoPoints())
                .eventId(order.getEventId())
                .build();

        calculateReturnRequestEligibility(order, response);

        if (order.getCustomerId() != null) {
            try {
                ApiResponseDTO<UserProfileResponse> userResponse =
                        userClient.getUserDetailById(order.getCustomerId());

                if (userResponse.isSuccess() && userResponse.getData() != null) {
                    response.setCustomerInfo(userResponse.getData());
                }
            } catch (Exception e) {
                log.warn("Failed to fetch customer info for customerId {}: {}",
                        order.getCustomerId(), e.getMessage());
            }
        }

        if (order.getShippingAddress() != null) {
            ShippingAddressResponse addressDTO = ShippingAddressResponse.builder()
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

        if (order.getOrderItems() != null && !order.getOrderItems().isEmpty()) {
            List<OrderItemResponse> itemDTOs = order.getOrderItems().stream()
                    .map(item -> OrderItemResponse.builder()
                            .orderItemId(item.getOrderItemId())
                            .productId(item.getProductId())
                            .price(item.getPrice())
                            .productName(item.getProductName())
                            .productImage(item.getProductImage())
                            .ecoPoint(item.getEcoPoint())
                            .build())
                    .collect(Collectors.toList());

            response.setOrderItems(itemDTOs);
        }

        return response;
    }

    private void calculateReturnRequestEligibility(Order order, OrderResponse response) {
        response.setCanCreateReturnRequest(false);
        response.setRemainingReturnHours(null);
        if (order.getOrderStatus() != OrderStatus.DELIVERED) {
            return;
        }

        if (order.getDeliveredAt() == null) {
            return;
        }

        if (order.getCanCreateReturnRequest() == null || !order.getCanCreateReturnRequest()) {
            return;
        }

        LocalDateTime deadline = order.getDeliveredAt().plusDays(7);
        LocalDateTime now = LocalDateTime.now();

        if (now.isAfter(deadline)) {
            return;
        }

        response.setCanCreateReturnRequest(true);

        long remainingHours = java.time.Duration.between(now, deadline).toHours();
        response.setRemainingReturnHours(remainingHours);
    }



    private ProductDTO validateAndGetProduct(Long productId) {
        ApiResponseDTO<ProductDTO> response = productClient.getProductDetailById(productId);

        if (!response.isSuccess() || response.getData() == null) {
            throw new ProductNotFoundException(productId);
        }

        ProductDTO product = response.getData();

        if (!ProductStatusConstant.AVAILABLE.equals(product.getStatus())) {
            throw new ProductNotAvailableException(product.getId());
        }

        return product;
    }

    private OrderItemRequest buildOrderItemFromProduct(ProductDTO product) {
        Integer ecoPoint = product.getEcoPointValue() != null ? product.getEcoPointValue() : 0;

        String productImage = null;
        if (product.getImageUrls() != null && !product.getImageUrls().isEmpty()) {
            ProductDTO.ProductAssetDTO asset = product.getImageUrls().get(0);
            if (asset != null) {
                productImage = asset.getProductAssetUrl();
            }
        }

        return OrderItemRequest.builder()
                .productId(product.getId())
                .price(product.getPrice())
                .productName(product.getName())
                .productImage(productImage)
                .ecoPoint(ecoPoint)
                .build();
    }


    private CartItem buildTempCartItemFromProduct(ProductDTO product) {
        String productImage = null;
        if (product.getImageUrls() != null && !product.getImageUrls().isEmpty()) {
            ProductDTO.ProductAssetDTO asset = product.getImageUrls().get(0);
            if (asset != null) {
                productImage = asset.getProductAssetUrl();
            }
        }

        return CartItem.builder()
                .productId(product.getId())
                .price(product.getPrice())
                .productName(product.getName())
                .productImage(productImage)
                .weight(product.getWeight())
                .width(product.getWidth())
                .height(product.getHeight())
                .length(product.getLength())
                .build();
    }


    private CheckoutRequest convertToCheckoutRequest(DirectCheckoutRequest directRequest) {
        return CheckoutRequest.builder()
                .selectedRateId(directRequest.getSelectedRateId())
                .shippingAddress(directRequest.getShippingAddress())
                .voucherUserId(directRequest.getVoucherUserId())
                .paymentMethod(directRequest.getPaymentMethod())
                .platform(directRequest.getPlatform())
                .build();
    }

    private LocalDateTime calculateExpectedDeliveryTime(String estimatedDelivery) {
        try {
            String numberStr = estimatedDelivery.replaceAll("[^0-9]", "");
            if (!numberStr.isEmpty()) {
                int days = Integer.parseInt(numberStr);
                return LocalDateTime.now().plusDays(days);
            }
        } catch (Exception e) {
            log.warn("Failed to parse delivery time: {}", estimatedDelivery);
        }
        return LocalDateTime.now().plusDays(3);
    }

    private void validateCancelPermission(Order order, OrderStatus currentStatus,
                                          Long requestingUserId, String userRole) {

        boolean isStaffOrAbove = RoleConstant.ROLE_STAFF.equals(userRole) ||
                RoleConstant.ROLE_MANAGER.equals(userRole) ||
                RoleConstant.ROLE_ADMIN.equals(userRole);

        if (order.getPaymentMethod() == PaymentMethod.PAYOS &&
                order.getPaymentStatus() == PaymentStatus.PAID) {

            if (!isStaffOrAbove) {
                throw new UnauthorizedCancelException(
                        "Đơn hàng đã thanh toán. Chỉ nhân viên mới có thể hủy để xử lý hoàn tiền. " +
                                "Vui lòng liên hệ hotline để được hỗ trợ."
                );
            }
        }

        if (currentStatus == OrderStatus.CONFIRMED ||
                currentStatus == OrderStatus.PROCESSING ||
                currentStatus == OrderStatus.READY_TO_SHIP ||
                currentStatus == OrderStatus.SHIPPING ||
                currentStatus == OrderStatus.DELIVERING ||
                currentStatus == OrderStatus.DELIVERED ||
                currentStatus == OrderStatus.DELIVERY_FAILED ||
                currentStatus == OrderStatus.RETURNING) {

            if (!isStaffOrAbove) {
                throw new UnauthorizedCancelException(
                        "Đơn hàng đã được xác nhận. Chỉ nhân viên mới có thể hủy. " +
                                "Vui lòng liên hệ hotline để được hỗ trợ."
                );
            }
        }

        if (currentStatus == OrderStatus.PENDING) {
            if (RoleConstant.ROLE_CUSTOMER.equals(userRole)) {
                if (!order.getCustomerId().equals(requestingUserId)) {
                    throw new UnauthorizedCancelException(
                            "Bạn không có quyền hủy đơn hàng này"
                    );
                }
            }
        }
    }

    private void reserveProductsViaFeign(Order order) {
        log.info("Reserving products via Feign for order {}", order.getOrderId());

        List<ReserveProductsRequest.ProductReserve> products = order.getOrderItems().stream()
                .map(item -> ReserveProductsRequest.ProductReserve.builder()
                        .productId(item.getProductId())
                        .build())
                .collect(Collectors.toList());

        ReserveProductsRequest request = ReserveProductsRequest.builder()
                .orderId(order.getOrderId())
                .customerId(order.getCustomerId())
                .products(products)
                .build();

        try {
            ApiResponseDTO<Void> response = productClient.reserveProducts(request);
            if (!response.isSuccess()) {
                log.error("Failed to reserve products for order {}", order.getOrderId());
                throw new RuntimeException("Không thể reserve sản phẩm");
            }
            log.info("Reserved {} products for order {}", products.size(), order.getOrderId());
        } catch (Exception e) {
            log.error("Error calling product service to reserve products", e);
            throw new RuntimeException("Lỗi khi gọi Product Service", e);
        }

        // Nếu có voucher, gọi Reward Service qua Feign
        if (order.getVoucherUserId() != null) {
            markVoucherAsUsedViaFeign(order);
        }
    }

    private void unreserveProductsViaFeign(Order order) {
        List<Long> productIds = order.getOrderItems().stream()
                .map(OrderItem::getProductId)
                .collect(Collectors.toList());

        UnreserveProductsRequest request = UnreserveProductsRequest.builder()
                .orderId(order.getOrderId())
                .productIds(productIds)
                .build();

        try {
            ApiResponseDTO<Void> response = productClient.unreserveProducts(request);
            if (!response.isSuccess()) {
            }
        } catch (Exception e) {
        }
    }

    private void markVoucherAsUsedViaFeign(Order order) {
        log.info("Marking voucher as used via Feign for order: {}, voucherUserId: {}",
                order.getOrderId(), order.getVoucherUserId());

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
                log.error("Failed to mark voucher as used for order {}", order.getOrderId());
            } else {
                log.info("Voucher marked as used successfully via Feign for voucherUserId: {}",
                        order.getVoucherUserId());
            }
        } catch (Exception e) {
            log.error("Error calling reward service to mark voucher as used", e);
        }
    }


    private void markProductsAsSoldViaFeign(Order order) {
        log.info("Marking products as SOLD via Feign for order {}", order.getOrderId());

        List<MarkProductsSoldRequest.ProductSold> products = order.getOrderItems().stream()
                .map(item -> MarkProductsSoldRequest.ProductSold.builder()
                        .productId(item.getProductId())
                        .ecoPointValue(item.getEcoPoint() != null ? item.getEcoPoint() : 0)
                        .build())
                .collect(Collectors.toList());

        MarkProductsSoldRequest request = MarkProductsSoldRequest.builder()
                .orderId(order.getOrderId())
                .products(products)
                .build();

        try {
            ApiResponseDTO<Void> response = productClient.markProductsAsSold(request);
            if (!response.isSuccess()) {
                log.error("Failed to mark products as SOLD for order {}", order.getOrderId());
            }
        } catch (Exception e) {
            log.error("Error calling product service to mark as sold", e);
        }
    }

    private void handleCODCheckout(
            Long userId,
            String orderId,
            String orderCode,
            CheckoutRequest request,
            List<OrderItemRequest> orderItems,
            BigDecimal productTotal,
            BigDecimal shippingFee,
            BigDecimal totalPrice,
            BigDecimal discountAmount,
            VoucherDiscountResult voucherResult,
            ShippingEstimateResponse.ShippingOption selectedOption,
            LocalDateTime expectedDeliveryTime,
            ParcelDimensionDTO parcelDimensions, Boolean directCheckout) {
        CreateOrderRequest orderRequest = CreateOrderRequest.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .customerId(userId)
                .subTotal(productTotal)
                .discountAmount(discountAmount)
                .totalPrice(totalPrice)
                .shippingFee(shippingFee)
                .voucherUserId(request.getVoucherUserId())
                .originalShippingFee(selectedOption.getFee())
                .voucherCode(voucherResult.getVoucherCode())
                .orderStatus(OrderStatus.PENDING)
                .paymentStatus(PaymentStatus.UNPAID)
                .orderItems(orderItems)
                .shippingAddress(request.getShippingAddress())
                .paymentMethod(PaymentMethod.COD)
                .selectedRateId(request.getSelectedRateId())
                .carrier(selectedOption.getCarrierName())
                .expectedDeliveryTime(expectedDeliveryTime)
                .parcelWeight(String.valueOf(parcelDimensions.getWeight()))
                .parcelWidth(String.valueOf(parcelDimensions.getWidth()))
                .parcelHeight(String.valueOf(parcelDimensions.getHeight()))
                .parcelLength(String.valueOf(parcelDimensions.getLength()))
                .shippingStatus(900)
                .build();

        Order createdOrder = buildAndSaveOrder(orderRequest);

        reserveProductsViaFeign(createdOrder);

        if(!directCheckout){
            cartService.clearCart(userId);
        }

    }

    private String handlePayOSCheckout(
            Long userId,
            String orderId,
            String orderCode,
            CheckoutRequest request,
            List<OrderItemRequest> orderItems,
            BigDecimal productTotal,
            BigDecimal shippingFee,
            BigDecimal totalPrice,
            BigDecimal discountAmount,
            VoucherDiscountResult voucherResult,
            ShippingEstimateResponse.ShippingOption selectedOption,
            LocalDateTime expectedDeliveryTime,
            ParcelDimensionDTO parcelDimensions) {
        String platform = request.getPlatform() != null ? request.getPlatform() : "web";
        PayOSPaymentResponse paymentResponse = payOSPaymentService.createPaymentUrl(
                orderId, totalPrice, platform, false);

        PendingOrderRedis pendingOrder = PendingOrderRedis.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .customerId(userId)
                .orderType(OrderType.ONLINE)
                .paymentMethod(PaymentMethod.PAYOS)
                .paymentOrderCode(paymentResponse.getPaymentOrderCode())
                .paymentUrl(paymentResponse.getCheckoutUrl())
                .subTotal(productTotal)
                .discountAmount(discountAmount)
                .totalPrice(totalPrice)
                .originalShippingFee(selectedOption.getFee())
                .shippingFee(shippingFee)
                .voucherUserId(request.getVoucherUserId())
                .voucherCode(voucherResult.getVoucherCode())
                .items(orderItems)
                .shippingAddress(request.getShippingAddress())
                .selectedRateId(request.getSelectedRateId())
                .carrier(selectedOption.getCarrierName())
                .expectedDeliveryTime(expectedDeliveryTime)
                .parcelWeight(String.valueOf(parcelDimensions.getWeight()))
                .parcelWidth(String.valueOf(parcelDimensions.getWidth()))
                .parcelHeight(String.valueOf(parcelDimensions.getHeight()))
                .parcelLength(String.valueOf(parcelDimensions.getLength()))
                .shippingStatus(900)
                .createdAt(LocalDateTime.now())
                .build();

        pendingOrderCacheService.savePendingOrder(pendingOrder);
        return paymentResponse.getCheckoutUrl();

    }


}
