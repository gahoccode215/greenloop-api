package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.client.UserClient;
import com.greenloop.order.client.RewardClient;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.ParcelDimensionDTO;
import com.greenloop.order.dto.ProductDTO;
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

    @Override
    @Transactional
    public void updateOrderStatus(String orderId, OrderStatus newStatus) {
        orderRepository.findById(orderId).ifPresent(order -> {
            order.setOrderStatus(newStatus);
            orderRepository.save(order);
        });
    }

    @Override
    @Transactional
    public CheckoutResponse checkout(Long userId, CheckoutRequest request) {
        // Bắt buộc phải chọn gói vận chuyển (rate)
        if (request.getSelectedRateId() == null || request.getSelectedRateId().isBlank()) {
            throw new IllegalArgumentException("Vui lòng chọn đơn vị vận chuyển");
        }

        // Lấy giỏ hàng của user
        Cart cart = cartRepository.findByCustomerId(userId)
                .orElseThrow(() -> new CartNotFoundException(userId));

        // Giỏ hàng trống thì không cho checkout
        if (cart.getItems().isEmpty()) {
            throw new EmptyCartException();
        }

        // 1. VALIDATE TỪNG SẢN PHẨM VÀ TÍNH TỔNG TIỀN HÀNG

        List<OrderItemRequest> orderItems = cart.getItems().stream()
                .map(cartItem -> {
                    // 2.1. Gọi Product Service để lấy chi tiết sản phẩm
                    ApiResponseDTO<ProductDTO> response = productClient.getProductDetailById(cartItem.getProductId());

                    // 2.2. Nếu không lấy được data sản phẩm -> ném lỗi
                    if (!response.isSuccess() || response.getData() == null) {
                        throw new ProductNotFoundException(cartItem.getProductId());
                    }

                    ProductDTO product = response.getData();

                    // 2.3. Nếu sản phẩm không còn ở trạng thái AVAILABLE -> không cho mua
                    if (!ProductStatusConstant.AVAILABLE.equals(product.getStatus())) {
                        throw new ProductNotAvailableException(product.getId());
                    }

                    Integer ecoPoint = product.getEcoPointValue() != null
                            ? product.getEcoPointValue()
                            : 0;

                    // 2.4. Map từng item trong cart sang OrderItemRequest để dùng tiếp
                    return OrderItemRequest.builder()
                            .productId(cartItem.getProductId())
                            .price(cartItem.getPrice())
                            .productName(cartItem.getProductName())
                            .productImage(cartItem.getProductImage())
                            .ecoPoint(ecoPoint)
                            .build();
                })
                .collect(Collectors.toList());

        // 2.5. Tính tổng tiền hàng trước giảm giá
        BigDecimal productTotal = orderItems.stream()
                .map(OrderItemRequest::getPrice)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        // 3. TÍNH PHÍ VẬN CHUYỂN VÀ CHỌN GÓI
// 3.1. Gọi service tính phí ship dựa trên giỏ hàng + địa chỉ giao hàng
        ShippingEstimateResponse estimate = shippingCalculationService.calculateShippingFee(
                cart.getItems(),
                productTotal,
                String.valueOf(request.getShippingAddress().getCityId()),
                String.valueOf(request.getShippingAddress().getDistrictId())
        );

// 3.2. Nếu không có option vận chuyển nào -> báo lỗi
        if (estimate.getAvailableOptions().isEmpty()) {
            throw new ShippingRateNotFoundException("Không tìm thấy đơn vị vận chuyển phù hợp");
        }

// 3.3. Lọc ra option mà user đã chọn (selectedRateId)
        ShippingEstimateResponse.ShippingOption selectedOption = estimate.getAvailableOptions().stream()
                .filter(option -> option.getRateId().equals(request.getSelectedRateId()))
                .findFirst()
                .orElseThrow(() -> new InvalidShippingRateException(request.getSelectedRateId()));

// 3.4. Phí ship gốc (chưa áp dụng voucher)
        BigDecimal originalShippingFee = selectedOption.getFee();


        // 4. ÁP DỤNG VOUCHER VÀ TÍNH CÁC KHOẢN TIỀN

// 4.1. Gọi service voucher để tính giảm giá trên tiền hàng + phí ship
        VoucherDiscountResult voucherResult = voucherDiscountService.validateAndCalculateOnline(
                request.getVoucherUserId(),
                productTotal,
                originalShippingFee
        );

// 4.2. Tách riêng tiền giảm trên sản phẩm
        BigDecimal productDiscount = voucherResult.getDiscountAmount() != null
                ? voucherResult.getDiscountAmount()
                : BigDecimal.ZERO;

// 4.3. Tách riêng tiền giảm trên phí ship
        BigDecimal shippingDiscount = voucherResult.getShippingDiscount() != null
                ? voucherResult.getShippingDiscount()
                : BigDecimal.ZERO;

// 4.4. Tính phí ship sau giảm (không được âm)
        BigDecimal finalShippingFee = originalShippingFee.subtract(shippingDiscount);
        if (finalShippingFee.compareTo(BigDecimal.ZERO) < 0) {
            finalShippingFee = BigDecimal.ZERO;
        }

// 4.5. Tiền hàng sau khi trừ giảm giá sản phẩm
        BigDecimal subtotalAfterDiscount = productTotal.subtract(productDiscount);

// 4.6. Tổng tiền khách phải trả = tiền hàng sau giảm + phí ship sau giảm
        BigDecimal totalPrice = subtotalAfterDiscount.add(finalShippingFee);


        // 5. TÍNH NGÀY GIAO DỰ KIẾN, KÍCH THƯỚC KIỆN VÀ MÃ ĐƠN

// 5.1. Tính expectedDeliveryTime từ chuỗi estimatedDelivery (ví dụ: "2-3 ngày")
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

// 5.2. Tính kích thước kiện hàng từ các sản phẩm trong giỏ
        ParcelDimensionDTO parcelDimensions = shippingCalculationService
                .calculateParcelDimensions(cart.getItems());

// 5.3. Tạo orderId (UUID) và orderCode (theo format riêng)
        String orderId = UUID.randomUUID().toString();
        String orderCode = orderCodeGenerator.generateOrderOnlineCode();


        // 6. CHUẨN BỊ RESPONSE VÀ RẼ NHÁNH THEO PAYMENT METHOD

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
            // 6.2.1. Xử lý checkout COD: build CreateOrderRequest và lưu Order vào DB
            handleCODCheckout(
                    userId, orderId, orderCode, request, orderItems,
                    productTotal, finalShippingFee, totalPrice,
                    productDiscount.add(shippingDiscount), voucherResult,
                    selectedOption, expectedDeliveryTime, parcelDimensions
            );

            // 6.2.2. Message trả về
            String message = String.format(
                    "Đặt hàng thành công! Tổng thanh toán: %,dđ khi nhận hàng.",
                    totalPrice.longValue()
            );

            // COD không có paymentUrl
            responseBuilder.paymentUrl(null).message(message);

        } else if (request.getPaymentMethod() == PaymentMethod.PAYOS) {
            // 6.3.1. Xử lý checkout PayOS: Tạo paymentUrl và lưu PendingOrder vào Redis
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

            // PayOS có paymentUrl để redirect
            responseBuilder.paymentUrl(paymentUrl).message(message);
        }

        return responseBuilder.build();
    }

    /**
     * Xử lý checkout COD - Lưu thẳng vào Database
     */
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
            ParcelDimensionDTO parcelDimensions) {
// GOM TOÀN BỘ THÔNG TIN ORDER ĐỂ LƯU DB
        CreateOrderRequest orderRequest = CreateOrderRequest.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .customerId(userId)
                .subTotal(productTotal)
                .discountAmount(discountAmount)
                .totalPrice(totalPrice)
                .shippingFee(shippingFee)
                .voucherUserId(request.getVoucherUserId())
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
                .shippingStatus(900) // trạng thái default khi mới tạo đơn
                .build();

// 1) Lưu Order vào DB (buildAndSaveOrder sẽ gắn ShippingAddress + Warehouse)
        Order createdOrder = buildAndSaveOrder(orderRequest);

// 2. Gọi Feign Client để reserve sản phẩm
        reserveProductsViaFeign(createdOrder);

        transactionService.createTransactionFromOrder(createdOrder);

// 3) Xóa giỏ hàng vì đơn COD đã được tạo thành công
        cartService.clearCart(userId);

    }

    /**
     * Xử lý checkout PayOS - Lưu vào Redis
     */
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
// 1) Tạo paymentUrl từ PayOS, kèm platform (web / mobile)
        String platform = request.getPlatform() != null ? request.getPlatform() : "web";
        PayOSPaymentResponse paymentResponse = payOSPaymentService.createPaymentUrl(
                orderId, totalPrice, platform);

// 2) Build PendingOrderRedis, chứa toàn bộ thông tin đơn nhưng CHƯA LƯU DB
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

// 3) Lưu pending order vào Redis, chờ webhook PayOS confirm thanh toán
        pendingOrderCacheService.savePendingOrder(pendingOrder);

// 4) KHÔNG clear cart, KHÔNG publish event, vì đơn chưa thanh toán thành công
// 5) Trả về paymentUrl để FE redirect
        return paymentResponse.getCheckoutUrl();

    }


    @Override
    @Transactional
    public Order buildAndSaveOrder(CreateOrderRequest request) {
        log.info("Creating order {} for customer {}",
                request.getOrderCode(), request.getCustomerId());

        if (request.getTotalPrice().compareTo(BigDecimal.ZERO) <= 0) {
            throw new InvalidOrderPriceException();
        }

        Order order = Order.builder()
                .orderId(request.getOrderId())
                .orderCode(request.getOrderCode())
                .customerId(request.getCustomerId())
                .subTotal(request.getSubTotal())
                .discountAmount(request.getDiscountAmount())
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

        log.info("Order created successfully: {}", savedOrder.getOrderCode());

        return savedOrder;
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
    public Order getOrderEntityById(String orderId) {
        return orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));
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


        log.info("Order {} ready to ship. Shipment ID: {}. Carrier: {}. Previous status: {}. Reason: {}",
                orderId, shipmentResponse.getId(), shipmentResponse.getCarrier(), oldStatus, request.getReason());

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
    public void handleLostOrder(String orderId, String reason) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));

        log.error("Processing LOST order: {} | PaymentMethod: {} | Reason: {}",
                order.getOrderCode(), order.getPaymentMethod(), reason);

        // Xử lý payment theo method
        if (order.getPaymentMethod() == PaymentMethod.COD) {
            log.info("Lost order {} is COD - No refund needed. Customer has not paid yet.",
                    order.getOrderCode());
            // COD: Khách chưa trả tiền, không cần hoàn tiền

        } else if (order.getPaymentMethod() == PaymentMethod.PAYOS
                && order.getPaymentStatus() == PaymentStatus.PAID) {
            // TODO: Xử lý PayOS refund sau
            log.warn("Lost order {} requires PayOS refund - Not implemented yet",
                    order.getOrderCode());
        }

        // Product đã được update sang LOST ở GoShipWebhookService.handleProductStatusChange()
        // Hàng thật sự bị mất, không trả về AVAILABLE

        // Thông báo khách hàng
//        notifyCustomerLostOrder(order, reason);

        // Alert staff để khiếu nại GoShip
//        alertStaffLostOrder(order, reason);

        orderRepository.save(order);

        log.warn("Lost order {} processed. Product marked as LOST in inventory.",
                order.getOrderCode());
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
                    OrderStatus.COMPLETED.getDescription()
            );
        }

        int totalEcoPoints = order.getOrderItems().stream()
                .mapToInt(item -> item.getEcoPoint() != null ? item.getEcoPoint() : 0)
                .sum();

        order.setEarnedEcoPoints(totalEcoPoints);
        order.setOrderStatus(OrderStatus.COMPLETED);
        order.setUpdatedAt(LocalDateTime.now());

        orderRepository.save(order);

        transactionService.completeTransaction(orderId);

        markProductsAsSoldViaFeign(order);
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

        log.info("Order {} processing started. Previous status: {}. Reason: {}",
                orderId, oldStatus, reason);
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

        log.info("Order {} confirmed. Previous status: {}. Reason: {}",
                orderId, oldStatus, reason);
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

        if (order.getPaymentStatus() == PaymentStatus.PAID) {
            transactionService.createRefundTransaction(order, reason);
        }


        unreserveProductsViaFeign(order);

        log.info("Order {} cancelled. Previous status: {}. Reason: {}",
                orderId, oldStatus, reason);
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
                .earnedEcoPoints(order.getEarnedEcoPoints())
                .eventId(order.getEventId())
                .build();

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

    private void validateCancelPermission(Order order, OrderStatus currentStatus,
                                          Long requestingUserId, String userRole) {

        // RULE 2: Từ CONFIRMED trở đi → CHỈ STAFF/MANAGER/ADMIN
        if (currentStatus == OrderStatus.CONFIRMED ||
                currentStatus == OrderStatus.PROCESSING ||
                currentStatus == OrderStatus.READY_TO_SHIP ||
                currentStatus == OrderStatus.SHIPPING ||
                currentStatus == OrderStatus.DELIVERING ||
                currentStatus == OrderStatus.DELIVERED ||
                currentStatus == OrderStatus.DELIVERY_FAILED ||
                currentStatus == OrderStatus.RETURNING) {

            if (!isStaffOrAbove(userRole)) {
                throw new UnauthorizedCancelException(
                        "Đơn hàng đã được xác nhận. Chỉ nhân viên mới có thể hủy. " +
                                "Vui lòng liên hệ hotline để được hỗ trợ."
                );
            }

            log.info("Staff/Manager/Admin {} cancelling confirmed order {}",
                    requestingUserId, order.getOrderId());
        }

        // RULE 3: Trạng thái PENDING → Customer chỉ hủy được đơn của mình
        if (currentStatus == OrderStatus.PENDING) {
            if (isCustomer(userRole)) {
                if (!order.getCustomerId().equals(requestingUserId)) {
                    throw new UnauthorizedCancelException(
                            "Bạn không có quyền hủy đơn hàng này"
                    );
                }
                log.info("Customer {} cancelling their own pending order {}",
                        requestingUserId, order.getOrderId());
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

    /**
     * Unreserve sản phẩm khi cancel order
     */
    private void unreserveProductsViaFeign(Order order) {
        log.info("Unreserving products via Feign for order {}", order.getOrderId());

        List<UnreserveProductsRequest.ProductUnreserve> products = order.getOrderItems().stream()
                .map(item -> UnreserveProductsRequest.ProductUnreserve.builder()
                        .productId(item.getProductId())
                        .build())
                .collect(Collectors.toList());

        UnreserveProductsRequest request = UnreserveProductsRequest.builder()
                .orderId(order.getOrderId())
                .products(products)
                .build();

        try {
            ApiResponseDTO<Void> response = productClient.unreserveProducts(request);
            if (!response.isSuccess()) {
                log.error("Failed to unreserve products for order {}", order.getOrderId());
            }
        } catch (Exception e) {
            log.error("Error calling product service to unreserve products", e);
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
            ApiResponseDTO<Void> response = rewardClient.markVoucherAsUsed(request); // ✅ DÙNG voucherClient
            if (!response.isSuccess()) {
                log.error("Failed to mark voucher as used for order {}", order.getOrderId());
            } else {
                log.info("Voucher marked as used successfully via Feign for voucherUserId: {}",
                        order.getVoucherUserId());
            }
        } catch (Exception e) {
            log.error("Error calling reward service to mark voucher as used", e);
            // Không throw exception để không làm fail checkout flow
        }
    }

    /**
     * Đánh dấu sản phẩm là SOLD khi hoàn thành đơn hàng
     */
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

    private boolean isStaffOrAbove(String userRole) {
        return "ROLE_STAFF".equals(userRole) ||
                "ROLE_MANAGER".equals(userRole) ||
                "ROLE_ADMIN".equals(userRole);
    }

    private boolean isCustomer(String userRole) {
        return "ROLE_CUSTOMER".equals(userRole);
    }


}
