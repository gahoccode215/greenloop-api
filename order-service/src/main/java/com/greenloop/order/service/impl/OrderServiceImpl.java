package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.ParcelDimensionDTO;
import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.event.OrderCheckedOutEvent;
import com.greenloop.order.dto.request.*;
import com.greenloop.order.dto.response.*;
import com.greenloop.order.entity.Cart;
import com.greenloop.order.entity.CartItem;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.OrderItem;
import com.greenloop.order.entity.ShippingAddress;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.*;
import com.greenloop.order.repository.CartRepository;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.repository.specification.OrderSpecification;
import com.greenloop.order.service.CartService;
import com.greenloop.order.service.OrderService;
import com.greenloop.order.service.PayOSPaymentService;
import com.greenloop.order.service.ShippingCalculationService;
import com.greenloop.order.util.OrderCodeGenerator;
import com.greenloop.order.util.PageResponseUtil;
import com.greenloop.order.util.ShippingStatusMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.stream.function.StreamBridge;
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
    private final CartService cartService;
    private final PayOSPaymentService payOSPaymentService;
    private final ShippingCalculationService shippingCalculationService;
    private final StreamBridge streamBridge;

    @Value("${goship.default-warehouse.name}")
    private String warehouseName;

    @Value("${goship.default-warehouse.phone}")
    private String warehousePhone;

    @Value("${goship.default-warehouse.address}")
    private String warehouseAddress;

    @Value("${goship.default-warehouse.ward-code}")
    private Long warehouseWardCode;

    @Value("${goship.default-warehouse.ward-name}")
    private String warehouseWardName;

    @Value("${goship.default-warehouse.district-id}")
    private Integer warehouseDistrictId;

    @Value("${goship.default-warehouse.city-id}")
    private Integer warehouseCityId;

    @Value("${goship.default-warehouse.district-name}")
    private String warehouseDistrictName;

    @Value("${goship.default-warehouse.city-name}")
    private String warehouseCityName;

    @Override
    @Transactional
    public void createOrder(Order order) {
        orderRepository.save(order);
    }

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
        if (request.getSelectedRateId() == null || request.getSelectedRateId().isBlank()) {
            throw new IllegalArgumentException("Vui lòng chọn đơn vị vận chuyển");
        }

        Cart cart = cartRepository.findByCustomerId(userId)
                .orElseThrow(() -> new CartNotFoundException(userId));

        if (cart.getItems().isEmpty()) {
            throw new EmptyCartException();
        }

        List<OrderItemRequest> orderItems = cart.getItems().stream()
                .map(this::validateAndMapCartItem)
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

        BigDecimal shippingFee = selectedOption.getFee();
        BigDecimal totalPrice = productTotal.add(shippingFee);

        LocalDateTime expectedDeliveryTime = calculateExpectedDeliveryTime(
                selectedOption.getEstimatedDelivery());

        ParcelDimensionDTO parcelDimensions = shippingCalculationService
                .calculateParcelDimensions(cart.getItems());

        String orderId = UUID.randomUUID().toString();
        String orderCode = OrderCodeGenerator.generateOrderCode();

        CreateOrderRequest.CreateOrderRequestBuilder orderRequestBuilder = CreateOrderRequest.builder()
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
                .carrier(selectedOption.getCarrierName())
                .expectedDeliveryTime(expectedDeliveryTime)
                .parcelWeight(String.valueOf(parcelDimensions.getWeight()))
                .parcelWidth(String.valueOf(parcelDimensions.getWidth()))
                .parcelHeight(String.valueOf(parcelDimensions.getHeight()))
                .parcelLength(String.valueOf(parcelDimensions.getLength()))
                .shippingStatus(900);

        CheckoutResponse.CheckoutResponseBuilder responseBuilder = CheckoutResponse.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .productTotal(productTotal)
                .shippingFee(shippingFee)
                .totalPrice(totalPrice)
                .selectedCarrier(selectedOption.getCarrierName())
                .estimatedDelivery(selectedOption.getEstimatedDelivery())
                .createdAt(LocalDateTime.now());

        if (request.getPaymentMethod() == PaymentMethod.COD) {
            responseBuilder.paymentUrl(null)
                    .message(String.format("Đặt hàng thành công! Tổng thanh toán: %,dđ khi nhận hàng.",
                            totalPrice.longValue()));

        } else if (request.getPaymentMethod() == PaymentMethod.PAYOS) {
            String platform = request.getPlatform() != null ? request.getPlatform() : "web";
            PayOSPaymentResponse paymentResponse = payOSPaymentService.createPaymentUrl(
                    orderId, totalPrice, platform);

            orderRequestBuilder.paymentOrderCode(paymentResponse.getPaymentOrderCode());

            responseBuilder.paymentUrl(paymentResponse.getCheckoutUrl())
                    .message(String.format("Vui lòng thanh toán %,dđ để hoàn tất đơn hàng.",
                            totalPrice.longValue()));
        }

        CreateOrderRequest orderRequest = orderRequestBuilder.build();
        Order createdOrder = buildAndSaveOrder(orderRequest);

        publishOrderCheckedOutEvent(createdOrder.getOrderId(), userId, cart, totalPrice);

        cartService.clearCart(userId);

        return responseBuilder.build();
    }

    @Transactional
    protected Order buildAndSaveOrder(CreateOrderRequest request) {
        log.info("Creating order {} for customer {}",
                request.getOrderCode(), request.getCustomerId());

        if (request.getTotalPrice().compareTo(BigDecimal.ZERO) <= 0) {
            throw new InvalidOrderPriceException();
        }

        Order order = Order.builder()
                .orderId(request.getOrderId())
                .orderCode(request.getOrderCode())
                .customerId(request.getCustomerId())
                .totalPrice(request.getTotalPrice())
                .shippingFee(request.getShippingFee())
                .orderStatus(request.getOrderStatus())
                .paymentStatus(request.getPaymentStatus())
                .paymentMethod(request.getPaymentMethod())
                .paymentOrderCode(request.getPaymentOrderCode())
                .selectedRateId(request.getSelectedRateId())
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
                    .warehouseName(warehouseName)
                    .warehousePhone(warehousePhone)
                    .warehouseAddress(warehouseAddress)
                    .warehouseWardCode(warehouseWardCode)
                    .warehouseWardName(warehouseWardName)
                    .warehouseDistrictId(warehouseDistrictId)
                    .warehouseDistrictName(warehouseDistrictName)
                    .warehouseCityName(warehouseCityName)
                    .warehouseCityId(warehouseCityId)
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
                            .order(order)
                            .build())
                    .collect(Collectors.toList());

            order.setOrderItems(orderItems);
        }

        Order savedOrder = orderRepository.save(order);

        log.info("Order created successfully: {}", savedOrder.getOrderCode());

        return savedOrder;
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
    public void updateOrderStatusWithDetails(String orderId, UpdateOrderStatusRequest request) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));

        OrderStatus oldStatus = order.getOrderStatus();

        // Validate status transition
        if (!oldStatus.canTransitionTo(request.getNewStatus())) {
            throw new InvalidOrderStatusException(
                    oldStatus.getDescription(),
                    request.getNewStatus().getDescription()
            );
        }

        // Additional validation for cancellation
        if (request.getNewStatus() == OrderStatus.CANCELLED) {
            validateCancellation(order);
        }

        // Update order status
        order.setOrderStatus(request.getNewStatus());
        order.setUpdatedAt(LocalDateTime.now());

        // Update shipping info if provided
        if (request.getGoshipShipmentId() != null) {
            order.setGoshipShipmentId(request.getGoshipShipmentId());
            order.setGoshipTrackingUrl(request.getGoshipTrackingCode());
            order.setCarrier(request.getCarrier());
        }

        orderRepository.save(order);

        log.info("Order {} status updated from {} to {}. Reason: {}",
                orderId, oldStatus, request.getNewStatus(), request.getReason());

    }

    private void validateCancellation(Order order) {
        if (!order.getOrderStatus().isCancellable()) {
            throw new OrderNotCancellableException(order.getOrderStatus().getDescription());
        }

        if (order.getPaymentStatus() == PaymentStatus.PAID
                && order.getPaymentMethod() == PaymentMethod.PAYOS) {
            throw new OrderNotCancellableException(
                    "Đơn hàng đã thanh toán online không thể hủy. Vui lòng liên hệ CSKH"
            );
        }
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
                .shippingStatusText(ShippingStatusMapper.getStatusText(order.getShippingStatus()))
                .goshipTrackingUrl(order.getGoshipTrackingUrl())
                .createdAt(order.getCreatedAt())
                .updatedAt(order.getUpdatedAt())
                .build();

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
                            .build())
                    .collect(Collectors.toList());

            response.setOrderItems(itemDTOs);
        }

        return response;
    }

    private void publishOrderCheckedOutEvent(String orderId, Long customerId, Cart cart, BigDecimal totalAmount) {
        log.info("Publishing OrderCheckedOutEvent for order {}", orderId);
        int totalEcoPoints = 0;
        List<OrderCheckedOutEvent.ProductStatusChange> productStatusChanges = new ArrayList<>();

        for (CartItem item : cart.getItems()) {
            try {
                ApiResponseDTO<ProductDTO> response = productClient.getProductById(item.getProductId());

                if (response.isSuccess() && response.getData() != null) {
                    ProductDTO product = response.getData();
                    int ecoPoint = product.getEcoPointValue() != null ? product.getEcoPointValue() : 0;
                    totalEcoPoints += ecoPoint;

                    productStatusChanges.add(
                            OrderCheckedOutEvent.ProductStatusChange.builder()
                                    .productId(item.getProductId())
                                    .newStatus(ProductStatusConstant.SOLD)
                                    .ecoPointValue(ecoPoint)
                                    .build()
                    );
                }
            } catch (Exception e) {
                log.error("Failed to fetch product {}: {}", item.getProductId(), e.getMessage());
            }
        }

        OrderCheckedOutEvent event = OrderCheckedOutEvent.builder()
                .orderId(orderId)
                .customerId(customerId)
                .totalAmount(totalAmount)
                .checkedOutAt(LocalDateTime.now())
                .productStatusChanges(productStatusChanges)
                .totalEcoPoints(totalEcoPoints)
                .build();

        streamBridge.send("orderCheckedOut-out-0", event);
        log.info("Published OrderCheckedOutEvent for order {}", orderId);
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
                .productName(cartItem.getProductName())
                .productImage(cartItem.getProductImage())
                .build();
    }
}
