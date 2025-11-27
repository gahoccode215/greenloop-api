package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.command.CreateOrderCommand;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.ParcelDimensionDTO;
import com.greenloop.order.dto.response.OrderItemResponse;
import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.response.ShippingAddressResponse;
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
import com.greenloop.order.util.ShippingStatusMapper;
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
        RateResponse selectedRate = RateResponse.builder()
                .id(selectedOption.getRateId())
                .carrierName(selectedOption.getCarrierName())
                .carrierLogo(selectedOption.getCarrierLogo())
                .service(selectedOption.getService())
                .totalFee(selectedOption.getFee())
                .expected(selectedOption.getEstimatedDelivery())
                .build();
        BigDecimal shippingFee = selectedRate.getTotalFee();
        BigDecimal totalPrice = productTotal.add(shippingFee);
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
            expectedDeliveryTime = LocalDateTime.now().plusDays(3);
        }

        ParcelDimensionDTO parcelDimensions = shippingCalculationService.calculateParcelDimensions(cart.getItems());

        String orderId = UUID.randomUUID().toString();
        String orderCode = OrderCodeGenerator.generateOrderCode();

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
                .selectedCarrier(selectedRate.getCarrierName())
                .estimatedDelivery(selectedRate.getExpected())
                .createdAt(LocalDateTime.now());
        if (request.getPaymentMethod() == PaymentMethod.COD) {
            responseBuilder
                    .paymentUrl(null)
                    .message(String.format("Đặt hàng thành công! Tổng thanh toán: %,dđ khi nhận hàng.",
                            totalPrice.longValue()));

        } else if (request.getPaymentMethod() == PaymentMethod.PAYOS) {
            String platform = request.getPlatform() != null ? request.getPlatform() : "web";
            PayOSPaymentResponse paymentResponse = payOSPaymentService.createPaymentUrl(
                    orderId, totalPrice, platform);
            commandBuilder.paymentOrderCode(paymentResponse.getPaymentOrderCode());
            responseBuilder
                    .paymentUrl(paymentResponse.getCheckoutUrl())
                    .message(String.format("Vui lòng thanh toán %,dđ để hoàn tất đơn hàng.",
                            totalPrice.longValue()));
        }
        commandGateway.sendAndWait(commandBuilder.build());
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
                .shippingStatus(order.getShippingStatus())
                .shippingStatusText(ShippingStatusMapper.getStatusText(order.getShippingStatus()))
                .goshipTrackingUrl(order.getGoshipTrackingUrl())
                .createdAt(order.getCreatedAt())
                .updatedAt(order.getUpdatedAt())
                .build();

        // Map shipping address
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

        // Map order items
        if (order.getOrderItems() != null && !order.getOrderItems().isEmpty()) {
            List<OrderItemResponse> itemDTOs = order.getOrderItems().stream()
                    .map(item -> OrderItemResponse.builder()
                            .orderItemId(item.getOrderItemId())
                            .productId(item.getProductId())
                            .quantity(item.getQuantity())
                            .price(item.getPrice())
                            .productName(item.getProductName())
                            .productImage(item.getProductImage())
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
                .productName(cartItem.getProductName())
                .productImage(cartItem.getProductImage())
                .build();
    }
}
