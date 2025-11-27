package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.command.CreatePOSOrderCommand;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.ProductDTO;
import com.greenloop.order.dto.event.ProductSoldEvent;
import com.greenloop.order.dto.request.OrderItemRequest;
import com.greenloop.order.dto.request.order.offline.POSCheckoutRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.order.offline.POSCheckoutResponse;
import com.greenloop.order.dto.response.order.offline.POSCustomerInfo;
import com.greenloop.order.dto.response.order.offline.POSSoldItem;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.ProductNotAvailableException;
import com.greenloop.order.exception.ProductNotFoundException;
import com.greenloop.order.service.POSService;
import com.greenloop.order.service.PayOSPaymentService;
import com.greenloop.order.util.OrderCodeGenerator;
import lombok.RequiredArgsConstructor;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class POSServiceImpl implements POSService {

    private final CommandGateway commandGateway;
    private final ProductClient productClient;
    private final PayOSPaymentService payOSPaymentService;
    private final StreamBridge streamBridge;

    @Override
    @Transactional
    public POSCheckoutResponse checkout(POSCheckoutRequest request) {

        List<ProductDTO> products = validateProducts(request);

        BigDecimal totalAmount = products.stream()
                .map(ProductDTO::getPrice)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        POSCustomerInfo customerInfo = resolveCustomer(request.getCustomer());

        String orderId = UUID.randomUUID().toString();
        String orderCode = OrderCodeGenerator.generatePOSOrderCode();

        List<OrderItemRequest> orderItems = products.stream()
                .map(p -> OrderItemRequest.builder()
                        .productId(p.getId())
                        .quantity(1)
                        .price(p.getPrice())
                        .productName(p.getName())
                        .productImage(p.getImageUrls() != null && !p.getImageUrls().isEmpty()
                                ? p.getImageUrls().get(0)
                                : null)
                        .build())
                .toList();

        OrderStatus orderStatus;
        PaymentStatus paymentStatus;
        Long paymentOrderCode = null;
        String paymentUrl = null;

        if ("CASH".equals(request.getPayment().getMethod())) {
            orderStatus = OrderStatus.COMPLETED;
            paymentStatus = PaymentStatus.PAID;

        } else if ("QR_CODE".equals(request.getPayment().getMethod())) {
            orderStatus = OrderStatus.PENDING;
            paymentStatus = PaymentStatus.UNPAID;

            var paymentResponse = payOSPaymentService.createPaymentUrl(
                    orderId, totalAmount, "mobile");

            paymentOrderCode = paymentResponse.getPaymentOrderCode();
            paymentUrl = paymentResponse.getCheckoutUrl();
        } else {
            throw new IllegalArgumentException("Invalid payment method: " + request.getPayment().getMethod());
        }

        CreatePOSOrderCommand command = CreatePOSOrderCommand.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .orderType(OrderType.POS_OFFLINE)
                .customerId(customerInfo.getCustomerId())
                .isGuestPurchase(customerInfo.getCustomerId() == null)
                .eventLocationId(request.getEventLocationId())
                .posStaffId(request.getStaffId())
                .totalPrice(totalAmount)
                .orderStatus(orderStatus)
                .paymentStatus(paymentStatus)
                .paymentMethod(PaymentMethod.valueOf(request.getPayment().getMethod()))
                .paymentOrderCode(paymentOrderCode)
                .orderItems(orderItems)
                .build();

        commandGateway.sendAndWait(command);

        if ("CASH".equals(request.getPayment().getMethod())) {
            publishProductSoldEvents(products, orderId, orderCode);
        }

        return POSCheckoutResponse.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .orderType("POS_OFFLINE")
                .totalAmount(totalAmount)
                .paymentMethod(request.getPayment().getMethod())
                .paymentStatus(paymentStatus.name())
                .paymentUrl(paymentUrl)
                .paymentOrderCode(paymentOrderCode)
                .items(products.stream()
                        .map(p -> POSSoldItem.builder()
                                .productId(p.getId())
                                .productName(p.getName())
                                .imageUrl(p.getImageUrls() != null && !p.getImageUrls().isEmpty()
                                        ? p.getImageUrls().get(0)
                                        : null)
                                .price(p.getPrice())
                                .build())
                        .toList())
                .customer(customerInfo)
                .ecoPointsEarned(customerInfo.getCustomerId() != null
                        ? calculateEcoPoints(totalAmount) : null)
                .createdAt(LocalDateTime.now())
                .build();
    }

    private List<ProductDTO> validateProducts(POSCheckoutRequest request) {
        List<ProductDTO> products = new ArrayList<>();

        for (Long productId : request.getProductIds()) {
            ApiResponseDTO<ProductDTO> response = productClient.getProductById(productId);

            if (!response.isSuccess() || response.getData() == null) {
                throw new ProductNotFoundException(productId);
            }

            ProductDTO product = response.getData();

            if (!ProductStatusConstant.AVAILABLE.equals(product.getStatus())) {
                throw new ProductNotAvailableException(product.getId());
            }

            products.add(product);
        }

        return products;
    }

    private POSCustomerInfo resolveCustomer(com.greenloop.order.dto.request.order.offline.POSCustomer request) {
        if ("GUEST".equals(request.getType())) {
            return POSCustomerInfo.builder()
                    .type("GUEST")
                    .customerId(null)
                    .phoneNumber(request.getPhoneNumber())
                    .name(request.getName())
                    .message("Đơn hàng khách vãng lai")
                    .build();
        } else {
            return POSCustomerInfo.builder()
                    .type("MEMBER")
                    .customerId(request.getCustomerId())
                    .phoneNumber(request.getPhoneNumber())
                    .name(request.getName())
                    .message("Đơn hàng member")
                    .build();
        }
    }

    private void publishProductSoldEvents(List<ProductDTO> products, String orderId, String orderCode) {
        for (ProductDTO product : products) {
            ProductSoldEvent event = ProductSoldEvent.builder()
                    .productId(product.getId())
                    .orderId(orderId)
                    .orderCode(orderCode)
                    .newStatus(ProductStatusConstant.SOLD)
                    .soldAt(LocalDateTime.now())
                    .build();

            streamBridge.send("productSold-out-0", event);
        }
    }

    private int calculateEcoPoints(BigDecimal amount) {
        return amount.divide(BigDecimal.valueOf(10000), RoundingMode.DOWN).intValue();
    }
}
