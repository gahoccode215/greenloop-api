package com.greenloop.order.service.impl;

import com.greenloop.order.command.CreateOrderOfflineCommand;
import com.greenloop.order.dto.request.CreateOrderOfflineRequest;
import com.greenloop.order.dto.request.OrderItemOfflineRequest;
import com.greenloop.order.dto.response.OrderItemResponse;
import com.greenloop.order.dto.response.OrderOfflineResponse;
import com.greenloop.order.dto.response.VoucherDiscountResult;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.service.OrderOfflineService;
import com.greenloop.order.service.VoucherDiscountService;
import com.greenloop.order.util.OrderCodeGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
public class OrderOfflineServiceImpl implements OrderOfflineService {

    private final CommandGateway commandGateway;
    private final OrderCodeGenerator orderCodeGenerator;
    private final VoucherDiscountService voucherDiscountService;

    @Override
    @Transactional
    public OrderOfflineResponse createOrderOffline(CreateOrderOfflineRequest request) {
        boolean isGuestPurchase = (request.getCustomerId() == null);

        if (isGuestPurchase) {
            log.info("Creating offline order for GUEST: {}, event: {}",
                    request.getGuestName(), request.getEventId());
        } else {
            log.info("Creating offline order for CUSTOMER ID: {}, event: {}",
                    request.getCustomerId(), request.getEventId());
        }

        // 1. Calculate subtotal
        BigDecimal subtotal = calculateSubtotal(request.getItems());
        log.info("Order subtotal calculated: {}", subtotal);

        // 2. Apply voucher
        VoucherDiscountResult voucherResult =
                voucherDiscountService.validateAndCalculate(
                        request.getVoucherUserId(), subtotal);

        BigDecimal discountAmount = voucherResult.getDiscountAmount();
        BigDecimal totalPrice = subtotal.subtract(discountAmount);

        if (voucherResult.hasDiscount()) {
            log.info("Voucher {} applied. Discount: {}, Final price: {}",
                    voucherResult.getVoucherCode(), discountAmount, totalPrice);
        }

        // 3. Generate order identifiers
        String orderId = UUID.randomUUID().toString();
        String orderCode = orderCodeGenerator.generateOrderOfflineCode();

        // 4. Build Command
        CreateOrderOfflineCommand command = CreateOrderOfflineCommand.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .customerId(request.getCustomerId())
                .eventId(request.getEventId())
                .voucherUserId(request.getVoucherUserId())
                .voucherCode(voucherResult.getVoucherCode())
                .discountAmount(discountAmount)
                .guestName(request.getGuestName())
                .guestPhone(request.getGuestPhone())
                .isGuestPurchase(isGuestPurchase)
                .subTotal(subtotal)
                .totalPrice(totalPrice)
                .orderType(OrderType.OFFLINE)
                .orderStatus(OrderStatus.COMPLETED)
                .paymentStatus(PaymentStatus.PAID)
                .paymentMethod(PaymentMethod.valueOf(request.getPaymentMethod()))
                .orderItems(request.getItems())
                .note(request.getNote())
                .build();

        // 5. Send Command
        commandGateway.sendAndWait(command);

        log.info("Order created successfully with code: {} (Guest: {})",
                orderCode, isGuestPurchase);

        // 6. Build response TRỰC TIẾP từ data có sẵn (KHÔNG query DB)
        return buildResponseFromCommand(
                orderId,
                orderCode,
                request,
                subtotal,
                totalPrice,
                voucherResult
        );
    }

    /**
     * Build response directly from command data (No DB query needed)
     */
    private OrderOfflineResponse buildResponseFromCommand(
            String orderId,
            String orderCode,
            CreateOrderOfflineRequest request,
            BigDecimal subtotal,
            BigDecimal totalPrice,
            VoucherDiscountResult voucherResult) {

        List<OrderItemResponse> itemResponses = request.getItems().stream()
                .map(item -> OrderItemResponse.builder()
                        .orderItemId(null) // Will be set after projection saves
                        .productId(item.getProductId())
                        .productName(item.getProductName())
                        .productImage(item.getProductImage())
                        .price(item.getPrice())
                        .build())
                .collect(Collectors.toList());

        return OrderOfflineResponse.builder()
                .orderId(orderId)
                .orderCode(orderCode)
                .eventId(request.getEventId())
                .customerId(request.getCustomerId())
                .isGuestPurchase(request.getCustomerId() == null)
                .items(itemResponses)
                .subtotal(subtotal)
                .discountAmount(voucherResult.getDiscountAmount())
                .totalPrice(totalPrice)
                .voucherCode(voucherResult.getVoucherCode())
                .paymentMethod(request.getPaymentMethod())
                .createdAt(LocalDateTime.now())
                .createdBy(getCurrentEmployeeEmail())
                .build();
    }

    private BigDecimal calculateSubtotal(List<OrderItemOfflineRequest> items) {
        return items.stream()
                .map(OrderItemOfflineRequest::getPrice)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
    }

    private String getCurrentEmployeeEmail() {
        Authentication authentication = SecurityContextHolder
                .getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            return authentication.getName();
        }
        return "anonymous";
    }
}
