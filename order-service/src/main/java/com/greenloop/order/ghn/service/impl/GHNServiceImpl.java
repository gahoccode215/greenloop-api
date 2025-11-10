package com.greenloop.order.ghn.service.impl;

import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.OrderItem;
import com.greenloop.order.entity.ShippingAddress;
import com.greenloop.order.ghn.client.GHNClient;
import com.greenloop.order.ghn.config.GHNConfig;
import com.greenloop.order.ghn.dto.request.CreateShippingOrderRequest;
import com.greenloop.order.ghn.dto.response.GHNResponse;
import com.greenloop.order.ghn.dto.response.ShippingOrderResponse;
import com.greenloop.order.ghn.service.GHNService;
import com.greenloop.order.repository.OrderRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class GHNServiceImpl implements GHNService {

    private final GHNClient ghnClient;
    private final OrderRepository orderRepository;
    private final GHNConfig ghnConfig;

    @Override
    public ShippingOrderResponse createShippingOrder(String orderId) {
        // 1. Lấy thông tin order
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new RuntimeException("Order not found: " + orderId));

        // 2. Build request
        CreateShippingOrderRequest request = buildShippingRequest(order);

        // 3. Gọi GHN API
        GHNResponse<ShippingOrderResponse> response = ghnClient.createShippingOrder(request);

        if (!response.isSuccess()) {
            throw new RuntimeException("GHN API failed: " + response.getMessage());
        }

        // 4. Lưu mã vận đơn vào order
        ShippingOrderResponse data = response.getData();
        order.setGhnOrderCode(data.getOrderCode());
        order.setShippingFee(BigDecimal.valueOf(data.getTotalFee()));
        order.setShippingStatus("ready_to_pick");

        if (data.getExpectedDeliveryTime() != null && !data.getExpectedDeliveryTime().isEmpty()) {
            try {
                ZonedDateTime zonedDateTime = ZonedDateTime.parse(data.getExpectedDeliveryTime());
                order.setExpectedDeliveryTime(zonedDateTime.toLocalDateTime());
            } catch (Exception e) {
                log.warn("Failed to parse expected delivery time: {}", data.getExpectedDeliveryTime(), e);
            }
        }

        orderRepository.save(order);

        log.info("Created GHN shipping order: {} for order {}",
                data.getOrderCode(), orderId);

        return data;
    }

    private CreateShippingOrderRequest buildShippingRequest(Order order) {
        GHNConfig.ShopConfig shop = ghnConfig.getShop();
        ShippingAddress addr = order.getShippingAddress();

        return CreateShippingOrderRequest.builder()
                // Người gửi (từ config)
                .fromName(shop.getName())
                .fromPhone(shop.getPhone())
                .fromAddress(shop.getAddress())
                .fromWardName(shop.getWardName())
                .fromDistrictName(shop.getDistrictName())
                .fromProvinceName(shop.getProvinceName())

                // Người nhận (từ order)
                .toName(addr.getReceiverName())
                .toPhone(addr.getReceiverPhone())
                .toAddress(addr.getAddress())
                .toWardCode(addr.getWardCode())
                .toDistrictId(addr.getDistrictId())

                // Thông tin đơn hàng
                .codAmount(order.getTotalPrice().intValue())
                .content("Đơn hàng " + order.getOrderCode())
                .weight(calculateTotalWeight(order.getOrderItems()))
                .length(20)
                .width(15)
                .height(10)
                .serviceTypeId(2)  // E-commerce
                .paymentTypeId(2)  // Người nhận trả phí
                .requiredNote("CHOTHUHANG")
                .note(addr.getNote())
                .clientOrderCode(order.getOrderCode())
                .insuranceValue(order.getTotalPrice().intValue())

                // Danh sách sản phẩm
                .items(mapOrderItems(order.getOrderItems()))
                .build();
    }

    /**
     * Map OrderItem entity sang GHN ItemDetail DTO
     */
    private List<CreateShippingOrderRequest.ItemDetail> mapOrderItems(List<OrderItem> orderItems) {
        return orderItems.stream()
                .map(item -> CreateShippingOrderRequest.ItemDetail.builder()
                        .name("Product " + item.getProductId())  // Cần lấy tên thật từ Product service
                        .code(String.valueOf(item.getProductId()))
                        .quantity(item.getQuantity())
                        .price(item.getPrice().intValue())
                        .weight(200)  // 200g mỗi sản phẩm (default)
                        .length(10)
                        .width(10)
                        .height(5)
                        .build())
                .collect(Collectors.toList());
    }

    /**
     * Tính tổng cân nặng đơn hàng
     */
    private Integer calculateTotalWeight(List<OrderItem> items) {
        return items.stream()
                .mapToInt(item -> item.getQuantity() * 200)  // 200g mỗi sản phẩm
                .sum();
    }

    @Override
    public String trackOrder(String ghnOrderCode) {
        // TODO: Implement tracking API
        return null;
    }

    @Override
    public void cancelOrder(String ghnOrderCode) {
        // TODO: Implement cancel API
    }
}
