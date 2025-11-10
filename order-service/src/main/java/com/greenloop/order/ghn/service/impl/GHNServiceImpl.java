package com.greenloop.order.ghn.service.impl;

import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.ShippingAddress;
import com.greenloop.order.ghn.client.GHNClient;
import com.greenloop.order.ghn.dto.CreateShippingOrderRequest;
import com.greenloop.order.ghn.dto.GHNResponse;
import com.greenloop.order.ghn.dto.ShippingOrderResponse;
import com.greenloop.order.ghn.service.GHNService;
import com.greenloop.order.repository.OrderRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class GHNServiceImpl implements GHNService {

    private final GHNClient ghnClient;
    private final OrderRepository orderRepository;

    @Override
    public ShippingOrderResponse createShippingOrder(String orderId) {
        // 1. Lấy order
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new RuntimeException("Order not found"));

        // 2. Build request
        CreateShippingOrderRequest request = buildShippingRequest(order);

        // 3. Gọi GHN API
        GHNResponse<ShippingOrderResponse> response = ghnClient.createShippingOrder(request);

        if (!response.isSuccess()) {
            throw new RuntimeException("GHN API failed: " + response.getMessage());
        }

        // 4. Lưu mã vận đơn và thông tin shipping
        ShippingOrderResponse data = response.getData();
        order.setGhnOrderCode(data.getOrderCode());
        order.setShippingFee(BigDecimal.valueOf(data.getTotalFee()));
        order.setShippingStatus("ready_to_pick");

        if (data.getExpectedDeliveryTime() != null) {
            order.setExpectedDeliveryTime(
                    LocalDateTime.parse(data.getExpectedDeliveryTime())
            );
        }

        orderRepository.save(order);

        log.info("Saved GHN order code {} for order {}", data.getOrderCode(), orderId);

        return data;
    }


    private CreateShippingOrderRequest buildShippingRequest(Order order) {
        ShippingAddress addr = order.getShippingAddress();

        return CreateShippingOrderRequest.builder()
                .toName(addr.getReceiverName())
                .toPhone(addr.getReceiverPhone())
                .toAddress(addr.getAddress())
                .toWardCode(addr.getWardCode())
                .toDistrictId(addr.getDistrictId())
                .codAmount(order.getTotalPrice().intValue())
                .content("Đơn hàng " + order.getOrderCode())
                .weight(500)
                .length(20)
                .width(15)
                .height(10)
                .serviceTypeId(2)
                .paymentTypeId(2)
                .requiredNote(addr.getNote() != null ? addr.getNote() : "CHOTHUHANG")
                .items(order.getOrderItems().stream()
                        .map(item -> CreateShippingOrderRequest.ItemDetail.builder()
                                .name("Product " + item.getProductId())
                                .quantity(item.getQuantity())
                                .price(item.getPrice().intValue())
                                .build())
                        .collect(Collectors.toList()))
                .build();
    }


    @Override
    public String trackOrder(String ghnOrderCode) {
        // TODO: Implement tracking
        return null;
    }

    @Override
    public void cancelOrder(String ghnOrderCode) {
        // TODO: Implement cancel
    }
}
