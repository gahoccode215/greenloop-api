package com.greenloop.order.ghn.service.impl;

import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.OrderItem;
import com.greenloop.order.entity.ShippingAddress;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.ghn.client.GHNClient;
import com.greenloop.order.ghn.dto.request.CreateShippingOrderRequest;
import com.greenloop.order.ghn.dto.request.CreateShippingRequest;
import com.greenloop.order.ghn.dto.response.*;
import com.greenloop.order.ghn.service.GHNService;
import com.greenloop.order.repository.OrderRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class GHNServiceImpl implements GHNService {

    private final GHNClient ghnClient;
    private final OrderRepository orderRepository;

    @Override
    public ShippingOrderResponse createShippingOrder(String orderId, CreateShippingRequest createShippingRequest) {
        // 1. Lấy thông tin order
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new RuntimeException("Order not found: " + orderId));

        // 2. Build request với thông tin người gửi từ request
        CreateShippingOrderRequest request = buildShippingRequest(order, createShippingRequest);

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
                log.warn("Failed to parse expected delivery time: {}", data.getExpectedDeliveryTime());
            }
        }

        orderRepository.save(order);

        log.info("Created GHN shipping order: {} for order {}", data.getOrderCode(), orderId);

        return data;
    }

    @Override
    public List<ProvinceResponse> getProvinces() {
        return ghnClient.getProvinces();
    }

    @Override
    public List<DistrictResponse> getDistricts(Integer provinceId) {
        return ghnClient.getDistricts(provinceId);
    }

    @Override
    public List<WardResponse> getWards(Integer districtId) {
        return ghnClient.getWards(districtId);
    }

    @Override
    public CancelOrderResponse cancelOrder(String orderId) {
        // 1. Lấy order từ DB
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new RuntimeException("Order not found: " + orderId));

        // 2. Kiểm tra có mã vận đơn GHN không
        if (order.getGhnOrderCode() == null || order.getGhnOrderCode().isEmpty()) {
            throw new RuntimeException("Order chưa có mã vận đơn GHN");
        }

        // 3. Gọi GHN API hủy đơn
        List<CancelOrderResponse> responses = ghnClient.cancelOrders(
                List.of(order.getGhnOrderCode())
        );

        // 4. Xử lý response
        if (responses != null && !responses.isEmpty()) {
            CancelOrderResponse response = responses.get(0);

            if (response.getResult()) {
                order.setShippingStatus("cancelled");
                order.setOrderStatus(OrderStatus.CANCELLED);
                orderRepository.save(order);

                log.info("Successfully cancelled order {} with GHN code {}",
                        orderId, order.getGhnOrderCode());
            }

            return response;
        }

        throw new RuntimeException("Failed to cancel order: " + orderId);
    }


    private CreateShippingOrderRequest buildShippingRequest(
            Order order,
            CreateShippingRequest createShippingRequest) {

        ShippingAddress addr = order.getShippingAddress();

        return CreateShippingOrderRequest.builder()
                // Thông tin người gửi
                .fromName(createShippingRequest.getSenderInfo().getName())
                .fromPhone(createShippingRequest.getSenderInfo().getPhone())
                .fromAddress(createShippingRequest.getSenderInfo().getAddress())
                .fromWardName(createShippingRequest.getSenderInfo().getWardName())
                .fromDistrictName(createShippingRequest.getSenderInfo().getDistrictName())
                .fromProvinceName(createShippingRequest.getSenderInfo().getProvinceName())

                // Thông tin người nhận
                .toName(addr.getReceiverName())
                .toPhone(addr.getReceiverPhone())
                .toAddress(addr.getReceiverAddress())
                .toWardCode(addr.getReceiverWardCode())
                .toDistrictId(addr.getReceiverDistrictId())
                .toProvinceId(addr.getReceiverProvinceId())

                // Thông tin đơn hàng
                .codAmount(order.getTotalPrice().intValue())
                .content("Đơn hàng " + order.getOrderCode())
                .weight(createShippingRequest.getOrderWeight())
                .length(createShippingRequest.getOrderLength())
                .width(createShippingRequest.getOrderWidth())
                .height(createShippingRequest.getOrderHeight())
                .serviceTypeId(createShippingRequest.getOrderServiceType())
                .paymentTypeId(createShippingRequest.getOrderPaymentType())
                .requiredNote(createShippingRequest.getOrderRequireNote())
                .note(addr.getNote())
                .clientOrderCode(order.getOrderCode())
                .insuranceValue(order.getTotalPrice().intValue())

                .items(mapOrderItems(order.getOrderItems()))
                .build();
    }

    private List<CreateShippingOrderRequest.ItemDetail> mapOrderItems(List<OrderItem> orderItems) {
        return orderItems.stream()
                .map(item -> CreateShippingOrderRequest.ItemDetail.builder()
                        .name("Product " + item.getProductId()) // Ở đây sau thay bằng tên sản phẩm
                        .code("Product " + item.getProductId())
                        .quantity(item.getQuantity())
                        .price(item.getPrice().intValue())
                        .build())
                .collect(Collectors.toList());
    }

    @Override
    public String trackOrder(String ghnOrderCode) {
        return null;
    }


}
