package com.greenloop.order.goship.service.impl;

import com.greenloop.order.dto.request.CreateShipmentRequestDTO;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.ShippingAddress;
import com.greenloop.order.exception.OrderNotFoundException;
import com.greenloop.order.goship.client.GoShipClient;
import com.greenloop.order.goship.dto.*;
import com.greenloop.order.goship.service.GoShipService;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.service.OrderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class GoShipServiceImpl implements GoShipService {

    private final GoShipClient goShipClient;
    private final OrderRepository orderRepository;

    @Override
    public List<RateResponse> calculateShippingRates(CalculateRateRequest request) {
        try {
            return goShipClient.calculateRates(request);
        } catch (Exception e) {
            throw new RuntimeException("Không thể tính cước phí vận chuyển: " + e.getMessage());
        }
    }

    @Override
    public CreateShipmentResponse createShipmentForOrder(String orderId, CreateShipmentRequestDTO staffRequest) {
        log.info("Creating GoShip shipment for order: {}", orderId);

        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));

        if (order.getSelectedRateId() == null || order.getSelectedRateId().isBlank()) {
            throw new IllegalArgumentException("Đơn hàng chưa có thông tin vận chuyển ");
        }

        ShippingAddress address = order.getShippingAddress();

        CreateShipmentRequest.AddressData warehouseAddr =
                (staffRequest.getWarehouseAddress() != null)
                        ? buildAddressFromOverride(staffRequest.getWarehouseAddress())
                        : buildWarehouseAddressFromOrder(address);

        CreateShipmentRequest.AddressData customerAddr =
                (staffRequest.getCustomerAddress() != null)
                        ? buildAddressFromOverride(staffRequest.getCustomerAddress())
                        : buildCustomerAddressFromOrder(address);

        String weight = (staffRequest.getWeight() != null && !staffRequest.getWeight().isBlank())
                ? staffRequest.getWeight() : order.getParcelWeight();

        String width = (staffRequest.getWidth() != null && !staffRequest.getWidth().isBlank())
                ? staffRequest.getWidth() : order.getParcelWidth();

        String height = (staffRequest.getHeight() != null && !staffRequest.getHeight().isBlank())
                ? staffRequest.getHeight() : order.getParcelHeight();

        String length = (staffRequest.getLength() != null && !staffRequest.getLength().isBlank())
                ? staffRequest.getLength() : order.getParcelLength();

        String metadata = (staffRequest.getMetadata() != null && !staffRequest.getMetadata().isBlank())
                ? staffRequest.getMetadata() : address.getNote();

        Long totalAmount = order.getTotalPrice().longValue();
        Long codAmount = 0L;

        if (staffRequest.getTotalAmount() != null) {
            totalAmount = staffRequest.getTotalAmount();
        }

        if (staffRequest.getCodAmount() != null) {
            codAmount = staffRequest.getCodAmount();
        }

        CreateShipmentRequest.ParcelData parcel = CreateShipmentRequest.ParcelData.builder()
                .cod(codAmount)
                .amount(totalAmount)
                .weight(weight)
                .width(width)
                .height(height)
                .length(length)
                .metadata(metadata)
                .build();

        CreateShipmentRequest goshipRequest = CreateShipmentRequest.builder()
                .shipment(CreateShipmentRequest.ShipmentData.builder()
                        .rate(order.getSelectedRateId())
                        .orderId(order.getOrderCode())
                        .payer(staffRequest.getPayer())
                        .addressFrom(warehouseAddr)
                        .addressTo(customerAddr)
                        .parcel(parcel)
                        .build())
                .build();

        return goShipClient.createShipment(goshipRequest);
    }

    @Override
    public void cancelShipment(String goshipShipmentId) {
        goShipClient.cancelShipment(goshipShipmentId);
    }


    private CreateShipmentRequest.AddressData buildAddressFromOverride(
            CreateShipmentRequestDTO.AddressOverrideDTO override) {

        return CreateShipmentRequest.AddressData.builder()
                .name(override.getName())
                .phone(override.getPhone())
                .street(override.getStreet())
                .ward(override.getWardCode())
                .district(override.getDistrictId())
                .city(override.getCityId())
                .build();
    }

    private CreateShipmentRequest.AddressData buildWarehouseAddressFromOrder(
            ShippingAddress address) {

        return CreateShipmentRequest.AddressData.builder()
                .name(address.getWarehouseName())
                .phone(address.getWarehousePhone())
                .street(address.getWarehouseAddress())
                .ward(String.valueOf(address.getWarehouseWardCode()))
                .district(String.valueOf(address.getWarehouseDistrictId()))
                .city(String.valueOf(address.getWarehouseCityId()))
                .build();
    }

    private CreateShipmentRequest.AddressData buildCustomerAddressFromOrder(
            ShippingAddress address) {

        return CreateShipmentRequest.AddressData.builder()
                .name(address.getReceiverName())
                .phone(address.getReceiverPhone())
                .street(address.getReceiverAddress())
                .ward(String.valueOf(address.getReceiverWardCode()))
                .district(String.valueOf(address.getReceiverDistrictId()))
                .city(String.valueOf(address.getReceiverCityId()))
                .build();
    }
}
