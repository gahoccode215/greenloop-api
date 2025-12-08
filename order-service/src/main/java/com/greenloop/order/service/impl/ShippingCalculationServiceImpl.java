package com.greenloop.order.service.impl;

import com.greenloop.order.dto.ParcelDimensionDTO;
import com.greenloop.order.dto.response.ShippingEstimateResponse;
import com.greenloop.order.entity.CartItem;
import com.greenloop.order.entity.WarehouseSetting; // THÊM
import com.greenloop.order.goship.dto.CalculateRateRequest;
import com.greenloop.order.goship.dto.RateResponse;
import com.greenloop.order.goship.service.GoShipService;
import com.greenloop.order.service.ShippingCalculationService;
import com.greenloop.order.service.WarehouseSettingService; // THÊM
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ShippingCalculationServiceImpl implements ShippingCalculationService {

    private final GoShipService goShipService;
    private final WarehouseSettingService warehouseSettingService;

    @Override
    public ShippingEstimateResponse calculateShippingFee(
            List<CartItem> cartItems,
            BigDecimal productTotal,
            String cityCode,
            String districtCode) {

        log.info("Calculating shipping fee for {} items to city: {}, district: {}",
                cartItems.size(), cityCode, districtCode);

        ParcelDimensionDTO parcel = calculateParcelDimensions(cartItems);
        CalculateRateRequest rateRequest = buildRateRequest(cityCode, districtCode, parcel, productTotal);
        List<RateResponse> rates = goShipService.calculateShippingRates(rateRequest);

        return processShippingRates(rates, productTotal);
    }

    @Override
    public ParcelDimensionDTO calculateParcelDimensions(List<CartItem> cartItems) {
        if (cartItems == null || cartItems.isEmpty()) {
            log.warn("No cart items provided for parcel dimension calculation");
            return ParcelDimensionDTO.builder()
                    .weight(0)
                    .length(0)
                    .width(0)
                    .height(0)
                    .build();
        }

        int totalWeight = 0;
        int maxLength = 0;
        int maxWidth = 0;
        int maxHeight = 0;

        for (CartItem item : cartItems) {
            totalWeight += item.getWeight();
            maxLength = Math.max(maxLength, item.getLength());
            maxWidth = Math.max(maxWidth, item.getWidth());
            maxHeight = Math.max(maxHeight, item.getHeight());
        }

        log.debug("Calculated parcel dimensions: weight={}g, {}x{}x{}cm",
                totalWeight, maxLength, maxWidth, maxHeight);

        return ParcelDimensionDTO.builder()
                .weight(totalWeight)
                .length(maxLength)
                .width(maxWidth)
                .height(maxHeight)
                .build();
    }


    private CalculateRateRequest buildRateRequest(
            String cityCode,
            String districtCode,
            ParcelDimensionDTO parcel,
            BigDecimal orderTotal) {

        WarehouseSetting warehouse = warehouseSettingService.getWarehouse();

        CalculateRateRequest.AddressInfo addressFrom = CalculateRateRequest.AddressInfo.builder()
                .city(String.valueOf(warehouse.getCityId()))
                .district(String.valueOf(warehouse.getDistrictId()))
                .build();

        CalculateRateRequest.AddressInfo addressTo = CalculateRateRequest.AddressInfo.builder()
                .city(cityCode)
                .district(districtCode)
                .build();

        CalculateRateRequest.ParcelInfo parcelInfo = CalculateRateRequest.ParcelInfo.builder()
                .cod(orderTotal.longValue())
                .amount(orderTotal.longValue())
                .weight(parcel.getWeight())
                .length(parcel.getLength())
                .width(parcel.getWidth())
                .height(parcel.getHeight())
                .build();

        CalculateRateRequest.ShipmentInfo shipmentInfo = CalculateRateRequest.ShipmentInfo.builder()
                .addressFrom(addressFrom)
                .addressTo(addressTo)
                .parcel(parcelInfo)
                .build();

        log.debug("Built rate request from warehouse: {} (City: {}, District: {})",
                warehouse.getName(), warehouse.getCityId(), warehouse.getDistrictId());

        return CalculateRateRequest.builder()
                .shipment(shipmentInfo)
                .build();
    }

    private ShippingEstimateResponse processShippingRates(
            List<RateResponse> rates,
            BigDecimal productTotal) {

        if (rates == null || rates.isEmpty()) {
            log.error("No shipping rates returned from GoShip service");
            throw new IllegalStateException("No shipping rates available");
        }

        RateResponse cheapest = rates.stream()
                .min((r1, r2) -> r1.getTotalFee().compareTo(r2.getTotalFee()))
                .orElse(rates.get(0));

        BigDecimal shippingFee = cheapest.getTotalFee();
        String selectedCarrier = cheapest.getCarrierName();
        String estimatedDelivery = cheapest.getExpected();

        List<ShippingEstimateResponse.ShippingOption> availableOptions = rates.stream()
                .map(rate -> ShippingEstimateResponse.ShippingOption.builder()
                        .rateId(rate.getId())
                        .carrierName(rate.getCarrierName())
                        .carrierLogo(rate.getCarrierLogo())
                        .service(rate.getService())
                        .fee(rate.getTotalFee())
                        .estimatedDelivery(rate.getExpected())
                        .build())
                .collect(Collectors.toList());

        BigDecimal totalPrice = productTotal.add(shippingFee);

        log.info("Shipping calculation completed. Fee: {}, Carrier: {}, Total: {}",
                shippingFee, selectedCarrier, totalPrice);

        return ShippingEstimateResponse.builder()
                .productTotal(productTotal)
                .shippingFee(shippingFee)
                .totalPrice(totalPrice)
                .selectedCarrier(selectedCarrier)
                .estimatedDelivery(estimatedDelivery)
                .availableOptions(availableOptions)
                .build();
    }
}
