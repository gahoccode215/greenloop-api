package com.greenloop.order.service;

import com.greenloop.order.dto.ParcelDimensionDTO;
import com.greenloop.order.dto.response.ShippingEstimateResponse;
import com.greenloop.order.entity.CartItem;
import com.greenloop.order.goship.dto.CalculateRateRequest;
import com.greenloop.order.goship.dto.RateResponse;
import com.greenloop.order.goship.service.GoShipService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ShippingCalculationService {

    private final GoShipService goShipService;

    @Value("${goship.default-warehouse.city}")
    private String defaultWarehouseCity;

    @Value("${goship.default-warehouse.district}")
    private String defaultWarehouseDistrict;

    public ShippingEstimateResponse calculateShippingFee(
            List<CartItem> cartItems,
            BigDecimal productTotal,
            String cityCode,
            String districtCode) {

        ParcelDimensionDTO parcel = calculateParcelDimensions(cartItems);


        CalculateRateRequest rateRequest = buildRateRequest(cityCode, districtCode, parcel, productTotal);

        List<RateResponse> rates = goShipService.calculateShippingRates(rateRequest);

        return processShippingRates(rates, productTotal);
    }


    public ParcelDimensionDTO calculateParcelDimensions(List<CartItem> cartItems) {
        int totalWeight = 0;
        int maxLength = 0;
        int maxWidth = 0;
        int totalHeight = 0;

        for (CartItem item : cartItems) {
            totalWeight += item.getWeight();
            maxLength = Math.max(maxLength, item.getLength());
            maxWidth = Math.max(maxWidth, item.getWidth());
            totalHeight += item.getHeight();
        }

        int finalHeight = Math.min(totalHeight, 100);

        return ParcelDimensionDTO.builder()
                .weight(totalWeight)
                .length(maxLength)
                .width(maxWidth)
                .height(finalHeight)
                .build();
    }

    private CalculateRateRequest buildRateRequest(
            String cityCode,
            String districtCode,
            ParcelDimensionDTO parcel,
            BigDecimal orderTotal) {

        CalculateRateRequest.AddressInfo addressFrom = CalculateRateRequest.AddressInfo.builder()
                .city(defaultWarehouseCity)
                .district(defaultWarehouseDistrict)
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

        return CalculateRateRequest.builder()
                .shipment(shipmentInfo)
                .build();
    }

    /**
     * Xử lý kết quả từ GoShip API và trả về response
     */
    private ShippingEstimateResponse processShippingRates(List<RateResponse> rates, BigDecimal productTotal) {
        BigDecimal shippingFee;
        String selectedCarrier;
        String estimatedDelivery;
        List<ShippingEstimateResponse.ShippingOption> availableOptions;

        if (!rates.isEmpty()) {
            // Chọn option rẻ nhất
            RateResponse cheapest = rates.stream()
                    .min((r1, r2) -> r1.getTotalAmount().compareTo(r2.getTotalAmount()))
                    .orElse(rates.get(0));

            shippingFee = cheapest.getTotalAmount();
            selectedCarrier = cheapest.getCarrierName();
            estimatedDelivery = cheapest.getExpected();

            // Map tất cả options
            availableOptions = rates.stream()
                    .map(rate -> ShippingEstimateResponse.ShippingOption.builder()
                            .rateId(rate.getId())
                            .carrierName(rate.getCarrierName())
                            .carrierLogo(rate.getCarrierLogo())
                            .service(rate.getService())
                            .fee(rate.getTotalAmount())
                            .estimatedDelivery(rate.getExpected())
                            .build())
                    .collect(Collectors.toList());

            log.info("✅ Tìm thấy {} lựa chọn vận chuyển. Rẻ nhất: {} - {}đ",
                    rates.size(), selectedCarrier, shippingFee);

        } else {
            shippingFee = BigDecimal.valueOf(30000);
            selectedCarrier = "Vận chuyển tiêu chuẩn";
            estimatedDelivery = "3-5 ngày";
            availableOptions = List.of();
        }

        BigDecimal totalPrice = productTotal.add(shippingFee);

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
