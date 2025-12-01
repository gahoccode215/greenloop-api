package com.greenloop.order.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ShippingEstimateResponse {
    private BigDecimal productTotal;
    private BigDecimal shippingFee;
    private BigDecimal totalPrice;
    private String selectedCarrier;
    private String estimatedDelivery;
    private List<ShippingOption> availableOptions;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ShippingOption {
        private String rateId;
        private String carrierName;
        private String carrierLogo;
        private String service;
        private BigDecimal fee;
        private String estimatedDelivery;
    }
}
