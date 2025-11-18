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
        private String rateId;           // Rate ID để dùng khi checkout
        private String carrierName;      // Tên đơn vị vận chuyển
        private String carrierLogo;      // Logo URL
        private String service;          // Loại dịch vụ
        private BigDecimal fee;          // Phí vận chuyển
        private String estimatedDelivery; // Thời gian dự kiến
    }
}
