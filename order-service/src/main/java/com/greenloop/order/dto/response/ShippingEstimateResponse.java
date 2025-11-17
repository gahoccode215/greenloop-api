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

    /**
     * Tổng tiền sản phẩm
     */
    private BigDecimal productTotal;

    /**
     * Phí vận chuyển (đã chọn option rẻ nhất)
     */
    private BigDecimal shippingFee;

    /**
     * Tổng tiền = productTotal + shippingFee
     */
    private BigDecimal totalPrice;

    /**
     * Đơn vị vận chuyển đã chọn
     */
    private String selectedCarrier;

    /**
     * Thời gian giao hàng dự kiến
     */
    private String estimatedDelivery;

    /**
     * Danh sách các lựa chọn vận chuyển (optional - để customer chọn)
     */
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
