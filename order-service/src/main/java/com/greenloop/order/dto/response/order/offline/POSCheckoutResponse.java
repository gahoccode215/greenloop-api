package com.greenloop.order.dto.response.order.offline;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class POSCheckoutResponse {

    private String orderId;


    private String orderCode;

    private String orderType;


    private BigDecimal totalAmount;



    /**
     * Phương thức thanh toán
     */
    private String paymentMethod;

    /**
     * Trạng thái thanh toán
     * PAID (CASH) hoặc UNPAID (QR_CODE chờ webhook)
     */
    private String paymentStatus;

    /**
     * PayOS payment URL (chỉ có khi QR_CODE)
     */
    private String paymentUrl;

    /**
     * PayOS orderCode (chỉ có khi QR_CODE)
     */
    private Long paymentOrderCode;

    /**
     * Danh sách sản phẩm đã mua
     */
    private List<POSSoldItem> items;

    /**
     * Thông tin khách hàng
     */
    private POSCustomerInfo customer;

    /**
     * Số Eco Points tích được (null nếu GUEST)
     */
    private Integer ecoPointsEarned;

    /**
     * Thời gian tạo đơn
     */
    private LocalDateTime createdAt;
}
