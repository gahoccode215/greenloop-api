package com.greenloop.order.service;

import com.greenloop.order.dto.response.VoucherDiscountResult;

import java.math.BigDecimal;

public interface VoucherDiscountService {

    /**
     * Validate và tính discount cho đơn hàng OFFLINE
     * Không cho phép voucher FREESHIP
     */
    VoucherDiscountResult validateAndCalculateOffline(
            Long voucherUserId,
            BigDecimal subtotal);

    /**
     * Validate và tính discount cho đơn hàng ONLINE
     * Cho phép voucher FREESHIP, PERCENT, AMOUNT
     */
    VoucherDiscountResult validateAndCalculateOnline(
            Long voucherUserId,
            BigDecimal subtotal,
            BigDecimal shippingFee);
}
