package com.greenloop.order.service;

import com.greenloop.order.dto.response.VoucherDiscountResult;

import java.math.BigDecimal;

public interface VoucherDiscountService {

    VoucherDiscountResult validateAndCalculateOffline(
            Long voucherUserId,
            BigDecimal subtotal);

    VoucherDiscountResult validateAndCalculateOnline(
            Long voucherUserId,
            BigDecimal subtotal,
            BigDecimal shippingFee);
}
