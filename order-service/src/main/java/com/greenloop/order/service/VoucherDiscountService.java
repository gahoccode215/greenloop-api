package com.greenloop.order.service;

import com.greenloop.order.dto.response.VoucherDiscountResult;

import java.math.BigDecimal;

public interface VoucherDiscountService {

    VoucherDiscountResult validateAndCalculate(Long voucherUserId, BigDecimal subtotal);
}
