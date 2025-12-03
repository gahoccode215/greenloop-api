package com.greenloop.order.service;

import com.greenloop.order.dto.response.VoucherDiscountResult;

import java.math.BigDecimal;

public interface VoucherDiscountService {

    /**
     * Validate voucher và tính toán discount
     *
     * @param voucherUserId ID của voucher user
     * @param subtotal Tổng tiền trước khi giảm giá
     * @return VoucherDiscountResult chứa thông tin discount
     * @throws com.greenloop.order.exception.VoucherException nếu voucher không hợp lệ
     */
    VoucherDiscountResult validateAndCalculate(Long voucherUserId, BigDecimal subtotal);
}
