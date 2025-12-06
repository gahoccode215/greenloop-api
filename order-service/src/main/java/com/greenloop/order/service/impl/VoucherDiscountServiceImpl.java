package com.greenloop.order.service.impl;

import com.greenloop.order.client.VoucherClient;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.UserVoucherResponse;
import com.greenloop.order.dto.response.VoucherDiscountResult;
import com.greenloop.order.enums.VoucherType;
import com.greenloop.order.enums.VoucherUserStatus;
import com.greenloop.order.exception.VoucherException;
import com.greenloop.order.service.VoucherDiscountService;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class VoucherDiscountServiceImpl implements VoucherDiscountService {

    private final VoucherClient voucherClient;

    @Override
    public VoucherDiscountResult validateAndCalculate(
            Long voucherUserId,
            BigDecimal subtotal) {

        if (voucherUserId == null) {
            return VoucherDiscountResult.noDiscount();
        }

        try {
            ApiResponseDTO<UserVoucherResponse> response =
                    voucherClient.validateVoucherForUser(voucherUserId);

            if (!response.isSuccess() || response.getData() == null) {
                throw new VoucherException("Voucher không hợp lệ hoặc không tồn tại");
            }

            UserVoucherResponse voucher = response.getData();

            // Validate voucher type trước tiên
            validateVoucherType(voucher);

            // Validate các điều kiện khác
            validateVoucher(voucher, subtotal);

            BigDecimal discount = calculateDiscount(voucher, subtotal);

            return VoucherDiscountResult.builder()
                    .voucherUserId(voucherUserId)
                    .voucherCode(voucher.getVoucherCode())
                    .voucherName(voucher.getVoucherName())
                    .discountAmount(discount)
                    .finalAmount(subtotal.subtract(discount))
                    .build();

        } catch (VoucherException e) {
            throw e;

        } catch (FeignException.NotFound e) {
            throw new VoucherException("Voucher không tồn tại");

        } catch (FeignException e) {
            throw new VoucherException(
                    "Không thể xác thực voucher. Vui lòng thử lại sau");
        }
    }

    /**
     * Validate voucher type - Chỉ chấp nhận PERCENT và AMOUNT cho đơn offline
     */
    private void validateVoucherType(UserVoucherResponse voucher) {
        if (voucher.getVoucherType() == null) {
            throw new VoucherException("Loại voucher không xác định");
        }

        if (voucher.getVoucherType() == VoucherType.FREESHIP) {
            throw new VoucherException(
                    String.format("Voucher '%s' là voucher miễn phí ship, " +
                                    "không áp dụng cho đơn hàng offline",
                            voucher.getVoucherCode()));
        }
    }

    private void validateVoucher(UserVoucherResponse voucher,
                                 BigDecimal subtotal) {

        if (!Boolean.TRUE.equals(voucher.getActive())) {
            throw new VoucherException(
                    String.format("Voucher '%s' không còn khả dụng",
                            voucher.getVoucherCode()));
        }

        if (voucher.getStatus() != VoucherUserStatus.AVAILABLE) {
            throw new VoucherException(
                    String.format("Voucher '%s' đã được sử dụng hoặc không khả dụng",
                            voucher.getVoucherCode()));
        }

        if (voucher.getQuantity() == null || voucher.getQuantity() <= 0) {
            throw new VoucherException(
                    String.format("Voucher '%s' đã hết lượt sử dụng",
                            voucher.getVoucherCode()));
        }

        if (voucher.getExpiryDate() != null
                && voucher.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new VoucherException(
                    String.format("Voucher '%s' đã hết hạn",
                            voucher.getVoucherCode()));
        }

        if (voucher.getMinOrderValue() != null
                && subtotal.compareTo(voucher.getMinOrderValue()) < 0) {
            throw new VoucherException(
                    String.format(
                            "Đơn hàng tối thiểu %,dđ để sử dụng voucher '%s'. " +
                                    "Giá trị hiện tại: %,dđ",
                            voucher.getMinOrderValue().longValue(),
                            voucher.getVoucherCode(),
                            subtotal.longValue()));
        }
    }

    private BigDecimal calculateDiscount(UserVoucherResponse voucher,
                                         BigDecimal subtotal) {

        BigDecimal discount;
        BigDecimal value = voucher.getValue();

        // Xử lý theo loại voucher
        if (voucher.getVoucherType() == VoucherType.PERCENT) {
            // Tính phần trăm giảm giá
            discount = subtotal
                    .multiply(value)
                    .divide(BigDecimal.valueOf(100), 2, RoundingMode.HALF_UP);

            // Áp dụng max discount nếu có
            if (voucher.getMaxDiscount() != null
                    && discount.compareTo(voucher.getMaxDiscount()) > 0) {
                discount = voucher.getMaxDiscount();
            }
        } else {
            // VoucherType.AMOUNT - Giảm giá cố định
            discount = value;
        }

        // Đảm bảo discount không vượt quá subtotal
        if (discount.compareTo(subtotal) > 0) {
            discount = subtotal;
        }

        return discount;
    }
}
