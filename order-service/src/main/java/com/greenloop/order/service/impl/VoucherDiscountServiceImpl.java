package com.greenloop.order.service.impl;

import com.greenloop.order.client.VoucherClient;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.UserVoucherResponse;
import com.greenloop.order.dto.response.VoucherDiscountResult;
import com.greenloop.order.enums.VoucherUserStatus;
import com.greenloop.order.exception.VoucherException;
import com.greenloop.order.service.VoucherDiscountService;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class VoucherDiscountServiceImpl implements VoucherDiscountService {

    private final VoucherClient voucherClient;

    @Override
    public VoucherDiscountResult validateAndCalculate(
            Long voucherUserId,
            BigDecimal subtotal) {

        if (voucherUserId == null) {
            log.debug("No voucher provided, returning zero discount");
            return VoucherDiscountResult.noDiscount();
        }

        try {
            log.info("Validating voucher user ID: {} for subtotal: {}",
                    voucherUserId, subtotal);

            // 1. Call Reward Service
            ApiResponseDTO<UserVoucherResponse> response =
                    voucherClient.validateVoucherForUser(voucherUserId);

            if (!response.isSuccess() || response.getData() == null) {
                log.error("Voucher validation failed for ID: {}", voucherUserId);
                throw new VoucherException("Voucher không hợp lệ hoặc không tồn tại");
            }

            UserVoucherResponse voucher = response.getData();
            log.debug("Voucher found: {}", voucher.getVoucherCode());

            // 2. Validate voucher
            validateVoucher(voucher, subtotal);

            // 3. Calculate discount
            BigDecimal discount = calculateDiscount(voucher, subtotal);

            log.info("Voucher {} applied successfully. Discount: {}",
                    voucher.getVoucherCode(), discount);

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
            log.error("Voucher not found: {}", voucherUserId);
            throw new VoucherException("Voucher không tồn tại");

        } catch (FeignException e) {
            log.error("Error calling Reward Service: {}", e.getMessage(), e);
            throw new VoucherException(
                    "Không thể xác thực voucher. Vui lòng thử lại sau");
        }
    }

    private void validateVoucher(UserVoucherResponse voucher,
                                 BigDecimal subtotal) {

        // Check 1: Active status
        if (!Boolean.TRUE.equals(voucher.getActive())) {
            log.warn("Voucher {} is not active", voucher.getVoucherCode());
            throw new VoucherException(
                    String.format("Voucher '%s' không còn khả dụng",
                            voucher.getVoucherCode()));
        }

        // Check 2: Voucher user status
        if (voucher.getStatus() != VoucherUserStatus.AVAILABLE) {
            log.warn("Voucher {} status is {}, expected AVAILABLE",
                    voucher.getVoucherCode(), voucher.getStatus());
            throw new VoucherException(
                    String.format("Voucher '%s' đã được sử dụng hoặc không khả dụng",
                            voucher.getVoucherCode()));
        }

        // Check 3: Quantity
        if (voucher.getQuantity() == null || voucher.getQuantity() <= 0) {
            log.warn("Voucher {} has no remaining quantity",
                    voucher.getVoucherCode());
            throw new VoucherException(
                    String.format("Voucher '%s' đã hết lượt sử dụng",
                            voucher.getVoucherCode()));
        }

        // Check 4: Expiry date
        if (voucher.getExpiryDate() != null
                && voucher.getExpiryDate().isBefore(LocalDateTime.now())) {
            log.warn("Voucher {} expired at {}",
                    voucher.getVoucherCode(), voucher.getExpiryDate());
            throw new VoucherException(
                    String.format("Voucher '%s' đã hết hạn",
                            voucher.getVoucherCode()));
        }

        // Check 5: Min order value
        if (voucher.getMinOrderValue() != null
                && subtotal.compareTo(voucher.getMinOrderValue()) < 0) {
            log.warn("Subtotal {} is less than min order value {} for voucher {}",
                    subtotal, voucher.getMinOrderValue(), voucher.getVoucherCode());
            throw new VoucherException(
                    String.format(
                            "Đơn hàng tối thiểu %,dđ để sử dụng voucher '%s'. " +
                                    "Giá trị hiện tại: %,dđ",
                            voucher.getMinOrderValue().longValue(),
                            voucher.getVoucherCode(),
                            subtotal.longValue()));
        }

        log.debug("Voucher {} passed all validation checks",
                voucher.getVoucherCode());
    }

    private BigDecimal calculateDiscount(UserVoucherResponse voucher,
                                         BigDecimal subtotal) {

        BigDecimal discount;
        BigDecimal value = voucher.getValue();

        // PERCENTAGE discount (value < 100)
        if (value.compareTo(BigDecimal.valueOf(100)) < 0) {
            log.debug("Calculating percentage discount: {}%", value);

            discount = subtotal
                    .multiply(value)
                    .divide(BigDecimal.valueOf(100), 2, RoundingMode.HALF_UP);

            log.debug("Percentage discount calculated: {}", discount);

            // Apply max discount cap
            if (voucher.getMaxDiscount() != null
                    && discount.compareTo(voucher.getMaxDiscount()) > 0) {
                log.debug("Discount {} exceeds max {}, applying cap",
                        discount, voucher.getMaxDiscount());
                discount = voucher.getMaxDiscount();
            }
        }
        // FIXED_AMOUNT discount (value >= 100)
        else {
            log.debug("Applying fixed discount amount: {}", value);
            discount = value;
        }

        // Discount cannot exceed subtotal
        if (discount.compareTo(subtotal) > 0) {
            log.debug("Discount {} exceeds subtotal {}, capping to subtotal",
                    discount, subtotal);
            discount = subtotal;
        }

        log.debug("Final discount amount: {}", discount);
        return discount;
    }
}
