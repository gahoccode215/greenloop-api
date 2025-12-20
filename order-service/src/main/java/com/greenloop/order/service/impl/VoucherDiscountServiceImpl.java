package com.greenloop.order.service.impl;

import com.greenloop.order.client.RewardClient;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.UserVoucherResponse;
import com.greenloop.order.dto.response.VoucherDiscountResult;
import com.greenloop.order.enums.VoucherType;
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

@Slf4j
@Service
@RequiredArgsConstructor
public class VoucherDiscountServiceImpl implements VoucherDiscountService {

    private final RewardClient rewardClient;

    /**
     * Validate và tính discount cho đơn OFFLINE
     * Không cho phép voucher FREESHIP
     */
    @Override
    public VoucherDiscountResult validateAndCalculateOffline(
            Long voucherUserId,
            BigDecimal subtotal) {

        if (voucherUserId == null) {
            return VoucherDiscountResult.noDiscount();
        }

        try {
            ApiResponseDTO<UserVoucherResponse> response =
                    rewardClient.validateVoucherForUser(voucherUserId);

            if (!response.isSuccess() || response.getData() == null) {
                throw new VoucherException("Voucher không hợp lệ hoặc không tồn tại");
            }

            UserVoucherResponse voucher = response.getData();

            if (voucher.getVoucherType() == VoucherType.FREESHIP) {
                throw new VoucherException(
                        String.format("Voucher '%s' là voucher miễn phí ship, " +
                                        "không áp dụng cho đơn hàng offline",
                                voucher.getVoucherCode()));
            }

            validateVoucher(voucher, subtotal);

            BigDecimal discount = calculateDiscount(voucher, subtotal);

            log.info("Offline voucher applied - Code: {}, Subtotal: {}, Discount: {}",
                    voucher.getVoucherCode(), subtotal, discount);

            return VoucherDiscountResult.builder()
                    .voucherUserId(voucherUserId)
                    .voucherCode(voucher.getVoucherCode())
                    .voucherName(voucher.getVoucherName())
                    .discountAmount(discount)
                    .finalAmount(subtotal.subtract(discount))
                    .shippingDiscount(BigDecimal.ZERO)
                    .isFreeShip(false)
                    .discountType("PRODUCT")
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
     * Validate và tính discount cho đơn ONLINE
     * Cho phép voucher FREESHIP, PERCENT, AMOUNT
     */
    @Override
    public VoucherDiscountResult validateAndCalculateOnline(
            Long voucherUserId,
            BigDecimal subtotal,
            BigDecimal shippingFee) {

        if (voucherUserId == null) {
            return VoucherDiscountResult.noDiscount();
        }

        try {
            ApiResponseDTO<UserVoucherResponse> response =
                    rewardClient.validateVoucherForUser(voucherUserId);

            if (!response.isSuccess() || response.getData() == null) {
                throw new VoucherException("Voucher không hợp lệ hoặc không tồn tại");
            }

            UserVoucherResponse voucher = response.getData();

            validateVoucher(voucher, subtotal);

            BigDecimal productDiscount = BigDecimal.ZERO;
            BigDecimal shippingDiscount = BigDecimal.ZERO;
            Boolean isFreeShip = false;
            String discountType;

            if (voucher.getVoucherType() == VoucherType.FREESHIP) {
                shippingDiscount = shippingFee;

                if (voucher.getMaxDiscount() != null
                        && shippingDiscount.compareTo(voucher.getMaxDiscount()) > 0) {
                    shippingDiscount = voucher.getMaxDiscount();
                    log.info("FREESHIP capped by maxDiscount: {} -> {}",
                            shippingFee, shippingDiscount);
                }

                isFreeShip = shippingDiscount.compareTo(shippingFee) == 0;
                discountType = "SHIPPING";

            } else if (voucher.getVoucherType() == VoucherType.PERCENT) {
                productDiscount = subtotal
                        .multiply(voucher.getValue())
                        .divide(BigDecimal.valueOf(100), 2, RoundingMode.HALF_UP);

                if (voucher.getMaxDiscount() != null
                        && productDiscount.compareTo(voucher.getMaxDiscount()) > 0) {
                    productDiscount = voucher.getMaxDiscount();
                    log.info("PERCENT capped by maxDiscount: {} -> {}",
                            subtotal.multiply(voucher.getValue()).divide(BigDecimal.valueOf(100), 2, RoundingMode.HALF_UP),
                            productDiscount);
                }

                if (productDiscount.compareTo(subtotal) > 0) {
                    productDiscount = subtotal;
                }
                discountType = "PRODUCT";

            } else if (voucher.getVoucherType() == VoucherType.AMOUNT) {
                productDiscount = voucher.getValue();

                if (voucher.getMaxDiscount() != null
                        && productDiscount.compareTo(voucher.getMaxDiscount()) > 0) {
                    productDiscount = voucher.getMaxDiscount();
                    log.info("AMOUNT capped by maxDiscount: {} -> {}",
                            voucher.getValue(), productDiscount);
                }

                if (productDiscount.compareTo(subtotal) > 0) {
                    productDiscount = subtotal;
                }
                discountType = "PRODUCT";

            } else {
                throw new VoucherException("Loại voucher không được hỗ trợ");
            }

            BigDecimal finalAmount = subtotal.subtract(productDiscount)
                    .add(shippingFee.subtract(shippingDiscount));

            log.info("Online voucher applied - Code: {}, Type: {}, Subtotal: {}, ShippingFee: {}, " +
                            "ProductDiscount: {}, ShippingDiscount: {}, FinalAmount: {}",
                    voucher.getVoucherCode(), voucher.getVoucherType(), subtotal, shippingFee,
                    productDiscount, shippingDiscount, finalAmount);

            return VoucherDiscountResult.builder()
                    .voucherUserId(voucherUserId)
                    .voucherCode(voucher.getVoucherCode())
                    .voucherName(voucher.getVoucherName())
                    .discountAmount(productDiscount)
                    .shippingDiscount(shippingDiscount)
                    .isFreeShip(isFreeShip)
                    .discountType(discountType)
                    .finalAmount(finalAmount)
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
     * Validate các điều kiện chung của voucher
     */
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

    /**
     * Tính discount cho voucher PERCENT hoặc AMOUNT (cho đơn offline)
     */
    private BigDecimal calculateDiscount(UserVoucherResponse voucher,
                                         BigDecimal subtotal) {

        BigDecimal discount;
        BigDecimal value = voucher.getValue();

        if (voucher.getVoucherType() == VoucherType.PERCENT) {
            discount = subtotal
                    .multiply(value)
                    .divide(BigDecimal.valueOf(100), 2, RoundingMode.HALF_UP);

            if (voucher.getMaxDiscount() != null
                    && discount.compareTo(voucher.getMaxDiscount()) > 0) {
                discount = voucher.getMaxDiscount();
            }

        } else if (voucher.getVoucherType() == VoucherType.AMOUNT) {
            discount = value;

            if (voucher.getMaxDiscount() != null
                    && discount.compareTo(voucher.getMaxDiscount()) > 0) {
                discount = voucher.getMaxDiscount();
            }

        } else {
            throw new VoucherException("Loại voucher không được hỗ trợ cho đơn offline");
        }

        // Không được vượt quá subtotal
        if (discount.compareTo(subtotal) > 0) {
            discount = subtotal;
        }

        return discount;
    }
}
