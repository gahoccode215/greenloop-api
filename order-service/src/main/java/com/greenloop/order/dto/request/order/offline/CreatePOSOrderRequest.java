package com.greenloop.order.dto.request.order.offline;

import com.greenloop.order.enums.PaymentMethod;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
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
public class CreatePOSOrderRequest {

    @NotNull(message = "Event location ID không được để trống")
    private Long eventLocationId;

    // Nullable cho khách vãng lai
    private Long customerId;

    // Bắt buộc nếu customerId == null
    @Pattern(regexp = "^(0|\\+84)[0-9]{9}$", message = "Số điện thoại không hợp lệ")
    private String customerPhone;

    private String customerName;

    @NotEmpty(message = "Danh sách sản phẩm không được để trống")
    private List<Long> productIds;

    @NotNull(message = "Phương thức thanh toán không được để trống")
    private PaymentMethod paymentMethod;

    // Số tiền mặt (cho CASH hoặc MIXED)
    @Positive(message = "Số tiền mặt phải > 0")
    private BigDecimal cashAmount;

    // Số điểm sử dụng (cho ECO_POINT hoặc MIXED)
    @Positive(message = "Số điểm sử dụng phải > 0")
    private Integer ecoPointsUsed;

    @NotNull(message = "Staff ID không được để trống")
    private Long staffId;

    private String notes;

    // Custom validation
    public void validate() {
        // Khách vãng lai phải có SĐT
        if (customerId == null && (customerPhone == null || customerPhone.isBlank())) {
            throw new IllegalArgumentException("Khách vãng lai phải cung cấp số điện thoại");
        }

        // ECO_POINT/MIXED phải có customerId
        if ((paymentMethod == PaymentMethod.ECO_POINT || paymentMethod == PaymentMethod.MIXED)
                && customerId == null) {
            throw new IllegalArgumentException("Khách vãng lai không thể thanh toán bằng điểm");
        }

        // Validate theo payment method
        switch (paymentMethod) {
            case CASH:
                // cashAmount có thể null, sẽ tự tính = totalAmount
                break;
            case ECO_POINT:
                if (ecoPointsUsed == null || ecoPointsUsed <= 0) {
                    throw new IllegalArgumentException("Phải nhập số điểm sử dụng");
                }
                break;
            case MIXED:
                if (cashAmount == null || cashAmount.compareTo(BigDecimal.ZERO) <= 0) {
                    throw new IllegalArgumentException("Thanh toán hỗn hợp phải có số tiền mặt");
                }
                if (ecoPointsUsed == null || ecoPointsUsed <= 0) {
                    throw new IllegalArgumentException("Thanh toán hỗn hợp phải có số điểm");
                }
                break;
        }
    }
}
