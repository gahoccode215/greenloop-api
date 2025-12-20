package com.greenloop.order.dto.request;

import com.greenloop.order.enums.PaymentMethod;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DirectCheckoutRequest {
    private Long productId;                    // ID sản phẩm muốn mua
    private String selectedRateId;             // Đơn vị vận chuyển
    private CheckoutShippingAddressRequest shippingAddress;  // Địa chỉ giao hàng
    private Long voucherUserId;                // Voucher (optional)
    private PaymentMethod paymentMethod;       // COD hoặc PAYOS
    private String platform;                   // "web" hoặc "mobile" (cho PayOS)
}
