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
    private Long productId;
    private String selectedRateId;
    private CheckoutShippingAddressRequest shippingAddress;
    private Long voucherUserId;
    private PaymentMethod paymentMethod;
    private String platform;
}
