package com.greenloop.order.dto.response;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PayOSPaymentResponse {
    private String checkoutUrl;
    private Long paymentOrderCode;
}
