package com.greenloop.order.dto.request;

import com.greenloop.order.enums.PaymentMethod;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CheckoutRequest {
    @NotNull
    @Valid
    private CheckoutShippingAddressRequest shippingAddress;

    @NotNull
    private PaymentMethod paymentMethod;

    @NotBlank
    private String selectedRateId;

    @Builder.Default
    private String platform = "web";
}
