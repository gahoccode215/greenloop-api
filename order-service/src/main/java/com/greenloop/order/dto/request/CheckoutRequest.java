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

    @NotNull(message = "Thông tin giao hàng không được để trống")
    @Valid
    private CheckoutShippingAddressRequest shippingAddress;

    @NotNull(message = "Phương thức thanh toán không được để trống")
    private PaymentMethod paymentMethod;

    @NotBlank(message = "Vui lòng chọn đơn vị vận chuyển")
    @Schema(description = "Selected shipping rate ID (required)", example = "MTRfMTFfMTAwMg==", required = true)
    private String selectedRateId;

    @Schema(description = "Platform: web or mobile", example = "web", defaultValue = "web")
    @Builder.Default
    private String platform = "web";
}
