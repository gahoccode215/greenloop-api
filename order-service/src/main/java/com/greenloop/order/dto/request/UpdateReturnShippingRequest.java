package com.greenloop.order.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateReturnShippingRequest {

    @NotBlank(message = "Mã vận đơn không được để trống")
    private String returnShipmentId;

    @NotBlank(message = "Đơn vị vận chuyển không được để trống")
    private String returnCarrier;

    private String returnTrackingUrl;
}
