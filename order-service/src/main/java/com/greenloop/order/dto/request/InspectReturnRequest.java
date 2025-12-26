package com.greenloop.order.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InspectReturnRequest {

    @NotBlank(message = "Ghi chú kiểm tra không được để trống")
    private String inspectionNote;

    private BigDecimal actualReturnShippingFee;

    private BigDecimal refundAmount;
}
