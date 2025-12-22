package com.greenloop.order.dto.request;

import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.math.BigDecimal;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApproveReturnRequestRequest {

    @NotNull(message = "Vui lòng xác nhận duyệt hoặc từ chối")
    private Boolean approved;

    private String rejectedReason;

    private BigDecimal estimatedReturnShippingFee;
}
