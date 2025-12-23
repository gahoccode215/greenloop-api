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
public class RejectReturnRequestRequest {

    @NotBlank(message = "Lý do từ chối không được để trống")
    private String rejectedReason;
}
