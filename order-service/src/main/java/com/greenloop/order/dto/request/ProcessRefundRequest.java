package com.greenloop.order.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ProcessRefundRequest {

    @NotBlank(message = "Vui lòng upload ảnh chứng từ chuyển khoản")
    private String transferProofUrl;

    private String note;
}
