package com.greenloop.order.dto.request;

import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.math.BigDecimal;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class InspectReturnRequestRequest {

    @NotNull(message = "Vui lòng xác nhận kết quả kiểm tra")
    private Boolean inspectionResult;

    private String inspectionNote;

    private List<String> inspectionImages;

    @NotNull(message = "Phí vận chuyển thực tế không được để trống")
    private BigDecimal actualReturnShippingFee;
}
