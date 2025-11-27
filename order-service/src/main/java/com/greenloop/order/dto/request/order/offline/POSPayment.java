package com.greenloop.order.dto.request.order.offline;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class POSPayment {

    @NotBlank(message = "Payment method không được để trống")
    @Pattern(regexp = "CASH|QR_CODE", message = "Payment method phải là CASH hoặc QR_CODE")
    private String method;


    @NotNull(message = "Received amount không được để trống")
    @DecimalMin(value = "0", message = "Received amount phải lớn hơn 0")
    private BigDecimal receivedAmount;
}
