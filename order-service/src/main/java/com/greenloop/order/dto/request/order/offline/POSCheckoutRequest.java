package com.greenloop.order.dto.request.order.offline;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class POSCheckoutRequest {

    @NotNull(message = "Event location ID không được để trống")
    private Long eventLocationId;

    private Long staffId;


    @NotEmpty(message = "Giỏ hàng không được trống")
    @Valid
    private List<Long> productIds;


    @NotNull(message = "Thông tin khách hàng không được để trống")
    @Valid
    private POSCustomer customer;


    @NotNull(message = "Thông tin thanh toán không được để trống")
    @Valid
    private POSPayment payment;


    private String note;
}
