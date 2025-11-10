package com.greenloop.order.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateOrderRequest {

    @NotNull(message = "ID khách hàng không được để trống")
    private Long customerId;

    @NotNull(message = "Tổng giá trị đơn hàng không được để trống")
    @DecimalMin(value = "0.0", inclusive = false, message = "Tổng giá trị phải lớn hơn 0")
    private BigDecimal totalPrice;

    @NotNull(message = "Danh sách sản phẩm không được để trống")
    @Size(min = 1, message = "Đơn hàng phải có ít nhất 1 sản phẩm")
    @Valid
    private List<OrderItemRequest> orderItems;

    @NotNull(message = "Địa chỉ giao hàng không được để trống")
    @Valid
    private ShippingAddressRequest shippingAddress;
}
