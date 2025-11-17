package com.greenloop.order.dto.request;

import com.greenloop.order.enums.OrderStatus;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateOrderStatusRequest {
    @NotNull(message = "Trạng thái đơn hàng không được rỗng")
    private OrderStatus status;

    private String name;
    private String phone;
    private String address;
    private String wardCode;
    private Integer districtId;
    private Integer provinceId;
}

