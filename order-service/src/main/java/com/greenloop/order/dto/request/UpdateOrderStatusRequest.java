package com.greenloop.order.dto.request;

import com.greenloop.order.enums.OrderStatus;
import jakarta.validation.constraints.NotNull;
import lombok.Data;


@Data
public class UpdateOrderStatusRequest {
    @NotNull(message = "Trạng thái đơn hàng không được rỗng")
    private OrderStatus status;
}

