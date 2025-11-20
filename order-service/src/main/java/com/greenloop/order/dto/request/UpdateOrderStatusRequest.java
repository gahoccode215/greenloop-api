package com.greenloop.order.dto.request;

import com.greenloop.order.enums.OrderStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UpdateOrderStatusRequest {

    @NotNull(message = "Trạng thái đơn hàng không được để trống")
    @Schema(description = "Trạng thái mới của đơn hàng", example = "CONFIRMED")
    private OrderStatus newStatus;

    @Schema(description = "Lý do thay đổi trạng thái", example = "Đã xác nhận thanh toán")
    private String reason;
}
