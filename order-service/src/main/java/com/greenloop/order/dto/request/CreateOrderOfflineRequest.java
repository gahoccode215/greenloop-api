package com.greenloop.order.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateOrderOfflineRequest {

    @NotNull(message = "Event ID không được để trống")
    private Long eventId;

    private Long customerId;

    private Long voucherUserId;

    private String guestName;

    private String guestPhone;

    private Boolean isGuestPurchase;

    @NotEmpty(message = "Danh sách sản phẩm không được rỗng")
    private List<OrderItemOfflineRequest> items;

    @NotNull(message = "Phương thức thanh toán không được để trống")
    private String paymentMethod; // CASH hoặc BANK_TRANSFER

    private String note; // Ghi chú chung của đơn hàng
}
