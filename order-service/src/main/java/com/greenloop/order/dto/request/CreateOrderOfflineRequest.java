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

    @NotNull()
    private Long eventId;

    private Long customerId;

    private Long voucherUserId;

    private String guestName;

    private String guestPhone;

    private Boolean isGuestPurchase;

    @NotEmpty
    private List<OrderItemOfflineRequest> items;

    private String paymentMethod;

    private String note;
}
