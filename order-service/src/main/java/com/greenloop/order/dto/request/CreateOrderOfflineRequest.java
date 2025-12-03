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

    @NotNull(message = "Event ID is required")
    private Long eventId;

    /**
     * Customer ID (nullable - nếu null thì là guest)
     */
    private Long customerId;

    /**
     * Voucher User ID (nullable - nếu có thì apply voucher)
     */
    private Long voucherUserId;

    /**
     * Guest information (required if customerId is null)
     */
    private String guestName;
    private String guestPhone;

    @NotEmpty(message = "Order items cannot be empty")
    private List<OrderItemOfflineRequest> items;

    @NotNull(message = "Payment method is required")
    private String paymentMethod;

    private String note;
}
