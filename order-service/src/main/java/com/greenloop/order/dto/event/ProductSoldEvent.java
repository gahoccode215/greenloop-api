package com.greenloop.order.dto.event;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProductSoldEvent implements Serializable {

    private Long productId;
    private String orderId;
    private String orderCode;
    private String newStatus;
    private LocalDateTime soldAt;
}
