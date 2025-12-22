package com.greenloop.order.dto.feign;

import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data
@Builder
public class UnreserveProductsRequest {
    private String orderId;
    private List<Long> productIds;
}
