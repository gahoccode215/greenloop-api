package com.greenloop.order.query;

import com.greenloop.order.dto.request.OrderFilterRequest;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class GetAllOrdersQuery {
    private OrderFilterRequest filter;
    private Long requestingUserId;
}
