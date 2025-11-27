package com.greenloop.order.dto.response.order.offline;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class POSSoldItem {


    private Long productId;

    private String productName;


    private String imageUrl;

    private BigDecimal price;
}
