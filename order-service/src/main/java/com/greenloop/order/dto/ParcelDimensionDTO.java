package com.greenloop.order.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ParcelDimensionDTO {
    private Integer weight;
    private Integer length;
    private Integer width;
    private Integer height;
}
