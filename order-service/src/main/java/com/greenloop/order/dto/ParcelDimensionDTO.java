package com.greenloop.order.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ParcelDimensionDTO {
    private int weight;
    private int length;
    private int width;
    private int height;
}
