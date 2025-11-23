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
    private int weight;  // grams (int for calculation)
    private int length;  // cm
    private int width;   // cm
    private int height;  // cm
}
