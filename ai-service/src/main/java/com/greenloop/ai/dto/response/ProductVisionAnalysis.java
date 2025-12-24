package com.greenloop.ai.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProductVisionAnalysis {

    private List<String> labels;           // ["Clothing", "T-shirt", "Blue"]
    private String detectedText;           // Text đọc được từ ảnh
    private List<String> brands;           // ["Nike", "Adidas"]
    private String suggestedName;          // Tên sản phẩm gợi ý
    private String suggestedCategory;      // Danh mục gợi ý
}
