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

    // ========== RAW DATA (từ Vision API) ==========
    private List<String> labels;           // ["Clothing", "T-shirt", "Blue", "Cotton"]
    private String detectedText;           // Text đọc được từ ảnh
    private List<String> brands;           // ["Nike", "Adidas"]

    // ========== AUTO-FILL DATA (cho form) ==========
    private String suggestedName;          // "Áo Thun Nike Xanh Size M"
    private String suggestedDescription;   // Mô tả chi tiết (max 2000 chars)
    private String suggestedConditionGrade; // "NEW", "LIKE_NEW", "GOOD", "FAIR", "POOR"

    // ========== ADDITIONAL INFO ==========
    private Double confidence;             // 0.0-1.0 (độ tin cậy tổng thể)
}
