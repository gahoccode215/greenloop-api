package com.greenloop.product.dto.response;

import com.greenloop.product.enums.ConditionGrade;
import com.greenloop.product.enums.EventMappingStatus;
import com.greenloop.product.enums.ProductStatus;
import com.greenloop.product.enums.ProductType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProductResponse {
    private Long id;
    private String code;
    private String name;
    private String description;
    private BigDecimal price;
    private Integer ecoPointValue;
    private ConditionGrade conditionGrade;
    private ProductStatus status;
    private ProductType type;
    private Long categoryId;
    private String categoryName;
    private Long donationItemId;
    private String donationItemCode;
    private List<EventProductMappingResponse> eventProductMappingResponses;
    private List<ProductAssetResponse> imageUrls;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private int weight;
    private int length;
    private int width;
    private int height;
    private EventMappingStatus eventMappingStatus;
    private Boolean isEventReadyForSelling;
}
