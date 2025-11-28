package com.greenloop.order.dto;

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
public class ProductDTO {

    private Long id;
    private String code;
    private String name;
    private String description;
    private BigDecimal price;
    private Integer ecoPointValue;
    private String conditionGrade;
    private String status;
    private String type;
    private Long categoryId;
    private String categoryName;
    private Long donationItemId;
    private String donationItemCode;
    private List<EventProductMappingDTO> eventProductMappingResponses;
    private List<ProductAssetDTO> imageUrls;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private int weight;
    private int length;
    private int width;
    private int height;
    private String eventMappingStatus;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class EventProductMappingDTO {
        private Long id;
        private Long eventId;
        private LocalDateTime displayFrom;
        private LocalDateTime displayTo;
        private String status;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ProductAssetDTO {
        private String productAssetUrl;
        private Long productAssetId;
    }
}
