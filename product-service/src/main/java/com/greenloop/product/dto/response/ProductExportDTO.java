package com.greenloop.product.dto.response;


import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ProductExportDTO {
    private String productId;
    private String productCode;
    private String productName;
    private String description;
    private String categoryName;
    private String donationItemId;
    private String donationCode;
    private String price;
    private String ecoPointValue;
    private String conditionGrade;
    private String status;
    private String type;
    private String createdAt;
    private String updatedAt;
    private String imageUrls;
}