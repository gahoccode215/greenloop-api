package com.greenloop.product.dto.response;


import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class EventProductMappingExportDTO {
    private String mappingId;
    private String eventId;
    private String eventCode;
    private String eventName;
    private String eventStartTime;
    private String eventEndTime;
    private String eventStatus;
    private String productId;
    private String productCode;
    private String productName;
    private String productPrice;
    private String productStatus;
    private String productType;
    private String categoryName;
    private String displayFrom;
    private String displayTo;
    private String mappingStatus;
    private String createdAt;
}
