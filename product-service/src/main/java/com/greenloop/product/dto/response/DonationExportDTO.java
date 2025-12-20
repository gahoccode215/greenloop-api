package com.greenloop.product.dto.response;


import lombok.*;
import java.time.LocalDateTime;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DonationExportDTO {
    private String donationId;
    private String donationCode;
    private String userId;
    private String eventId;
    private String eventCode;
    private String eventName;
    private String donationNote;
    private String inspectedBy;
    private String inspectorName;
    private String donationCreatedAt;

    private String itemId;
    private String itemCode;
    private String itemName;
    private String itemDescription;
    private String categoryName;
    private String conditionGrade;
    private String ecoPointValue;
    private String itemStatus;
    private String convertProductId;
    private String imageUrl;
}