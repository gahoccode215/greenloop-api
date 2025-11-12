package com.greenloop.product.dto.request;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.List;

@Data
public class DonationCreateRequest {

    @NotNull(message = "User ID is required")
    private Long userId;

    @NotNull(message = "Event ID is required")
    private Long eventId;

    @NotNull(message = "Total weight is required")
    @DecimalMin(value = "0.0", inclusive = false, message = "Total weight must be greater than 0")
    private Float totalWeight;

    @Size(max = 2000, message = "Note must not exceed 2000 characters")
    private String note;

    @NotEmpty(message = "Donation must include at least one item")
    private List<DonationItemCreateRequest> donationItems;
}
