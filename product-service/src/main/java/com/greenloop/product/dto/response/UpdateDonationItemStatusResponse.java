package com.greenloop.product.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class UpdateDonationItemStatusResponse {
    private List<String> updatedCodes;
    private List<String> notFoundCodes;
}

