package com.greenloop.product.dto.request;

import com.greenloop.product.enums.DonationItemStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Data
@Builder
@Getter
@Setter
public class UpdateDonationItemStatusRequest {
    @Schema(description = "List of donation item codes to check in", example = "[\"ITEM001\", \"ITEM002\"]")
    @NotEmpty(message = "Donation item codes must not be empty")
    private List<String> donationItemCodes;
    private DonationItemStatus donationItemStatus;
}
