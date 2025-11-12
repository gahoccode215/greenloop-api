package com.greenloop.product.dto.request;

import com.greenloop.product.enums.DonationItemStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

@Data
public class DonationItemCodeRequest {

    @Schema(description = "List of donation item codes to check in", example = "[\"ITEM001\", \"ITEM002\"]")
    @NotEmpty(message = "Donation item codes must not be empty")
    private List<String> codes;

    private DonationItemStatus status;
}
