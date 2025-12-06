package com.greenloop.product.dto.request;

import com.greenloop.product.enums.EventMappingStatus;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Builder
@Setter
public class UpdateStatusProductEventMappingRequest {
    @NotNull(message = "Event ID cannot be null")
    private Long eventId;
    @NotNull(message = "Product IDs cannot be null")
    private List<Long> productIds;
    @NotNull(message = "Status cannot be null")
    private EventMappingStatus status;
}
