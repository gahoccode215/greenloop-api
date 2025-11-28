package com.greenloop.product.dto.response;

import com.greenloop.product.enums.EventMappingStatus;
import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class EventProductMappingStatisticsResponse {
    private Long totalMappings;
    private Map<EventMappingStatus, Long> mappingsByStatus;
    private List<EventProductCount> eventProductCounts;

    @Data
    @Builder
    public static class EventProductCount {
        private Long eventId;
        private Long productCount;
    }
}

