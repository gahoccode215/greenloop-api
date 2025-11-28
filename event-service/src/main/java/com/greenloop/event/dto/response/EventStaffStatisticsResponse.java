package com.greenloop.event.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class EventStaffStatisticsResponse {
    private Long totalAssignments;
    private Long storeManagers;
    private List<EventStaffCount> byEvent;

    @Data
    @Builder
    public static class EventStaffCount {
        private Long eventId;
        private Long staffCount;
        private Long storeManagers;
    }
}
