package com.greenloop.event.dto.response;

import com.greenloop.event.enums.EventStatus;
import java.time.LocalDateTime;
import java.util.HashMap;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Builder
public class EventDetailResponse {
  private Long id;
  private String code;
  private String name;
  private String description;
  private String imageUrl;
  private String locationDetail;
  private String latitude;
  private String longitude;
  private LocalDateTime startTime;
  private LocalDateTime endTime;
  private EventStatus status;
  private HashMap<String, String> googlePlaceId;
  private Integer totalRegistrations;
  private Integer totalStaffs;
  private Boolean isRegistered;
  private Boolean isActive;
  private Long createdBy;
  private String createByName;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;
  private Long updatedBy;
  private String updatedByName;
}
