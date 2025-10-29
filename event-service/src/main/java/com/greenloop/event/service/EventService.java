package com.greenloop.event.service;

import com.greenloop.event.dto.request.EventRequest;
import com.greenloop.event.dto.response.EventDetailResponse;
import com.greenloop.event.dto.response.EventResponse;
import com.greenloop.event.enums.EventStatus;
import java.time.LocalDateTime;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

public interface EventService {

  Long createEvent(EventRequest request, MultipartFile multipartFile);

  Page<EventResponse> getEventsByFilterByCustomer(
      String code,
      EventStatus status,
      String search,
      LocalDateTime startTime,
      LocalDateTime endTime,
      LocalDateTime createdAtStart,
      LocalDateTime createdAtEnd,
      Pageable pageable,
      boolean isAdmin);

  EventDetailResponse getEventByIdWithRole(Long id, boolean isAdmin);

  Long updateEvent(Long id, EventRequest request, MultipartFile multipartFile);

  Long activateEvent(Long id);
}
