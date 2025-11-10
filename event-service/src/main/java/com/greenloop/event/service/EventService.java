package com.greenloop.event.service;

import com.greenloop.event.dto.request.*;
import com.greenloop.event.dto.response.*;
import com.greenloop.event.enums.EventStatus;
import com.greenloop.event.enums.RegistrationStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.List;

public interface EventService {

    Long createEvent(EventRequest request, MultipartFile multipartFile);

    Page<EventResponse> getEventsForCustomer(
            String code,
            EventStatus status,
            String search,
            LocalDateTime startTime,
            LocalDateTime endTime,
            LocalDateTime createdAtStart,
            LocalDateTime createdAtEnd,
            Pageable pageable);

    Page<EventResponse> getEventsForAdmin(
            String code,
            EventStatus status,
            String search,
            LocalDateTime startTime,
            LocalDateTime endTime,
            LocalDateTime createdAtStart,
            LocalDateTime createdAtEnd,
            Pageable pageable);

    EventDetailResponse getEventByIdForAdmin(Long id);

    EventDetailResponse getEventByIdForCustomer(Long id);

    Long updateEvent(Long id, EventUpdateRequest request);

    Long activateEvent(Long id);

    Long uploadEventThumbnail(Long id, MultipartFile multipartFile);

    Long updateEventStatus(Long id, EventStatus status);

    void assignStaffToEvent(AssignStaffListRequest request);

    void updateStaffAssignments(Long eventId, AssignStaffListRequest request);

    List<EventStaffResponse> getStaffs(Long eventId);

    void registerUserToEvent(Long eventId, RegisterEventRequest request);

    void checkInByTicketCode(String ticketCode);

    void cancelEventRegistration(Long eventId);

    void updateRegistrationStatus(
            Long eventId, UpdateRegistrationStatusRequest updateRegistrationStatusRequest);

    List<UserEventResponse> getUserRegisteredEvents();

    List<UserEventDetailResponse> getUserEventDetail(Long eventId);

    Page<EventUserRegistrationResponse> getRegistrationsByEvent(
            Long eventId, RegistrationStatus status, Pageable pageable);


    Boolean validateStaffInEvent(Long eventId, Long staffId);
}
