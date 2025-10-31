package com.greenloop.event.service;

import com.greenloop.event.dto.request.UpdateRegistrationStatusRequest;
import com.greenloop.event.dto.response.EventUserRegistrationResponse;
import com.greenloop.event.dto.response.UserEventDetailResponse;
import com.greenloop.event.dto.response.UserEventResponse;
import com.greenloop.event.enums.RegistrationStatus;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface EventRegistrationService {
  void registerUserToEvent(Long eventId);

  void checkInByTicketCode(String ticketCode);

  void cancelEventRegistration(Long eventId);

  void updateRegistrationStatus(
      Long eventId, UpdateRegistrationStatusRequest updateRegistrationStatusRequest);

  List<UserEventResponse> getUserRegisteredEvents();

  UserEventDetailResponse getUserEventDetail(Long eventId);

  Page<EventUserRegistrationResponse> getRegistrationsByEvent(
      Long eventId, RegistrationStatus status, Pageable pageable);
}
