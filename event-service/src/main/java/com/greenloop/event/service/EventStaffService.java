package com.greenloop.event.service;

import com.greenloop.event.dto.request.AssignStaffListRequest;
import com.greenloop.event.dto.response.EventStaffResponse;
import java.util.List;

public interface EventStaffService {
  void assignStaffToEvent(AssignStaffListRequest request);

  void updateStaffAssignments(Long eventId, AssignStaffListRequest request);

  List<EventStaffResponse> getStaffs(Long eventId);
}
