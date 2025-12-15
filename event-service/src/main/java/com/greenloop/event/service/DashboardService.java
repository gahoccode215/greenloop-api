package com.greenloop.event.service;

import com.greenloop.event.dto.response.EventRegistrationStatisticsResponse;
import com.greenloop.event.dto.response.EventStaffStatisticsResponse;
import com.greenloop.event.dto.response.EventStatisticsResponse;

public interface DashboardService {

  EventStatisticsResponse getEventStatistics();

  EventRegistrationStatisticsResponse getEventRegistrationStatistics();

  EventStaffStatisticsResponse getEventStaffStatistics();
}
