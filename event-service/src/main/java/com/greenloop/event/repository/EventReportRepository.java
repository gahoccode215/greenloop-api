package com.greenloop.event.repository;

import com.greenloop.event.entity.EventReport;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EventReportRepository extends JpaRepository<EventReport, Long> {}
