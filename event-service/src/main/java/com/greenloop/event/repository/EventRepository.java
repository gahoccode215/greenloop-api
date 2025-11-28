package com.greenloop.event.repository;

import com.greenloop.event.entity.Event;
import com.greenloop.event.enums.EventStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface EventRepository
        extends JpaRepository<Event, Long>, JpaSpecificationExecutor<Event> {

    List<Event> findByStatusAndIsActiveAndEndTimeBefore(
            EventStatus status,
            boolean isActive,
            LocalDateTime endTime
    );


    List<Event> findByStatusAndIsActiveAndStartTimeBeforeAndEndTimeAfter(
            EventStatus status,
            boolean isActive,
            LocalDateTime startTime,
            LocalDateTime endTime
    );


    List<Event> findByStatusAndIsActiveAndStartTimeBetween(
            EventStatus status,
            boolean isActive,
            LocalDateTime startTimeAfter,
            LocalDateTime startTimeBefore
    );

}
