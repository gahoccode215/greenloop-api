package com.greenloop.event.repository;

import com.greenloop.event.entity.EventStaffAssignment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface EventStaffAssignmentRepository extends JpaRepository<EventStaffAssignment, Long> {
    boolean existsByEventIdAndStaffId(Long eventId, Long staffId);

    boolean existsByEventIdAndIsStoreManagerTrue(Long eventId);

    List<EventStaffAssignment> findByEventId(Long eventId);

    List<EventStaffAssignment> findByEventIdAndIsActiveTrue(Long eventId);

    EventStaffAssignment findByEventIdAndStaffIdAndIsActiveTrue(Long eventId, Long staffId);

    List<EventStaffAssignment> findByStaffIdAndIsActiveTrue(Long staffId);

    boolean existsByEventIdAndStaffIdAndIsActiveTrue(Long eventId, Long staffId);

    boolean existsByEventIdAndIsStoreManagerTrueAndIsActiveTrue(Long eventId);
}
