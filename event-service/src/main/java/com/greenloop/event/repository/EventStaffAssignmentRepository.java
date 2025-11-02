package com.greenloop.event.repository;

import com.greenloop.event.entity.EventStaffAssignment;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EventStaffAssignmentRepository extends JpaRepository<EventStaffAssignment, Long> {
  boolean existsByEventIdAndStaffId(Long eventId, Long staffId);

  boolean existsByEventIdAndIsStoreManagerTrue(Long eventId);

  List<EventStaffAssignment> findByEventId(Long eventId);

  List<EventStaffAssignment> findByEventIdAndIsActiveTrue(Long eventId);

  boolean existsByEventIdAndStaffIdAndIsActiveTrue(Long eventId, Long staffId);

  boolean existsByEventIdAndIsStoreManagerTrueAndIsActiveTrue(Long eventId);
}
