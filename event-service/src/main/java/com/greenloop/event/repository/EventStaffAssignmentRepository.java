package com.greenloop.event.repository;

import com.greenloop.event.entity.Event;
import com.greenloop.event.entity.EventStaffAssignment;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface EventStaffAssignmentRepository extends JpaRepository<EventStaffAssignment, Long> {
  boolean existsByEventIdAndStaffId(Long eventId, Long staffId);

  boolean existsByEventIdAndIsStoreManagerTrue(Long eventId);

  List<EventStaffAssignment> findByEventId(Long eventId);

  List<EventStaffAssignment> findByEventIdAndIsActiveTrue(Long eventId);

  EventStaffAssignment findByEventIdAndStaffIdAndIsActiveTrue(Long eventId, Long staffId);

  List<EventStaffAssignment> findByStaffIdAndIsActiveTrue(Long staffId);

  @Query("SELECT a.event FROM EventStaffAssignment a " + "WHERE a.staffId = :staffId")
  List<Event> findEventsByStaffId(@Param("staffId") Long staffId);

  boolean existsByEventIdAndStaffIdAndIsActiveTrue(Long eventId, Long staffId);

  boolean existsByEventIdAndIsStoreManagerTrueAndIsActiveTrue(Long eventId);
}
