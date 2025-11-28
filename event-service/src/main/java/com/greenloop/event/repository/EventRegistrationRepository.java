package com.greenloop.event.repository;

import com.greenloop.event.entity.EventRegistration;
import com.greenloop.event.enums.EventStatus;
import com.greenloop.event.enums.RegistrationStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface EventRegistrationRepository extends JpaRepository<EventRegistration, Long> {
    boolean existsByEventIdAndUserIdAndIsActiveTrue(Long eventId, Long userId);

    List<EventRegistration> findByUserIdAndIsActiveTrue(Long userId);

    List<EventRegistration> findByUserId(Long userId);

    Optional<EventRegistration> findByEventIdAndUserIdAndIsActiveTrue(Long eventId, Long userId);

    Optional<EventRegistration> findByEventIdAndUserId(Long eventId, Long userId);

    List<EventRegistration> findByEventIdAndIsActiveTrue(Long eventId);

    Optional<EventRegistration> findByQrCodeAndIsActiveTrue(String qrCode);

    Page<EventRegistration> findByEventIdAndIsActiveTrue(Long eventId, Pageable pageable);

    Page<EventRegistration> findByEventIdAndStatusAndIsActiveTrue(
            Long eventId, RegistrationStatus status, Pageable pageable);

    Page<EventRegistration> findByEventId(Long eventId, Pageable pageable);

    Page<EventRegistration> findByEventIdAndStatus(
            Long eventId, RegistrationStatus status, Pageable pageable);


    @Query("SELECT er FROM EventRegistration er " +
            "JOIN er.event e " +
            "WHERE er.status = :registrationStatus " +
            "AND e.status = :eventStatus " +
            "AND e.isActive = :isActive " +
            "AND er.isActive = true")
    List<EventRegistration> findBookedRegistrationsWithClosedEvents(
            @Param("registrationStatus") RegistrationStatus registrationStatus,
            @Param("eventStatus") EventStatus eventStatus,
            @Param("isActive") boolean isActive
    );

    Long countByStatus(RegistrationStatus status);

    @Query("SELECT FUNCTION('DATE', r.checkinTime) as date, COUNT(r) " +
            "FROM EventRegistration r WHERE r.checkinTime IS NOT NULL " +
            "GROUP BY FUNCTION('DATE', r.checkinTime)")
    List<Object[]> countCheckinByDate();

    @Query("SELECT r.userId, COUNT(r) " +
            "FROM EventRegistration r GROUP BY r.userId ORDER BY COUNT(r) DESC")
    List<Object[]> findTopUsers();
}
