package com.greenloop.event.repository;

import com.greenloop.event.entity.EventRegistration;
import com.greenloop.event.enums.RegistrationStatus;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

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
}
