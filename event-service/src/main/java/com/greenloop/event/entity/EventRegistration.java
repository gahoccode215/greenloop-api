package com.greenloop.event.entity;

import com.greenloop.event.enums.RegistrationStatus;
import jakarta.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import lombok.*;

@Entity
@Table(name = "event_registrations")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class EventRegistration extends BaseEntity implements Serializable {
  @Column(name = "user_id", nullable = false)
  private Long userId;

  @ManyToOne
  @JoinColumn(name = "event_id", nullable = false)
  private Event event;

  @Column(name = "qr_code", nullable = false, unique = true, length = 20)
  private String qrCode;

  @Column(name = "checkin_time")
  private LocalDateTime checkinTime;

  @Column(name = "note")
  private String note;

  @Enumerated(EnumType.STRING)
  @Column(name = "status", nullable = false, length = 25)
  private RegistrationStatus status;
}
