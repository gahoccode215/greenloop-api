package com.greenloop.event.entity;

import com.greenloop.event.enums.EventStatus;
import com.greenloop.event.utils.JsonConverter;
import jakarta.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import lombok.*;

@Entity
@Table(name = "events")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class Event extends BaseEntity implements Serializable {

  @Column(nullable = false, length = 20, unique = true, name = "code")
  private String code;

  @Column(nullable = false, name = "name")
  private String name;

  @Column(nullable = false, columnDefinition = "TEXT", name = "description")
  private String description;

  @Column(name = "start_time", nullable = false)
  private LocalDateTime startTime;

  @Column(name = "end_time", nullable = false)
  private LocalDateTime endTime;

  @Column(name = "image_url")
  private String imageUrl;

  @Column(name = "media_key")
  private String mediaKey;

  @Column(name = "location_detail")
  private String locationDetail;

  @Column(nullable = false, name = "latitude")
  private String latitude;

  @Column(nullable = false, name = "longitude")
  private String longitude;

  @Enumerated(EnumType.STRING)
  @Column(name = "status", nullable = false, length = 15)
  private EventStatus status;

  @Column(name = "google_place_id", columnDefinition = "JSON")
  @Convert(converter = JsonConverter.class)
  private HashMap<String, String> googlePlaceId;

  @Column(columnDefinition = "TEXT")
  private String note;

  @OneToMany(mappedBy = "event", cascade = CascadeType.ALL, orphanRemoval = true)
  @Builder.Default
  private List<EventMedia> mediaList = new ArrayList<>();

  @OneToMany(mappedBy = "event", cascade = CascadeType.ALL, orphanRemoval = true)
  @Builder.Default
  private List<EventReport> reports = new ArrayList<>();

  @OneToMany(mappedBy = "event", cascade = CascadeType.ALL, orphanRemoval = true)
  @Builder.Default
  private List<EventStaffAssignment> staffAssignments = new ArrayList<>();

  @OneToMany(mappedBy = "event", cascade = CascadeType.ALL, orphanRemoval = true)
  @Builder.Default
  private List<EventRegistration> registrations = new ArrayList<>();

  public void updateImage(String imageUrl, String mediaKey) {
    if (imageUrl != null) this.imageUrl = imageUrl;
    if (mediaKey != null) this.mediaKey = mediaKey;
  }
}
