package com.greenloop.event.entity;

import jakarta.persistence.*;
import java.io.Serializable;
import lombok.*;

@Entity
@Table(name = "event_media")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class EventMedia extends BaseEntity implements Serializable {
  @ManyToOne
  @JoinColumn(name = "event_id", nullable = false)
  private Event event;

  @Column(name = "media_key", nullable = false)
  private String mediaKey;

  @Column(name = "image_url", nullable = false)
  private String imageUrl;
}
