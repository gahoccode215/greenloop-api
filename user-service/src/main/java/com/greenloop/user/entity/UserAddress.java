package com.greenloop.user.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "user_addresses")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
public class UserAddress {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "recipient_name")
  private String recipientName;

  @Column(name = "recipient_phone")
  private String recipientPhone;

  @Column(name = "address_line")
  private String addressLine;

  @Column(name = "ward")
  private String ward;

  @Column(name = "district")
  private Long district;

  @Column(name = "district_name")
  private String districtName;

  @Column(name = "city")
  private Long city;

  @Column(name = "city_name")
  private String cityName;

  @Column(name = "is_default")
  private Boolean isDefault = false;

  @Column(name = "delivery_note")
  private String deliveryNote;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_id", nullable = false)
  @JsonIgnore
  private User user;
}
