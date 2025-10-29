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
  private String recipientName; // Tên người nhận

  @Column(name = "recipient_phone")
  private String recipientPhone; // Số điện thoại người nhận

  @Column(name = "address_line")
  private String addressLine; // Số nhà, tên đường

  @Column(name = "ward")
  private String ward; // Phường/Xã

  @Column(name = "district")
  private String district; // Quận/Huyện

  @Column(name = "city")
  private String city; // Thành phố

  @Column(name = "is_default")
  private Boolean isDefault = false;

  @Column(name = "delivery_note")
  private String deliveryNote;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_id", nullable = false)
  @JsonIgnore
  private User user;
}
