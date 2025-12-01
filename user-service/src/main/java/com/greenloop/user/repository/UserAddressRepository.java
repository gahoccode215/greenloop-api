package com.greenloop.user.repository;

import com.greenloop.user.entity.UserAddress;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserAddressRepository extends JpaRepository<UserAddress, Long> {

  @Query(
      "SELECT ua FROM UserAddress ua WHERE ua.user.id = :userId ORDER BY ua.isDefault DESC, ua.id DESC")
  List<UserAddress> findByUserIdOrderByIsDefaultDescIdDesc(@Param("userId") Long userId);

  @Query("SELECT ua FROM UserAddress ua WHERE ua.id = :id AND ua.user.id = :userId")
  Optional<UserAddress> findByIdAndUserId(@Param("id") Long id, @Param("userId") Long userId);

  @Query("SELECT ua FROM UserAddress ua WHERE ua.user.id = :userId AND ua.isDefault = true")
  Optional<UserAddress> findByUserIdAndIsDefaultTrue(@Param("userId") Long userId);

  @Query("SELECT COUNT(ua) FROM UserAddress ua WHERE ua.user.id = :userId")
  long countByUserId(@Param("userId") Long userId);

  @Query("SELECT ua FROM UserAddress ua WHERE ua.user.id = :userId AND ua.isDefault = true")
  Optional<UserAddress> findDefaultAddressByUserId(@Param("userId") Long userId);
}
