package com.greenloop.user.repository;

import com.greenloop.user.entity.User;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {
  boolean existsByEmail(String email);

  Optional<User> findByEmail(String email);

  boolean existsByPhone(String phoneNumber);

  // Tổng số người dùng
  long count();

  // Người dùng mới theo khoảng thời gian
  long countByCreatedAtAfter(LocalDateTime startDate);

  long countByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);

  // Phân bố theo vai trò (User có ManyToMany với Role)
  @Query("SELECT r.name, COUNT(DISTINCT u) FROM User u JOIN u.roles r GROUP BY r.name")
  List<Object[]> countUsersByRole();

  // Phân bố theo trạng thái (dùng isActive)
  @Query(
      "SELECT CASE WHEN u.isActive = true THEN 'ACTIVE' ELSE 'INACTIVE' END, COUNT(u) "
          + "FROM User u GROUP BY u.isActive")
  List<Object[]> countUsersByStatus();

  // Timeline người dùng mới (30 ngày gần nhất)
  @Query(
      "SELECT CAST(u.createdAt AS date), COUNT(u) "
          + "FROM User u "
          + "WHERE u.createdAt >= :startDate "
          + "GROUP BY CAST(u.createdAt AS date) "
          + "ORDER BY CAST(u.createdAt AS date) ASC")
  List<Object[]> getNewUsersTimeline(@Param("startDate") LocalDateTime startDate);

  // Active users
  long countByLastLoginAtAfter(LocalDateTime sinceDate);
}
