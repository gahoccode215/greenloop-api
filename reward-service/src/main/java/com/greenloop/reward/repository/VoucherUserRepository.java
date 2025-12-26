package com.greenloop.reward.repository;

import com.greenloop.reward.entity.VoucherUser;
import com.greenloop.reward.enums.VoucherStatus;
import com.greenloop.reward.enums.VoucherUserStatus;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface VoucherUserRepository extends JpaRepository<VoucherUser, Long> {
  Optional<VoucherUser> findByVoucherIdAndUserId(Long voucherId, Long userId);

  List<VoucherUser> findAllByUserId(Long userId);

  @Query(
      "SELECT vu FROM VoucherUser vu "
          + "JOIN vu.voucher v "
          + "WHERE vu.status = :voucherUserStatus "
          + "AND v.status = :voucherStatus "
          + "AND vu.isActive = :isActive")
  List<VoucherUser> findAvailableVoucherUsersWithExpiredVouchers(
      @Param("voucherUserStatus") VoucherUserStatus voucherUserStatus,
      @Param("voucherStatus") VoucherStatus voucherStatus,
      @Param("isActive") boolean isActive);

  Long countByStatus(VoucherUserStatus status);

  @Query(
      "SELECT vu.userId, COUNT(vu) FROM VoucherUser vu GROUP BY vu.userId ORDER BY COUNT(vu) DESC")
  List<Object[]> findTopUsers();

  @Query(
      """
        SELECT vu
        FROM VoucherUser vu
        JOIN vu.voucher v
        WHERE vu.status = :status
          AND v.status = 'ACTIVE'
          AND v.isActive = true
          AND v.expiryDate BETWEEN :from AND :to
        """)
  List<VoucherUser> findVoucherUsersExpiringInOneDay(
      @Param("status") VoucherUserStatus status,
      @Param("from") LocalDateTime from,
      @Param("to") LocalDateTime to);

  List<VoucherUser> findByUserId(Long userId);
}
