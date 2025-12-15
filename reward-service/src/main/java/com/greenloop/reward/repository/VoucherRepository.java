package com.greenloop.reward.repository;

import com.greenloop.reward.entity.Voucher;
import com.greenloop.reward.enums.VoucherStatus;
import com.greenloop.reward.enums.VoucherType;
import java.time.LocalDateTime;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface VoucherRepository
    extends JpaRepository<Voucher, Long>, JpaSpecificationExecutor<Voucher> {
  @Query(
      "SELECT v FROM Voucher v "
          + "WHERE v.status = :status "
          + "AND v.isActive = :isActive "
          + "AND v.expiryDate < :now")
  List<Voucher> findActiveVouchersBeforeExpiryDate(
      @Param("status") VoucherStatus status,
      @Param("isActive") boolean isActive,
      @Param("now") LocalDateTime now);

  List<Voucher> findByStatusAndIsActive(VoucherStatus status, boolean isActive);

  Long countByType(VoucherType type);

  Long countByStatus(VoucherStatus status);

  @Query(
      "SELECT v.id, v.name, v.quantity - COALESCE(SUM(vu.quantity),0) "
          + "FROM Voucher v LEFT JOIN v.voucherUsers vu "
          + "GROUP BY v.id, v.name, v.quantity ORDER BY (v.quantity - COALESCE(SUM(vu.quantity),0)) DESC")
  List<Object[]> findTopAvailableVouchers();
}
