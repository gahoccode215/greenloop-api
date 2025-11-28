package com.greenloop.reward.repository;

import com.greenloop.reward.entity.Voucher;
import com.greenloop.reward.enums.VoucherStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface VoucherRepository
        extends JpaRepository<Voucher, Long>, JpaSpecificationExecutor<Voucher> {
    @Query("SELECT v FROM Voucher v " +
            "WHERE v.status = :status " +
            "AND v.isActive = :isActive " +
            "AND v.expiryDate < :now")
    List<Voucher> findActiveVouchersBeforeExpiryDate(
            @Param("status") VoucherStatus status,
            @Param("isActive") boolean isActive,
            @Param("now") LocalDateTime now
    );


    List<Voucher> findByStatusAndIsActive(
            VoucherStatus status,
            boolean isActive
    );
}
