package com.greenloop.reward.repository;

import com.greenloop.reward.entity.VoucherUser;
import com.greenloop.reward.enums.VoucherStatus;
import com.greenloop.reward.enums.VoucherUserStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface VoucherUserRepository extends JpaRepository<VoucherUser, Long> {
    Optional<VoucherUser> findByVoucherIdAndUserId(Long voucherId, Long userId);

    List<VoucherUser> findAllByUserId(Long userId);

    @Query("SELECT vu FROM VoucherUser vu " +
            "JOIN vu.voucher v " +
            "WHERE vu.status = :voucherUserStatus " +
            "AND v.status = :voucherStatus " +
            "AND vu.isActive = :isActive")
    List<VoucherUser> findAvailableVoucherUsersWithExpiredVouchers(
            @Param("voucherUserStatus") VoucherUserStatus voucherUserStatus,
            @Param("voucherStatus") VoucherStatus voucherStatus,
            @Param("isActive") boolean isActive
    );
}
