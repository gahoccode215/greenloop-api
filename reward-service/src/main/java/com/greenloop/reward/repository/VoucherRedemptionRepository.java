package com.greenloop.reward.repository;

import com.greenloop.reward.entity.VoucherRedemption;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.util.List;

@Repository
public interface VoucherRedemptionRepository extends JpaRepository<VoucherRedemption, Long> {
    @Query("SELECT SUM(r.discountValue) FROM VoucherRedemption r")
    BigDecimal totalDiscountValue();

    @Query("SELECT FUNCTION('DATE', r.redeemedAt), COUNT(r), SUM(r.discountValue) " +
            "FROM VoucherRedemption r GROUP BY FUNCTION('DATE', r.redeemedAt)")
    List<Object[]> redemptionTrend();
}
