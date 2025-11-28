package com.greenloop.reward.repository;

import com.greenloop.reward.entity.EcoPointTransaction;
import com.greenloop.reward.enums.EcoPointType;
import com.greenloop.reward.enums.SourceType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface EcoPointTransactionRepository extends JpaRepository<EcoPointTransaction, Long> {

    Long countByType(EcoPointType type);

    Long countBySourceType(SourceType sourceType);

    @Query("SELECT FUNCTION('DATE', t.createdAt), " +
            "SUM(CASE WHEN t.type = 'EARNED' THEN t.points ELSE 0 END), " +
            "SUM(CASE WHEN t.type = 'SPEND' THEN t.points ELSE 0 END), " +
            "SUM(CASE WHEN t.type = 'ADJUST' THEN t.points ELSE 0 END) " +
            "FROM EcoPointTransaction t GROUP BY FUNCTION('DATE', t.createdAt)")
    List<Object[]> transactionTrend();
}
