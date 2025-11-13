package com.greenloop.reward.repository;

import com.greenloop.reward.entity.EcoPointTransaction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EcoPointTransactionRepository extends JpaRepository<EcoPointTransaction, Long> {
}
