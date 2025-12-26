package com.greenloop.order.repository;

import com.greenloop.order.entity.Transaction;
import com.greenloop.order.enums.TransactionType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TransactionRepository extends JpaRepository<Transaction, Long>,
        JpaSpecificationExecutor<Transaction> {

    Optional<Transaction> findByOrderId(String orderId);

    long countByTransactionCodeStartingWith(String prefix);

    Optional<Transaction> findByOrderIdAndTransactionType(String orderId, TransactionType transactionType);
}
