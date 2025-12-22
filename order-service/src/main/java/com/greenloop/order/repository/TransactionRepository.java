package com.greenloop.order.repository;

import com.greenloop.order.entity.Transaction;
import com.greenloop.order.enums.TransactionStatus;
import com.greenloop.order.enums.TransactionType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TransactionRepository extends JpaRepository<Transaction, Long>,
        JpaSpecificationExecutor<Transaction> {

    Optional<Transaction> findByOrderId(String orderId);


    Optional<Transaction> findByReturnRequestId(String returnRequestId);

    List<Transaction> findByTransactionTypeAndStatusOrderByCreatedAtDesc(
            TransactionType transactionType,
            TransactionStatus status);

    @Query("SELECT t FROM Transaction t WHERE t.returnRequestId IS NOT NULL " +
            "AND t.transactionType = :transactionType ORDER BY t.createdAt DESC")
    List<Transaction> findAllRefundTransactions(@Param("transactionType") TransactionType transactionType);
}
