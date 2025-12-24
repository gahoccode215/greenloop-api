package com.greenloop.order.repository;

import com.greenloop.order.entity.ReturnRequest;
import com.greenloop.order.enums.ReturnRequestStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

public interface ReturnRequestRepository extends JpaRepository<ReturnRequest, Long> , JpaSpecificationExecutor<ReturnRequest> {

    Page<ReturnRequest> findByOrderId(String orderId, Pageable pageable);

    Page<ReturnRequest> findByCustomerId(Long customerId, Pageable pageable);

    boolean existsByOrderIdAndStatusIn(String orderId, List<ReturnRequestStatus> statuses);

    List<ReturnRequest> findByStatusIn(List<ReturnRequestStatus> statuses);
}
