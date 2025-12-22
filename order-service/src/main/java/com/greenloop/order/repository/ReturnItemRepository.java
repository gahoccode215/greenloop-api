package com.greenloop.order.repository;

import com.greenloop.order.entity.ReturnItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

public interface ReturnItemRepository extends JpaRepository<ReturnItem, Long> {

    List<ReturnItem> findByReturnRequest_ReturnRequestId(Long returnRequestId);

    List<ReturnItem> findByProductId(Long productId);
}
