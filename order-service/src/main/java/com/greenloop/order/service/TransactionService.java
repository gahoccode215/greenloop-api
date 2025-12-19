package com.greenloop.order.service;

import com.greenloop.order.dto.request.TransactionFilterRequest;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.dto.response.TransactionDetailResponse;
import com.greenloop.order.dto.response.TransactionReportResponse;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.Transaction;

import java.time.LocalDateTime;

public interface TransactionService {

    /**
     * Tạo transaction khi đơn hàng được tạo
     */
    Transaction createTransactionFromOrder(Order order);

    /**
     * Cập nhật transaction khi đơn hàng hoàn thành
     */
    void completeTransaction(String orderId);

    /**
     * Tạo transaction hoàn tiền khi hủy đơn
     */
    Transaction createRefundTransaction(Order order, String reason);

    /**
     * Báo cáo chi tiết dòng tiền
     */
    TransactionReportResponse getDetailedTransactionReport(
            LocalDateTime from,
            LocalDateTime to,
            TransactionFilterRequest filter
    );

    /**
     * Lấy danh sách giao dịch phân trang
     */
    PageResponseDTO<TransactionDetailResponse> getTransactions(
            TransactionFilterRequest filter,
            int page,
            int size
    );

    TransactionDetailResponse getTransactionById(Long id);
}
