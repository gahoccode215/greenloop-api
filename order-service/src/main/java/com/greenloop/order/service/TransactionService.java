package com.greenloop.order.service;

import com.greenloop.order.dto.request.TransactionFilterRequest;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.dto.response.TransactionDetailResponse;
import com.greenloop.order.dto.response.TransactionReportResponse;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.ReturnRequest;
import com.greenloop.order.entity.Transaction;

import java.time.LocalDateTime;

public interface TransactionService {
    ;
    Transaction createTransactionForOnlineOrder(Order order);

    Transaction createTransactionForOfflineOrder(Order order);

    Transaction createRefundTransactionForReturnRequest(ReturnRequest returnRequest, Order order);
    TransactionReportResponse getDetailedTransactionReport(
            LocalDateTime from,
            LocalDateTime to,
            TransactionFilterRequest filter
    );


    PageResponseDTO<TransactionDetailResponse> getTransactions(
            TransactionFilterRequest filter,
            int page,
            int size
    );

    TransactionDetailResponse getTransactionById(Long id);
}
