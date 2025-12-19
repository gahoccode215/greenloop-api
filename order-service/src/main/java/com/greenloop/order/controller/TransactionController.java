package com.greenloop.order.controller;

import com.greenloop.order.dto.request.TransactionFilterRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.dto.response.TransactionDetailResponse;
import com.greenloop.order.dto.response.TransactionReportResponse;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.TransactionStatus;
import com.greenloop.order.enums.TransactionType;
import com.greenloop.order.service.TransactionService;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/v1/transactions")
@RequiredArgsConstructor
public class TransactionController {

    private final TransactionService transactionService;

    /**
     * API 1: Báo cáo chi tiết dòng tiền
     * GET /api/transactions/report?from=2025-12-01T00:00:00&to=2025-12-31T23:59:59
     */
    @GetMapping("/report")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<TransactionReportResponse>> getDetailedReport(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(required = false) TransactionType transactionType,
            @RequestParam(required = false) OrderType orderType,
            @RequestParam(required = false) PaymentMethod paymentMethod,
            @RequestParam(required = false) TransactionStatus status,
            @RequestParam(required = false) Long eventId,
            @RequestParam(required = false) Long customerId,
            @RequestParam(required = false) Boolean isGuestPurchase,
            @RequestParam(required = false) String searchKeyword) {

        TransactionFilterRequest filter = TransactionFilterRequest.builder()
                .fromDate(from)
                .toDate(to)
                .transactionType(transactionType)
                .orderType(orderType)
                .paymentMethod(paymentMethod)
                .status(status)
                .eventId(eventId)
                .customerId(customerId)
                .isGuestPurchase(isGuestPurchase)
                .searchKeyword(searchKeyword)
                .build();

        TransactionReportResponse report = transactionService.getDetailedTransactionReport(from, to, filter);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy báo cáo giao dịch chi tiết thành công",
                        report,
                        HttpStatus.OK
                )
        );
    }

    /**
     * API 2: Danh sách giao dịch có phân trang và filter
     * GET /api/transactions?fromDate=2025-12-01T00:00:00&toDate=2025-12-31T23:59:59&page=0&size=20
     */
    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
    public ResponseEntity<ApiResponseDTO<PageResponseDTO<TransactionDetailResponse>>> getTransactions(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime fromDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime toDate,
            @RequestParam(required = false) TransactionType transactionType,
            @RequestParam(required = false) OrderType orderType,
            @RequestParam(required = false) PaymentMethod paymentMethod,
            @RequestParam(required = false) TransactionStatus status,
            @RequestParam(required = false) Long eventId,
            @RequestParam(required = false) Long customerId,
            @RequestParam(required = false) Boolean isGuestPurchase,
            @RequestParam(required = false) String searchKeyword,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        TransactionFilterRequest filter = TransactionFilterRequest.builder()
                .fromDate(fromDate)
                .toDate(toDate)
                .transactionType(transactionType)
                .orderType(orderType)
                .paymentMethod(paymentMethod)
                .status(status)
                .eventId(eventId)
                .customerId(customerId)
                .isGuestPurchase(isGuestPurchase)
                .searchKeyword(searchKeyword)
                .build();

        PageResponseDTO<TransactionDetailResponse> result = transactionService.getTransactions(filter, page, size);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy danh sách giao dịch thành công",
                        result,
                        HttpStatus.OK
                )
        );
    }

    /**
     * API 3: Xem chi tiết 1 giao dịch
     * GET /api/transactions/{id}
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
    public ResponseEntity<ApiResponseDTO<TransactionDetailResponse>> getTransactionById(
            @PathVariable Long id) {

        TransactionDetailResponse transaction = transactionService.getTransactionById(id);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy chi tiết giao dịch thành công",
                        transaction,
                        HttpStatus.OK
                )
        );
    }

    /**
     * API 4: Tổng quan dòng tiền (Quick summary)
     * GET /api/transactions/summary?from=2025-12-01T00:00:00&to=2025-12-31T23:59:59
     */
    @GetMapping("/summary")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<TransactionReportResponse.OverallSummary>> getQuickSummary(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to) {

        TransactionFilterRequest filter = TransactionFilterRequest.builder()
                .fromDate(from)
                .toDate(to)
                .build();

        TransactionReportResponse report = transactionService.getDetailedTransactionReport(from, to, filter);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy tổng quan dòng tiền thành công",
                        report.getOverall(),
                        HttpStatus.OK
                )
        );
    }

    /**
     * API 5: Báo cáo theo sự kiện
     * GET /api/transactions/events?from=2025-12-01T00:00:00&to=2025-12-31T23:59:59
     */
    @GetMapping("/events")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<java.util.List<TransactionReportResponse.EventBreakdown>>> getEventReport(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(required = false) Long eventId) {

        TransactionFilterRequest filter = TransactionFilterRequest.builder()
                .fromDate(from)
                .toDate(to)
                .eventId(eventId)
                .orderType(OrderType.OFFLINE) // Chỉ lấy offline events
                .build();

        TransactionReportResponse report = transactionService.getDetailedTransactionReport(from, to, filter);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy báo cáo theo sự kiện thành công",
                        report.getEventBreakdowns(),
                        HttpStatus.OK
                )
        );
    }

    /**
     * API 6: So sánh Online vs Offline
     * GET /api/transactions/compare-sources?from=2025-12-01T00:00:00&to=2025-12-31T23:59:59
     */
    @GetMapping("/compare-sources")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<TransactionReportResponse.SourceBreakdown>> compareOnlineOffline(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to) {

        TransactionFilterRequest filter = TransactionFilterRequest.builder()
                .fromDate(from)
                .toDate(to)
                .build();

        TransactionReportResponse report = transactionService.getDetailedTransactionReport(from, to, filter);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "So sánh Online vs Offline thành công",
                        report.getSourceBreakdown(),
                        HttpStatus.OK
                )
        );
    }

    /**
     * API 7: Phân tích theo phương thức thanh toán
     * GET /api/transactions/payment-methods?from=2025-12-01T00:00:00&to=2025-12-31T23:59:59
     */
    @GetMapping("/payment-methods")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<TransactionReportResponse.PaymentBreakdown>> getPaymentMethodBreakdown(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(required = false) OrderType orderType) {

        TransactionFilterRequest filter = TransactionFilterRequest.builder()
                .fromDate(from)
                .toDate(to)
                .orderType(orderType)
                .build();

        TransactionReportResponse report = transactionService.getDetailedTransactionReport(from, to, filter);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Phân tích phương thức thanh toán thành công",
                        report.getPaymentBreakdown(),
                        HttpStatus.OK
                )
        );
    }

    /**
     * API 8: Chi tiết các khoản tiền (breakdown)
     * GET /api/transactions/amounts-breakdown?from=2025-12-01T00:00:00&to=2025-12-31T23:59:59
     */
    @GetMapping("/amounts-breakdown")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<TransactionReportResponse.DetailedAmounts>> getAmountsBreakdown(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to) {

        TransactionFilterRequest filter = TransactionFilterRequest.builder()
                .fromDate(from)
                .toDate(to)
                .build();

        TransactionReportResponse report = transactionService.getDetailedTransactionReport(from, to, filter);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy chi tiết các khoản tiền thành công",
                        report.getDetailedAmounts(),
                        HttpStatus.OK
                )
        );
    }
}
