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
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Transaction Management", description = "API quản lý giao dịch và báo cáo dòng tiền")
public class TransactionController {

    private final TransactionService transactionService;

    @GetMapping("/report")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(
            summary = "Báo cáo chi tiết dòng tiền",
            description = "Lấy báo cáo tổng hợp toàn diện về dòng tiền: tổng quan, phân tích theo nguồn (online/offline), " +
                    "phương thức thanh toán, sự kiện, chi tiết các khoản tiền và 20 giao dịch gần nhất. " +
                    "Dùng cho dashboard tổng hợp và biểu đồ."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Lấy báo cáo thành công"),
            @ApiResponse(responseCode = "403", description = "Không có quyền truy cập", content = @Content)
    })
    public ResponseEntity<ApiResponseDTO<TransactionReportResponse>> getDetailedReport(
            @Parameter(description = "Ngày bắt đầu (yyyy-MM-dd'T'HH:mm:ss)", example = "2025-12-01T00:00:00", required = true)
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,

            @Parameter(description = "Ngày kết thúc (yyyy-MM-dd'T'HH:mm:ss)", example = "2025-12-31T23:59:59", required = true)
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,

            @Parameter(description = "Loại giao dịch (PAYMENT/REFUND)")
            @RequestParam(required = false) TransactionType transactionType,

            @Parameter(description = "Loại đơn hàng (ONLINE/OFFLINE)")
            @RequestParam(required = false) OrderType orderType,

            @Parameter(description = "Phương thức thanh toán (COD/PAYOS/CASH/BANK_TRANSFER)")
            @RequestParam(required = false) PaymentMethod paymentMethod,

            @Parameter(description = "Trạng thái giao dịch (PENDING/COMPLETED/REFUNDED/FAILED)")
            @RequestParam(required = false) TransactionStatus status,

            @Parameter(description = "ID sự kiện (chỉ áp dụng cho offline)")
            @RequestParam(required = false) Long eventId,

            @Parameter(description = "ID khách hàng")
            @RequestParam(required = false) Long customerId,

            @Parameter(description = "Lọc đơn guest (true) hay đơn có tài khoản (false)")
            @RequestParam(required = false) Boolean isGuestPurchase,

            @Parameter(description = "Tìm kiếm theo mã đơn, mã giao dịch, tên khách")
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

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
    @Operation(
            summary = "Danh sách giao dịch phân trang",
            description = "Lấy danh sách chi tiết từng giao dịch với phân trang và filter. " +
                    "Dùng cho màn hình quản lý giao dịch (transaction list table)."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Lấy danh sách thành công"),
            @ApiResponse(responseCode = "403", description = "Không có quyền truy cập", content = @Content)
    })
    public ResponseEntity<ApiResponseDTO<PageResponseDTO<TransactionDetailResponse>>> getTransactions(
            @Parameter(description = "Ngày bắt đầu", example = "2025-12-01T00:00:00")
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime fromDate,

            @Parameter(description = "Ngày kết thúc", example = "2025-12-31T23:59:59")
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime toDate,

            @Parameter(description = "Loại giao dịch")
            @RequestParam(required = false) TransactionType transactionType,

            @Parameter(description = "Loại đơn hàng")
            @RequestParam(required = false) OrderType orderType,

            @Parameter(description = "Phương thức thanh toán")
            @RequestParam(required = false) PaymentMethod paymentMethod,

            @Parameter(description = "Trạng thái giao dịch")
            @RequestParam(required = false) TransactionStatus status,

            @Parameter(description = "ID sự kiện")
            @RequestParam(required = false) Long eventId,

            @Parameter(description = "ID khách hàng")
            @RequestParam(required = false) Long customerId,

            @Parameter(description = "Đơn guest?")
            @RequestParam(required = false) Boolean isGuestPurchase,

            @Parameter(description = "Từ khóa tìm kiếm")
            @RequestParam(required = false) String searchKeyword,

            @Parameter(description = "Số trang (bắt đầu từ 0)", example = "0")
            @RequestParam(defaultValue = "0") int page,

            @Parameter(description = "Số bản ghi mỗi trang", example = "20")
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

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
    @Operation(
            summary = "Chi tiết 1 giao dịch",
            description = "Xem đầy đủ thông tin của 1 giao dịch cụ thể: breakdown tiền, payment info, event, guest info, timestamps."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Lấy chi tiết thành công"),
            @ApiResponse(responseCode = "404", description = "Không tìm thấy giao dịch", content = @Content),
            @ApiResponse(responseCode = "403", description = "Không có quyền truy cập", content = @Content)
    })
    public ResponseEntity<ApiResponseDTO<TransactionDetailResponse>> getTransactionById(
            @Parameter(description = "ID giao dịch", example = "123", required = true)
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

    @GetMapping("/summary")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(
            summary = "Tổng quan dòng tiền nhanh",
            description = "Lấy tóm tắt nhanh các chỉ số chính: tổng tiền vào, tiền ra, net cash flow, số lượng giao dịch. " +
                    "Dùng cho dashboard widget summary cards."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Lấy tổng quan thành công"),
            @ApiResponse(responseCode = "403", description = "Không có quyền truy cập", content = @Content)
    })
    public ResponseEntity<ApiResponseDTO<TransactionReportResponse.OverallSummary>> getQuickSummary(
            @Parameter(description = "Ngày bắt đầu", example = "2025-12-01T00:00:00", required = true)
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,

            @Parameter(description = "Ngày kết thúc", example = "2025-12-31T23:59:59", required = true)
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

    @GetMapping("/events")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(
            summary = "Báo cáo theo sự kiện",
            description = "Phân tích doanh thu theo từng sự kiện OFFLINE: revenue, refund, số giao dịch, " +
                    "phân bổ payment methods (COD/CASH/BANK). Dùng cho event performance analysis."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Lấy báo cáo sự kiện thành công"),
            @ApiResponse(responseCode = "403", description = "Không có quyền truy cập", content = @Content)
    })
    public ResponseEntity<ApiResponseDTO<java.util.List<TransactionReportResponse.EventBreakdown>>> getEventReport(
            @Parameter(description = "Ngày bắt đầu", example = "2025-12-01T00:00:00", required = true)
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,

            @Parameter(description = "Ngày kết thúc", example = "2025-12-31T23:59:59", required = true)
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,

            @Parameter(description = "Lọc theo ID sự kiện cụ thể (optional)")
            @RequestParam(required = false) Long eventId) {

        TransactionFilterRequest filter = TransactionFilterRequest.builder()
                .fromDate(from)
                .toDate(to)
                .eventId(eventId)
                .orderType(OrderType.OFFLINE)
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

    @GetMapping("/compare-sources")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(
            summary = "So sánh Online vs Offline",
            description = "So sánh doanh thu giữa đơn online (web/app) và offline (sự kiện): " +
                    "tổng tiền vào/ra, net amount, số giao dịch, phần trăm đóng góp. " +
                    "Dùng để vẽ pie chart/bar chart so sánh 2 nguồn."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "So sánh thành công"),
            @ApiResponse(responseCode = "403", description = "Không có quyền truy cập", content = @Content)
    })
    public ResponseEntity<ApiResponseDTO<TransactionReportResponse.SourceBreakdown>> compareOnlineOffline(
            @Parameter(description = "Ngày bắt đầu", example = "2025-12-01T00:00:00", required = true)
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,

            @Parameter(description = "Ngày kết thúc", example = "2025-12-31T23:59:59", required = true)
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

    @GetMapping("/payment-methods")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(
            summary = "Phân tích theo phương thức thanh toán",
            description = "Phân tích doanh thu theo từng payment method (COD, PayOS, CASH, BANK_TRANSFER): " +
                    "tổng tiền vào/ra, net amount, số giao dịch, phần trăm. " +
                    "Có thể filter riêng online hoặc offline. Dùng cho payment mix analysis."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Phân tích thành công"),
            @ApiResponse(responseCode = "403", description = "Không có quyền truy cập", content = @Content)
    })
    public ResponseEntity<ApiResponseDTO<TransactionReportResponse.PaymentBreakdown>> getPaymentMethodBreakdown(
            @Parameter(description = "Ngày bắt đầu", example = "2025-12-01T00:00:00", required = true)
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,

            @Parameter(description = "Ngày kết thúc", example = "2025-12-31T23:59:59", required = true)
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,

            @Parameter(description = "Lọc theo loại đơn (ONLINE/OFFLINE)")
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

    @GetMapping("/amounts-breakdown")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(
            summary = "Chi tiết các khoản tiền",
            description = "Phân tích chi tiết cấu trúc dòng tiền: tổng doanh thu sản phẩm, phí ship, " +
                    "discount (voucher + shipping), refund. Dùng cho kế toán/finance để reconcile số liệu."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Lấy breakdown thành công"),
            @ApiResponse(responseCode = "403", description = "Không có quyền truy cập", content = @Content)
    })
    public ResponseEntity<ApiResponseDTO<TransactionReportResponse.DetailedAmounts>> getAmountsBreakdown(
            @Parameter(description = "Ngày bắt đầu", example = "2025-12-01T00:00:00", required = true)
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,

            @Parameter(description = "Ngày kết thúc", example = "2025-12-31T23:59:59", required = true)
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
