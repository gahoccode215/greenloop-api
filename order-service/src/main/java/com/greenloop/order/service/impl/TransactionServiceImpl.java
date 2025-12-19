package com.greenloop.order.service.impl;

import com.greenloop.order.dto.request.TransactionFilterRequest;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.dto.response.TransactionDetailResponse;
import com.greenloop.order.dto.response.TransactionReportResponse;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.Transaction;
import com.greenloop.order.enums.*;
import com.greenloop.order.repository.TransactionRepository;
import com.greenloop.order.repository.specification.TransactionSpecification;
import com.greenloop.order.service.TransactionService;
import com.greenloop.order.util.PageResponseUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class TransactionServiceImpl implements TransactionService {

    private final TransactionRepository transactionRepository;

    @Override
    @Transactional
    public Transaction createTransactionFromOrder(Order order) {
        log.info("Creating transaction for order: {}", order.getOrderCode());

        String transactionCode = generateTransactionCode();

        Transaction transaction = Transaction.builder()
                .transactionCode(transactionCode)
                .orderId(order.getOrderId())
                .orderCode(order.getOrderCode())
                .customerId(order.getCustomerId())
                .transactionType(TransactionType.PAYMENT)
                .orderType(order.getOrderType())
                .amount(order.getTotalPrice())
                .productTotal(order.getSubTotal())
                .shippingFee(order.getShippingFee())
                .discountAmount(order.getDiscountAmount())
                .voucherCode(order.getVoucherCode())
                // TODO: Tính voucherDiscount và shippingDiscount riêng nếu có
                .voucherDiscount(order.getDiscountAmount())
                .shippingDiscount(BigDecimal.ZERO)
                .paymentMethod(order.getPaymentMethod())
                .paymentOrderCode(order.getPaymentOrderCode())
                .paymentTransactionId(order.getPaymentTransactionId())
                .status(order.getPaymentStatus() == PaymentStatus.PAID
                        ? TransactionStatus.COMPLETED
                        : TransactionStatus.PENDING)
                .description(buildDescription(order))
                .transactionDate(LocalDateTime.now())
                .eventId(order.getEventId())
                // TODO: Load event name from Event Service
                .isGuestPurchase(order.getIsGuestPurchase())
                .guestName(order.getGuestName())
                .guestPhone(order.getGuestPhone())
                .build();

        if (order.getPaymentStatus() == PaymentStatus.PAID) {
            transaction.setCompletedDate(LocalDateTime.now());
        }

        Transaction saved = transactionRepository.save(transaction);
        log.info("Transaction created: {} for order: {}", transactionCode, order.getOrderCode());
        return saved;
    }

    @Override
    @Transactional
    public void completeTransaction(String orderId) {
        log.info("Completing transaction for order: {}", orderId);

        transactionRepository.findByOrderId(orderId).ifPresent(transaction -> {
            transaction.setStatus(TransactionStatus.COMPLETED);
            transaction.setCompletedDate(LocalDateTime.now());
            transactionRepository.save(transaction);
            log.info("Transaction completed: {}", transaction.getTransactionCode());
        });
    }

    @Override
    @Transactional
    public Transaction createRefundTransaction(Order order, String reason) {
        log.info("Creating refund transaction for order: {}", order.getOrderCode());

        String transactionCode = generateTransactionCode();

        Transaction refundTransaction = Transaction.builder()
                .transactionCode(transactionCode)
                .orderId(order.getOrderId())
                .orderCode(order.getOrderCode())
                .customerId(order.getCustomerId())
                .transactionType(TransactionType.REFUND)
                .orderType(order.getOrderType())
                .amount(order.getTotalPrice().negate()) // Số âm
                .productTotal(order.getSubTotal())
                .shippingFee(order.getShippingFee())
                .discountAmount(order.getDiscountAmount())
                .paymentMethod(order.getPaymentMethod())
                .status(TransactionStatus.REFUNDED)
                .description("Hoàn tiền đơn hàng " + order.getOrderCode() + " - " + reason)
                .transactionDate(LocalDateTime.now())
                .refundedDate(LocalDateTime.now())
                .eventId(order.getEventId())
                .build();

        Transaction saved = transactionRepository.save(refundTransaction);
        log.info("Refund transaction created: {}", transactionCode);
        return saved;
    }

    @Override
    @Transactional(readOnly = true)
    public TransactionReportResponse getDetailedTransactionReport(
            LocalDateTime from, LocalDateTime to, TransactionFilterRequest filter) {

        log.info("Generating detailed report from {} to {}", from, to);

        // Build specification
        Specification<Transaction> spec = TransactionSpecification.filterTransactions(from, to, filter);
        List<Transaction> transactions = transactionRepository.findAll(spec);

        // 1. OVERALL SUMMARY
        TransactionReportResponse.OverallSummary overall = calculateOverallSummary(transactions);

        // 2. SOURCE BREAKDOWN (Online vs Offline)
        TransactionReportResponse.SourceBreakdown sourceBreakdown = calculateSourceBreakdown(transactions, overall.getTotalInflow());

        // 3. PAYMENT BREAKDOWN
        TransactionReportResponse.PaymentBreakdown paymentBreakdown = calculatePaymentBreakdown(transactions, overall.getTotalInflow());

        // 4. EVENT BREAKDOWN
        List<TransactionReportResponse.EventBreakdown> eventBreakdowns = calculateEventBreakdown(transactions);

        // 5. DETAILED AMOUNTS
        TransactionReportResponse.DetailedAmounts detailedAmounts = calculateDetailedAmounts(transactions);

        // 6. RECENT TRANSACTIONS
        List<TransactionDetailResponse> recentTransactions = transactions.stream()
                .sorted((t1, t2) -> t2.getTransactionDate().compareTo(t1.getTransactionDate()))
                .limit(20)
                .map(this::mapToDetailResponse)
                .toList();

        return TransactionReportResponse.builder()
                .fromDate(from)
                .toDate(to)
                .overall(overall)
                .sourceBreakdown(sourceBreakdown)
                .paymentBreakdown(paymentBreakdown)
                .eventBreakdowns(eventBreakdowns)
                .detailedAmounts(detailedAmounts)
                .recentTransactions(recentTransactions)
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public PageResponseDTO<TransactionDetailResponse> getTransactions(
            TransactionFilterRequest filter, int page, int size) {

        Specification<Transaction> spec = TransactionSpecification.filterTransactions(
                filter.getFromDate(), filter.getToDate(), filter);

        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "transactionDate"));
        Page<Transaction> transactionPage = transactionRepository.findAll(spec, pageable);
        Page<TransactionDetailResponse> responsePage = transactionPage.map(this::mapToDetailResponse);

        return PageResponseUtil.toPageResponse(responsePage);
    }
    @Override
    @Transactional(readOnly = true)
    public TransactionDetailResponse getTransactionById(Long id) {
        log.info("Getting transaction by id: {}", id);

        Transaction transaction = transactionRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Transaction not found with id: " + id));

        return mapToDetailResponse(transaction);
    }

    // ========================================
    // ========== PRIVATE HELPERS ==========
    // ========================================

    private TransactionReportResponse.OverallSummary calculateOverallSummary(List<Transaction> transactions) {
        BigDecimal totalInflow = transactions.stream()
                .filter(t -> t.getTransactionType() == TransactionType.PAYMENT && t.getStatus() == TransactionStatus.COMPLETED)
                .map(Transaction::getAmount)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        BigDecimal totalOutflow = transactions.stream()
                .filter(t -> t.getTransactionType() == TransactionType.REFUND && t.getStatus() == TransactionStatus.REFUNDED)
                .map(t -> t.getAmount().abs())
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        return TransactionReportResponse.OverallSummary.builder()
                .totalInflow(totalInflow)
                .totalOutflow(totalOutflow)
                .netCashFlow(totalInflow.subtract(totalOutflow))
                .totalTransactions(transactions.size())
                .inflowTransactions((int) transactions.stream().filter(t -> t.getTransactionType() == TransactionType.PAYMENT).count())
                .outflowTransactions((int) transactions.stream().filter(t -> t.getTransactionType() == TransactionType.REFUND).count())
                .build();
    }

    private TransactionReportResponse.SourceBreakdown calculateSourceBreakdown(List<Transaction> transactions, BigDecimal totalInflow) {
        // Online
        List<Transaction> onlineTransactions = transactions.stream()
                .filter(t -> t.getOrderType() == OrderType.ONLINE)
                .toList();
        TransactionReportResponse.OnlineOfflineData online = calculateOnlineOfflineData(onlineTransactions, totalInflow);

        // Offline
        List<Transaction> offlineTransactions = transactions.stream()
                .filter(t -> t.getOrderType() == OrderType.OFFLINE)
                .toList();
        TransactionReportResponse.OnlineOfflineData offline = calculateOnlineOfflineData(offlineTransactions, totalInflow);

        return TransactionReportResponse.SourceBreakdown.builder()
                .online(online)
                .offline(offline)
                .build();
    }

    private TransactionReportResponse.OnlineOfflineData calculateOnlineOfflineData(List<Transaction> transactions, BigDecimal totalInflow) {
        BigDecimal inflow = transactions.stream()
                .filter(t -> t.getTransactionType() == TransactionType.PAYMENT && t.getStatus() == TransactionStatus.COMPLETED)
                .map(Transaction::getAmount)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        BigDecimal outflow = transactions.stream()
                .filter(t -> t.getTransactionType() == TransactionType.REFUND)
                .map(t -> t.getAmount().abs())
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        double percentage = totalInflow.compareTo(BigDecimal.ZERO) > 0
                ? inflow.divide(totalInflow, 4, RoundingMode.HALF_UP).multiply(BigDecimal.valueOf(100)).doubleValue()
                : 0.0;

        return TransactionReportResponse.OnlineOfflineData.builder()
                .totalInflow(inflow)
                .totalOutflow(outflow)
                .netAmount(inflow.subtract(outflow))
                .transactionCount(transactions.size())
                .percentage(percentage)
                .build();
    }

    private TransactionReportResponse.PaymentBreakdown calculatePaymentBreakdown(List<Transaction> transactions, BigDecimal totalInflow) {
        Map<PaymentMethod, List<Transaction>> grouped = transactions.stream()
                .filter(t -> t.getPaymentMethod() != null)
                .collect(Collectors.groupingBy(Transaction::getPaymentMethod));

        List<TransactionReportResponse.PaymentMethodData> methods = grouped.entrySet().stream()
                .map(entry -> {
                    List<Transaction> list = entry.getValue();
                    BigDecimal inflow = list.stream()
                            .filter(t -> t.getTransactionType() == TransactionType.PAYMENT && t.getStatus() == TransactionStatus.COMPLETED)
                            .map(Transaction::getAmount)
                            .reduce(BigDecimal.ZERO, BigDecimal::add);

                    BigDecimal outflow = list.stream()
                            .filter(t -> t.getTransactionType() == TransactionType.REFUND)
                            .map(t -> t.getAmount().abs())
                            .reduce(BigDecimal.ZERO, BigDecimal::add);

                    double percentage = totalInflow.compareTo(BigDecimal.ZERO) > 0
                            ? inflow.divide(totalInflow, 4, RoundingMode.HALF_UP).multiply(BigDecimal.valueOf(100)).doubleValue()
                            : 0.0;

                    return TransactionReportResponse.PaymentMethodData.builder()
                            .paymentMethod(entry.getKey().name())
                            .totalInflow(inflow)
                            .totalOutflow(outflow)
                            .netAmount(inflow.subtract(outflow))
                            .transactionCount(list.size())
                            .percentage(percentage)
                            .build();
                })
                .toList();

        return TransactionReportResponse.PaymentBreakdown.builder()
                .methods(methods)
                .build();
    }

    private List<TransactionReportResponse.EventBreakdown> calculateEventBreakdown(List<Transaction> transactions) {
        Map<Long, List<Transaction>> grouped = transactions.stream()
                .filter(t -> t.getEventId() != null)
                .collect(Collectors.groupingBy(Transaction::getEventId));

        return grouped.entrySet().stream()
                .map(entry -> {
                    List<Transaction> list = entry.getValue();
                    String eventName = list.get(0).getEventName(); // Assume same event name

                    BigDecimal revenue = list.stream()
                            .filter(t -> t.getTransactionType() == TransactionType.PAYMENT && t.getStatus() == TransactionStatus.COMPLETED)
                            .map(Transaction::getAmount)
                            .reduce(BigDecimal.ZERO, BigDecimal::add);

                    BigDecimal refund = list.stream()
                            .filter(t -> t.getTransactionType() == TransactionType.REFUND)
                            .map(t -> t.getAmount().abs())
                            .reduce(BigDecimal.ZERO, BigDecimal::add);

                    TransactionReportResponse.PaymentMethodSplit split = calculatePaymentMethodSplit(list);

                    return TransactionReportResponse.EventBreakdown.builder()
                            .eventId(entry.getKey())
                            .eventName(eventName)
                            .totalRevenue(revenue)
                            .totalRefund(refund)
                            .netRevenue(revenue.subtract(refund))
                            .transactionCount(list.size())
                            .paymentSplit(split)
                            .build();
                })
                .toList();
    }

    private TransactionReportResponse.PaymentMethodSplit calculatePaymentMethodSplit(List<Transaction> transactions) {
        BigDecimal cash = sumByPaymentMethod(transactions, PaymentMethod.CASH);
        BigDecimal bankTransfer = sumByPaymentMethod(transactions, PaymentMethod.BANK_TRANSFER);
        BigDecimal cod = sumByPaymentMethod(transactions, PaymentMethod.COD);
        BigDecimal payos = sumByPaymentMethod(transactions, PaymentMethod.PAYOS);

        return TransactionReportResponse.PaymentMethodSplit.builder()
                .cash(cash)
                .bankTransfer(bankTransfer)
                .cod(cod)
                .payos(payos)
                .build();
    }

    private BigDecimal sumByPaymentMethod(List<Transaction> transactions, PaymentMethod method) {
        return transactions.stream()
                .filter(t -> t.getPaymentMethod() == method && t.getStatus() == TransactionStatus.COMPLETED)
                .map(Transaction::getAmount)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
    }

    private TransactionReportResponse.DetailedAmounts calculateDetailedAmounts(List<Transaction> transactions) {
        BigDecimal productRevenue = transactions.stream()
                .filter(t -> t.getTransactionType() == TransactionType.PAYMENT && t.getStatus() == TransactionStatus.COMPLETED)
                .map(Transaction::getProductTotal)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        BigDecimal shippingFee = transactions.stream()
                .filter(t -> t.getTransactionType() == TransactionType.PAYMENT && t.getStatus() == TransactionStatus.COMPLETED)
                .map(Transaction::getShippingFee)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        BigDecimal discount = transactions.stream()
                .filter(t -> t.getTransactionType() == TransactionType.PAYMENT && t.getStatus() == TransactionStatus.COMPLETED)
                .map(Transaction::getDiscountAmount)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        BigDecimal voucherDiscount = transactions.stream()
                .filter(t -> t.getTransactionType() == TransactionType.PAYMENT && t.getStatus() == TransactionStatus.COMPLETED)
                .map(t -> t.getVoucherDiscount() != null ? t.getVoucherDiscount() : BigDecimal.ZERO)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        BigDecimal shippingDiscount = transactions.stream()
                .filter(t -> t.getTransactionType() == TransactionType.PAYMENT && t.getStatus() == TransactionStatus.COMPLETED)
                .map(t -> t.getShippingDiscount() != null ? t.getShippingDiscount() : BigDecimal.ZERO)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        BigDecimal refund = transactions.stream()
                .filter(t -> t.getTransactionType() == TransactionType.REFUND)
                .map(t -> t.getAmount().abs())
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        return TransactionReportResponse.DetailedAmounts.builder()
                .totalProductRevenue(productRevenue)
                .totalShippingFee(shippingFee)
                .totalDiscount(discount)
                .totalVoucherDiscount(voucherDiscount)
                .totalShippingDiscount(shippingDiscount)
                .totalRefund(refund)
                .build();
    }

    private TransactionDetailResponse mapToDetailResponse(Transaction transaction) {
        return TransactionDetailResponse.builder()
                .id(transaction.getId())
                .transactionCode(transaction.getTransactionCode())
                .orderCode(transaction.getOrderCode())
                .customerId(transaction.getCustomerId())
                .transactionType(transaction.getTransactionType())
                .orderType(transaction.getOrderType())
                .amount(transaction.getAmount())
                .breakdown(TransactionDetailResponse.AmountBreakdown.builder()
                        .productTotal(transaction.getProductTotal())
                        .shippingFee(transaction.getShippingFee())
                        .discountAmount(transaction.getDiscountAmount())
                        .voucherDiscount(transaction.getVoucherDiscount())
                        .shippingDiscount(transaction.getShippingDiscount())
                        .finalAmount(transaction.getAmount())
                        .build())
                .paymentMethod(transaction.getPaymentMethod())
                .paymentDisplayName(getPaymentDisplayName(transaction.getPaymentMethod()))
                .paymentTransactionId(transaction.getPaymentTransactionId())
                .status(transaction.getStatus())
                .statusDisplayName(transaction.getStatus() != null ? transaction.getStatus().getDescription() : null)
                .eventId(transaction.getEventId())
                .eventName(transaction.getEventName())
                .isGuestPurchase(transaction.getIsGuestPurchase())
                .guestName(transaction.getGuestName())
                .guestPhone(transaction.getGuestPhone())
                .transactionDate(transaction.getTransactionDate())
                .completedDate(transaction.getCompletedDate())
                .refundedDate(transaction.getRefundedDate())
                .description(transaction.getDescription())
                .build();
    }

    private String getPaymentDisplayName(PaymentMethod method) {
        if (method == null) return null;
        return switch (method) {
            case CASH -> "Tiền mặt";
            case BANK_TRANSFER -> "Chuyển khoản";
            case COD -> "Thanh toán khi nhận hàng (COD)";
            case PAYOS -> "PayOS";
        };
    }

    private String buildDescription(Order order) {
        String orderType = order.getOrderType() == OrderType.ONLINE ? "online" : "offline";
        return String.format("Thanh toán đơn hàng %s (%s)", order.getOrderCode(), orderType);
    }

    private String generateTransactionCode() {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
        return "TXN" + timestamp + String.format("%04d", (int)(Math.random() * 10000));
    }
}
