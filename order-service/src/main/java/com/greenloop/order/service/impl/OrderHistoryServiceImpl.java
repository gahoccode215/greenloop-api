package com.greenloop.order.service.impl;

import com.greenloop.order.dto.response.OrderHistoryResponse;
import com.greenloop.order.entity.OrderHistory;
import com.greenloop.order.repository.OrderHistoryRepository;
import com.greenloop.order.service.OrderHistoryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class OrderHistoryServiceImpl implements OrderHistoryService {

    private final OrderHistoryRepository historyRepository;

    @Override
    @Transactional(readOnly = true)
    public List<OrderHistoryResponse> getOrderHistory(String orderId) {

        List<OrderHistory> histories = historyRepository.findByOrderIdOrderByCreatedAtAsc(orderId);


        return histories.stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }


    private OrderHistoryResponse mapToResponse(OrderHistory history) {
        return OrderHistoryResponse.builder()
                .id(history.getId())
                .eventType(history.getEventType())
                .description(history.getDescription())
                .oldValue(history.getOldValue())
                .newValue(history.getNewValue())
                .changedByRole(history.getChangedByRole())
                .createdAt(history.getCreatedAt())
                .build();
    }
}
