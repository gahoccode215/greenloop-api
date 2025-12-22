package com.greenloop.order.service.impl;

import com.greenloop.order.dto.request.CreateReturnRequestRequest;
import com.greenloop.order.dto.request.ReturnRequestFilterRequest;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.dto.response.ReturnRequestResponse;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.OrderItem;
import com.greenloop.order.entity.ReturnItem;
import com.greenloop.order.entity.ReturnRequest;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.ReturnRequestStatus;
import com.greenloop.order.exception.InvalidReturnRequestException;
import com.greenloop.order.exception.OrderNotFoundException;
import com.greenloop.order.exception.ReturnRequestExpiredException;
import com.greenloop.order.exception.ReturnRequestNotFoundException;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.repository.ReturnRequestRepository;
import com.greenloop.order.repository.specification.ReturnRequestSpecification;
import com.greenloop.order.service.CloudinaryService;
import com.greenloop.order.service.ReturnRequestService;
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
import org.springframework.web.multipart.MultipartFile;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ReturnRequestServiceImpl implements ReturnRequestService {

    private static final int RETURN_DAYS_LIMIT = 7;
    private static final int MAX_IMAGES = 5;

    private final ReturnRequestRepository returnRequestRepository;
    private final OrderRepository orderRepository;
    private final CloudinaryService cloudinaryService;

    @Override
    @Transactional
    public ReturnRequestResponse createReturnRequest(Long customerId, String orderId,
                                                     CreateReturnRequestRequest request,
                                                     List<MultipartFile> images) {

        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));

        validateReturnRequest(order, customerId, request, images);

        List<OrderItem> returnOrderItems = getReturnOrderItems(order, request.getReturnOrderItemIds());

        BigDecimal originalAmount = calculateOriginalAmount(returnOrderItems);

        List<String> imageUrls = uploadImages(images);

        ReturnRequest returnRequest = ReturnRequest.builder()
                .orderId(orderId)
                .customerId(customerId)
                .returnReason(request.getReturnReason())
                .description(request.getDescription())
                .images(imageUrls)
                .returnType(request.getReturnType())
                .bankInfo(request.getBankInfo())
                .status(ReturnRequestStatus.PENDING_APPROVAL)
                .originalAmount(originalAmount)
                .requestedAt(LocalDateTime.now())
                .build();

        List<ReturnItem> returnItems = returnOrderItems.stream()
                .map(orderItem -> ReturnItem.builder()
                        .returnRequest(returnRequest)
                        .productId(orderItem.getProductId())
                        .productName(orderItem.getProductName())
                        .productImage(orderItem.getProductImage())
                        .price(orderItem.getPrice())
                        .ecoPoint(orderItem.getEcoPoint())
                        .build())
                .collect(Collectors.toList());

        returnRequest.setReturnItems(returnItems);

        ReturnRequest saved = returnRequestRepository.save(returnRequest);

        return mapToResponse(saved, order);
    }

    @Override
    @Transactional(readOnly = true)
    public ReturnRequestResponse getReturnRequestById(Long returnRequestId) {
        ReturnRequest returnRequest = returnRequestRepository.findById(returnRequestId)
                .orElseThrow(() -> new ReturnRequestNotFoundException(
                        "Không tìm thấy yêu cầu trả hàng: " + returnRequestId));

        Order order = orderRepository.findById(returnRequest.getOrderId())
                .orElseThrow(() -> new OrderNotFoundException(returnRequest.getOrderId()));

        return mapToResponse(returnRequest, order);
    }

    @Override
    @Transactional(readOnly = true)
    public PageResponseDTO<ReturnRequestResponse> getReturnRequestsByOrder(
            String orderId, Integer page, Integer size, String sortBy, String sortDirection) {

        Sort sort = Sort.by(
                "DESC".equalsIgnoreCase(sortDirection)
                        ? Sort.Direction.DESC
                        : Sort.Direction.ASC,
                sortBy != null ? sortBy : "createdAt"
        );

        Pageable pageable = PageRequest.of(
                page != null ? page : 0,
                size != null ? size : 10,
                sort
        );

        Page<ReturnRequest> returnRequestPage = returnRequestRepository
                .findByOrderId(orderId, pageable);

        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(orderId));

        Page<ReturnRequestResponse> responsePage = returnRequestPage.map(rr ->
                mapToResponse(rr, order)
        );

        return PageResponseUtil.toPageResponse(responsePage);
    }

    @Override
    @Transactional(readOnly = true)
    public PageResponseDTO<ReturnRequestResponse> getReturnRequestsByCustomer(
            Long customerId, Integer page, Integer size, String sortBy, String sortDirection) {

        Sort sort = Sort.by(
                "DESC".equalsIgnoreCase(sortDirection)
                        ? Sort.Direction.DESC
                        : Sort.Direction.ASC,
                sortBy != null ? sortBy : "createdAt"
        );

        Pageable pageable = PageRequest.of(
                page != null ? page : 0,
                size != null ? size : 10,
                sort
        );

        Page<ReturnRequest> returnRequestPage = returnRequestRepository
                .findByCustomerId(customerId, pageable);

        Page<ReturnRequestResponse> responsePage = returnRequestPage.map(rr -> {
            Order order = orderRepository.findById(rr.getOrderId()).orElse(null);
            return mapToResponse(rr, order);
        });

        return PageResponseUtil.toPageResponse(responsePage);
    }

    @Override
    @Transactional(readOnly = true)
    public PageResponseDTO<ReturnRequestResponse> getAllReturnRequests(ReturnRequestFilterRequest filter) {

        Specification<ReturnRequest> spec = ReturnRequestSpecification.filterReturnRequests(filter);

        Sort sort = Sort.by(
                "DESC".equalsIgnoreCase(filter.getSortDirection())
                        ? Sort.Direction.DESC
                        : Sort.Direction.ASC,
                filter.getSortBy() != null ? filter.getSortBy() : "createdAt"
        );

        Pageable pageable = PageRequest.of(
                filter.getPage() != null ? filter.getPage() : 0,
                filter.getSize() != null ? filter.getSize() : 10,
                sort
        );

        Page<ReturnRequest> returnRequestPage = returnRequestRepository.findAll(spec, pageable);

        Page<ReturnRequestResponse> responsePage = returnRequestPage.map(rr -> {
            Order order = orderRepository.findById(rr.getOrderId()).orElse(null);
            return mapToResponse(rr, order);
        });

        return PageResponseUtil.toPageResponse(responsePage);
    }

    private void validateReturnRequest(Order order, Long customerId,
                                       CreateReturnRequestRequest request,
                                       List<MultipartFile> images) {
        if (!order.getCustomerId().equals(customerId)) {
            throw new InvalidReturnRequestException(
                    "Bạn không có quyền tạo yêu cầu trả hàng cho đơn này");
        }

        if (order.getOrderStatus() != OrderStatus.COMPLETED) {
            throw new InvalidReturnRequestException(
                    "Chỉ có thể trả hàng cho đơn đã giao thành công. Trạng thái hiện tại: "
                            + order.getOrderStatus().getDescription());
        }

        LocalDateTime completedTime = order.getUpdatedAt();
        if (completedTime == null) {
            completedTime = order.getCreatedAt();
        }

        long daysSinceCompleted = ChronoUnit.DAYS.between(completedTime, LocalDateTime.now());
        if (daysSinceCompleted > RETURN_DAYS_LIMIT) {
            throw new ReturnRequestExpiredException(
                    String.format("Đơn hàng đã quá thời hạn trả hàng (%d ngày). Thời hạn cho phép: %d ngày",
                            daysSinceCompleted, RETURN_DAYS_LIMIT));
        }

        List<Long> orderItemIds = order.getOrderItems().stream()
                .map(OrderItem::getOrderItemId)
                .collect(Collectors.toList());

        for (Long orderItemId : request.getReturnOrderItemIds()) {
            if (!orderItemIds.contains(orderItemId)) {
                throw new InvalidReturnRequestException(
                        "OrderItem ID " + orderItemId + " không có trong đơn hàng");
            }
        }

        if (images != null && images.size() > MAX_IMAGES) {
            throw new InvalidReturnRequestException(
                    String.format("Số lượng ảnh vượt quá giới hạn. Tối đa %d ảnh", MAX_IMAGES));
        }

        List<ReturnRequestStatus> activeStatuses = Arrays.asList(
                ReturnRequestStatus.PENDING_APPROVAL,
                ReturnRequestStatus.APPROVED,
                ReturnRequestStatus.RETURNING,
                ReturnRequestStatus.RETURNED_TO_WAREHOUSE,
                ReturnRequestStatus.INSPECTED_APPROVED
        );

        boolean hasActiveReturn = returnRequestRepository.existsByOrderIdAndStatusIn(
                order.getOrderId(), activeStatuses);

        if (hasActiveReturn) {
            throw new InvalidReturnRequestException(
                    "Đơn hàng này đã có yêu cầu trả hàng đang được xử lý");
        }
    }

    private List<OrderItem> getReturnOrderItems(Order order, List<Long> returnOrderItemIds) {
        return order.getOrderItems().stream()
                .filter(item -> returnOrderItemIds.contains(item.getOrderItemId()))
                .collect(Collectors.toList());
    }

    private BigDecimal calculateOriginalAmount(List<OrderItem> orderItems) {
        return orderItems.stream()
                .map(OrderItem::getPrice)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
    }

    private List<String> uploadImages(List<MultipartFile> images) {
        if (images == null || images.isEmpty()) {
            return new ArrayList<>();
        }

        List<String> imageUrls = new ArrayList<>();

        for (MultipartFile image : images) {
            try {
                Map<String, String> uploadResult = cloudinaryService.uploadImage(
                        image.getBytes(),
                        "GreenLoop/ReturnRequests");

                String imageUrl = cloudinaryService.getImageUrl(uploadResult.get("asset_id"));
                imageUrls.add(imageUrl);

            } catch (Exception e) {
                throw new RuntimeException("Failed to upload return request image", e);
            }
        }

        return imageUrls;
    }

    private ReturnRequestResponse mapToResponse(ReturnRequest returnRequest, Order order) {
        List<ReturnRequestResponse.ReturnProductItem> returnProducts =
                returnRequest.getReturnItems().stream()
                        .map(item -> ReturnRequestResponse.ReturnProductItem.builder()
                                .productId(item.getProductId())
                                .productName(item.getProductName())
                                .productImage(item.getProductImage())
                                .price(item.getPrice())
                                .ecoPoint(item.getEcoPoint())
                                .build())
                        .collect(Collectors.toList());

        return ReturnRequestResponse.builder()
                .returnRequestId(returnRequest.getReturnRequestId())
                .orderId(returnRequest.getOrderId())
                .orderCode(order != null ? order.getOrderCode() : null)
                .customerId(returnRequest.getCustomerId())
                .returnProducts(returnProducts)
                .returnReason(returnRequest.getReturnReason())
                .returnReasonText(returnRequest.getReturnReason().getDescription())
                .description(returnRequest.getDescription())
                .images(returnRequest.getImages())
                .returnType(returnRequest.getReturnType())
                .returnTypeText(returnRequest.getReturnType().getDescription())
                .bankInfo(returnRequest.getBankInfo())
                .status(returnRequest.getStatus())
                .statusText(returnRequest.getStatus().getDescription())
                .returnShipmentId(returnRequest.getReturnShipmentId())
                .returnTrackingUrl(returnRequest.getReturnTrackingUrl())
                .returnCarrier(returnRequest.getReturnCarrier())
                .returnShippingStatus(returnRequest.getReturnShippingStatus())
                .estimatedReturnShippingFee(returnRequest.getEstimatedReturnShippingFee())
                .actualReturnShippingFee(returnRequest.getActualReturnShippingFee())
                .originalAmount(returnRequest.getOriginalAmount())
                .refundAmount(returnRequest.getRefundAmount())
                .rejectedReason(returnRequest.getRejectedReason())
                .approvedAt(returnRequest.getApprovedAt())
                .rejectedAt(returnRequest.getRejectedAt())
                .inspectionNote(returnRequest.getInspectionNote())
                .inspectionImages(returnRequest.getInspectionImages())
                .inspectedAt(returnRequest.getInspectedAt())
                .requestedAt(returnRequest.getRequestedAt())
                .returnedAt(returnRequest.getReturnedAt())
                .completedAt(returnRequest.getCompletedAt())
                .createdAt(returnRequest.getCreatedAt())
                .updatedAt(returnRequest.getUpdatedAt())
                .build();
    }
}
