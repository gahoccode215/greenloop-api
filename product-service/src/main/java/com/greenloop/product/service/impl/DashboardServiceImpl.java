package com.greenloop.product.service.impl;

import com.greenloop.product.dto.response.CategoryStatisticsResponse;
import com.greenloop.product.dto.response.DonationStatisticsResponse;
import com.greenloop.product.dto.response.EventProductMappingStatisticsResponse;
import com.greenloop.product.dto.response.ProductStatisticsResponse;
import com.greenloop.product.enums.*;
import com.greenloop.product.repository.*;
import com.greenloop.product.service.DashboardService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class DashboardServiceImpl implements DashboardService {
    private final ProductRepository productRepository;
    private final CategoryRepository categoryRepository;
    private final DonationRepository donationRepository;
    private final DonationItemRepository donationItemRepository;
    private final EventProductMappingRepository eventProductMappingRepository;

    @Override
    public ProductStatisticsResponse getProductStatistics() {
        Long totalProducts = productRepository.count();

        Map<ProductStatus, Long> productsByStatus = Arrays.stream(ProductStatus.values())
                .collect(Collectors.toMap(
                        status -> status,
                        status -> productRepository.countByStatus(status)
                ));

        Map<ProductType, Long> productsByType = Arrays.stream(ProductType.values())
                .collect(Collectors.toMap(
                        type -> type,
                        type -> productRepository.countByType(type)
                ));

        Map<ConditionGrade, Long> productsByCondition = Arrays.stream(ConditionGrade.values())
                .collect(Collectors.toMap(
                        grade -> grade,
                        grade -> productRepository.countByConditionGrade(grade)
                ));

        List<ProductStatisticsResponse.TopProduct> topProducts =
                productRepository.findTopSoldProducts().stream()
                        .map(row -> ProductStatisticsResponse.TopProduct.builder()
                                .productId((Long) row[0])
                                .name((String) row[1])
                                .soldCount(((Number) row[2]).longValue())
                                .build())
                        .collect(Collectors.toList());

        return ProductStatisticsResponse.builder()
                .totalProducts(totalProducts)
                .productsByStatus(productsByStatus)
                .productsByType(productsByType)
                .productsByCondition(productsByCondition)
                .topProducts(topProducts)
                .build();
    }

    @Override
    public CategoryStatisticsResponse getCategoryStatistics() {
        Long totalCategories = categoryRepository.count();

        List<CategoryStatisticsResponse.CategoryCount> categoryCounts =
                categoryRepository.countProductsByCategory().stream()
                        .map(row -> CategoryStatisticsResponse.CategoryCount.builder()
                                .categoryId((Long) row[0])
                                .name((String) row[1])
                                .productCount(((Number) row[2]).longValue())
                                .build())
                        .collect(Collectors.toList());

        return CategoryStatisticsResponse.builder()
                .totalCategories(totalCategories)
                .categoryCounts(categoryCounts)
                .build();
    }

    @Override
    public DonationStatisticsResponse getDonationStatistics() {
        Long totalDonations = donationRepository.count();
        Long totalDonationItems = donationItemRepository.count();

        Map<DonationItemStatus, Long> itemsByStatus = Arrays.stream(DonationItemStatus.values())
                .collect(Collectors.toMap(
                        status -> status,
                        status -> donationItemRepository.countByStatus(status)
                ));

        Map<ConditionGrade, Long> itemsByCondition = Arrays.stream(ConditionGrade.values())
                .collect(Collectors.toMap(
                        grade -> grade,
                        grade -> donationItemRepository.countByConditionGrade(grade)
                ));

        return DonationStatisticsResponse.builder()
                .totalDonations(totalDonations)
                .totalDonationItems(totalDonationItems)
                .itemsByStatus(itemsByStatus)
                .itemsByCondition(itemsByCondition)
                .build();
    }

    @Override
    public EventProductMappingStatisticsResponse getEventProductMappingStatistics() {
        Long totalMappings = eventProductMappingRepository.count();

        Map<EventMappingStatus, Long> mappingsByStatus = Arrays.stream(EventMappingStatus.values())
                .collect(Collectors.toMap(
                        status -> status,
                        status -> eventProductMappingRepository.countByStatus(status)
                ));

        List<EventProductMappingStatisticsResponse.EventProductCount> eventProductCounts =
                eventProductMappingRepository.countProductsByEvent().stream()
                        .map(row -> EventProductMappingStatisticsResponse.EventProductCount.builder()
                                .eventId((Long) row[0])
                                .productCount(((Number) row[1]).longValue())
                                .build())
                        .collect(Collectors.toList());

        return EventProductMappingStatisticsResponse.builder()
                .totalMappings(totalMappings)
                .mappingsByStatus(mappingsByStatus)
                .eventProductCounts(eventProductCounts)
                .build();
    }
}
