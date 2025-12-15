package com.greenloop.product.service;

import com.greenloop.product.dto.response.CategoryStatisticsResponse;
import com.greenloop.product.dto.response.DonationStatisticsResponse;
import com.greenloop.product.dto.response.EventProductMappingStatisticsResponse;
import com.greenloop.product.dto.response.ProductStatisticsResponse;

public interface DashboardService {
    ProductStatisticsResponse getProductStatistics();

    CategoryStatisticsResponse getCategoryStatistics();

    DonationStatisticsResponse getDonationStatistics();

    EventProductMappingStatisticsResponse getEventProductMappingStatistics();
}
