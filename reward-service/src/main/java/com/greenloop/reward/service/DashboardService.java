package com.greenloop.reward.service;

import com.greenloop.reward.dto.response.EcoPointStatisticsResponse;
import com.greenloop.reward.dto.response.VoucherStatisticsResponse;

public interface DashboardService {
    EcoPointStatisticsResponse getEcoPointStatistics();

    VoucherStatisticsResponse getVoucherStatistics();
}
