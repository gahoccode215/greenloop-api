package com.greenloop.reward.service;

import com.greenloop.reward.dto.request.VoucherUsedRequest;

public interface RewardInternalService {
  void markVoucherAsUsed(VoucherUsedRequest request);

  void addEcoPointsForOnlineOrder(
      Long customerId, Integer points, String orderId, String orderCode);
}
