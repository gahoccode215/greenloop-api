package com.greenloop.reward.service;

import com.greenloop.reward.dto.event.EcoPointTransactionDTO;
import com.greenloop.reward.dto.response.EcoPointLeaderboardResponse;
import com.greenloop.reward.dto.response.EcoPointUserResponse;

public interface EcoPointUserService {
  void updateEcoPointUserBalance(EcoPointTransactionDTO ecoPointTransactionDTO);

  EcoPointUserResponse getEcoPointOfUser(Long userId);

  EcoPointLeaderboardResponse getEcoPointUserDTOByUser();

  void addEcoPointsForOfflineOrder(
      Long customerId, Integer points, String orderId, String orderCode);

    void addEcoPointsForOnlineOrder(Long customerId, Integer points, String orderId, String orderCode);
}
