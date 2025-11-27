package com.greenloop.event.service;

import com.greenloop.event.dto.response.EcoPointTransactionDTO;

public interface EcoPointCheckInProducer {
  void sendEcoPointDonationMessage(EcoPointTransactionDTO ecoPointTransactionDTO);
}
