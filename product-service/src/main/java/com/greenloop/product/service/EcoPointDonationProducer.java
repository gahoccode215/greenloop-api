package com.greenloop.product.service;

import com.greenloop.product.dto.event.EcoPointTransactionDTO;

public interface EcoPointDonationProducer {
    void sendEcoPointDonationMessage(EcoPointTransactionDTO ecoPointTransactionDTO);
}
