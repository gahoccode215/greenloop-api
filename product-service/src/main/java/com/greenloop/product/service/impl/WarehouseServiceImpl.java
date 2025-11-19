package com.greenloop.product.service.impl;

import com.greenloop.product.dto.request.UpdateDonationItemStatusRequest;
import com.greenloop.product.dto.response.UpdateDonationItemStatusResponse;
import com.greenloop.product.entity.DonationItem;
import com.greenloop.product.enums.DonationItemStatus;
import com.greenloop.product.repository.DonationItemRepository;
import com.greenloop.product.service.WarehouseService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class WarehouseServiceImpl implements WarehouseService {
    private final DonationItemRepository donationItemRepository;

    @Override
    @Transactional
    public UpdateDonationItemStatusResponse changeStatusDonationItems(UpdateDonationItemStatusRequest request) {

        List<String> codes = request.getDonationItemCodes();
        DonationItemStatus newStatus = request.getDonationItemStatus();

        log.info("Updating donation items status. Codes: {}, New status: {}", codes, newStatus);

        List<DonationItem> items = donationItemRepository.findAllByCodeIn(codes);

        Set<String> foundCodes = items.stream()
                .map(DonationItem::getCode)
                .collect(Collectors.toSet());

        List<String> notFoundCodes = codes.stream()
                .filter(code -> !foundCodes.contains(code))
                .toList();

        items.forEach(item -> item.setStatus(newStatus));
        donationItemRepository.saveAll(items);

        List<String> updatedCodes = items.stream()
                .map(DonationItem::getCode)
                .toList();

        log.info("Updated {} items. Not found: {}", updatedCodes.size(), notFoundCodes);

        return UpdateDonationItemStatusResponse.builder()
                .updatedCodes(updatedCodes)
                .notFoundCodes(notFoundCodes)
                .build();
    }


}
