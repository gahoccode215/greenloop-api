package com.greenloop.product.service;

import com.greenloop.product.dto.request.DonationCreateRequest;
import com.greenloop.product.dto.request.UpdateDonationItemStatusRequest;
import com.greenloop.product.dto.response.*;
import com.greenloop.product.enums.DonationItemStatus;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface DonationService {
    Long createDonation(DonationCreateRequest donationCreateRequest, List<MultipartFile> files);

    List<DonationResponse> getDonationsByEventId(Long eventId);

    List<DonationResponse> getMyDonations();

    DonationDetailResponse getDonationById(Long donationId);

    UpdateDonationItemStatusResponse changeStatusDonationItems(UpdateDonationItemStatusRequest request);

    PageResponseDTO<DonationItemDetailResponse> getDonationItems(String code, String name, Long donationId, DonationItemStatus status, Long eventId, Pageable pageable );

}
