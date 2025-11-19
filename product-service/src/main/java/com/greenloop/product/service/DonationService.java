package com.greenloop.product.service;

import com.greenloop.product.dto.request.DonationCreateRequest;
import com.greenloop.product.dto.request.UpdateDonationItemStatusRequest;
import com.greenloop.product.dto.response.DonationDetailResponse;
import com.greenloop.product.dto.response.DonationResponse;
import com.greenloop.product.dto.response.UpdateDonationItemStatusResponse;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface DonationService {
    Long createDonation(DonationCreateRequest donationCreateRequest, List<MultipartFile> files);

    List<DonationResponse> getDonationsByEventId(Long eventId);

    List<DonationResponse> getMyDonations();

    DonationDetailResponse getDonationById(Long donationId);

    UpdateDonationItemStatusResponse changeStatusDonationItems(UpdateDonationItemStatusRequest request);

}
