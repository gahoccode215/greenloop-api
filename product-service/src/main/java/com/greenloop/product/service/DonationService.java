package com.greenloop.product.service;

import com.greenloop.product.dto.request.DonationCreateRequest;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface DonationService {
    Long createDonation(DonationCreateRequest donationCreateRequest, List<MultipartFile> files);
}
