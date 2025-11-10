package com.greenloop.product.controller;

import com.greenloop.product.dto.request.DonationCreateRequest;
import com.greenloop.product.dto.response.ApiResponseDTO;
import com.greenloop.product.dto.response.DonationDetailResponse;
import com.greenloop.product.dto.response.DonationResponse;
import com.greenloop.product.service.DonationService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/v1/donations")
@RequiredArgsConstructor
@Slf4j
public class DonationController {
    private final DonationService donationService;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Create a new donation", description = "Creates a new donation with optional thumbnail images.")
    public ResponseEntity<ApiResponseDTO<Long>> createDonation(@RequestPart("event") @Valid DonationCreateRequest request,
                                                               @RequestPart(value = "thumbnail", required = false) List<MultipartFile> multipartFile) {
        return ResponseEntity.ok(
                ApiResponseDTO.<Long>builder()
                        .data(donationService.createDonation(request, multipartFile))
                        .message("Donation created successfully")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build());
    }

    @GetMapping("/event/{eventId}")
    @Operation(summary = "Get donations by event ID", description = "Retrieves all donations associated with a specific event ID.")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_STAFF', 'ROLE_STORE_MANAGER', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<List<DonationResponse>>> getDonationsByEventId(@PathVariable Long eventId) {

        List<DonationResponse> donations = donationService.getDonationsByEventId(eventId);

        return ResponseEntity.ok(
                ApiResponseDTO.<List<DonationResponse>>builder()
                        .data(donations)
                        .message("Donations retrieved successfully")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build());

    }

    @GetMapping("/{donationId}")
    @Operation(summary = "Get donation by ID", description = "Retrieves a specific donation by its ID.")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponseDTO<DonationDetailResponse>> getDonationById(@PathVariable Long donationId) {
        DonationDetailResponse donation = donationService.getDonationById(donationId);
        return ResponseEntity.ok(
                ApiResponseDTO.<DonationDetailResponse>builder()
                        .data(donation)
                        .message("Donation retrieved successfully")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build()
        );
    }

    @GetMapping("/my-donations")
    @Operation(summary = "Get my donations", description = "Retrieves donations made by the authenticated user.")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponseDTO<List<DonationResponse>>> getMyDonations() {
        List<DonationResponse> myDonations = donationService.getMyDonations();
        return ResponseEntity.ok(
                ApiResponseDTO.<List<DonationResponse>>builder()
                        .data(myDonations)
                        .message("My donations retrieved successfully")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build());
    }


}
