package com.greenloop.product.controller;

import com.greenloop.product.dto.request.DonationCreateRequest;
import com.greenloop.product.dto.response.ApiResponseDTO;
import com.greenloop.product.service.DonationService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
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

}
