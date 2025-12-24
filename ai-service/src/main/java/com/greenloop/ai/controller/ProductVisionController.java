package com.greenloop.ai.controller;

import com.greenloop.ai.dto.response.ApiResponseDTO;
import com.greenloop.ai.dto.response.ProductVisionAnalysis;
import com.greenloop.ai.service.VisionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/vision/product")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Product Vision AI", description = "AI analysis for clothing products")
public class ProductVisionController {

    private final VisionService visionService;

    @Operation(
            summary = "Analyze product image for auto-fill",
            description = "Upload ảnh quần áo để AI tự động điền: tên, mô tả, tình trạng (NEW/LIKE_NEW/GOOD/FAIR/POOR)"
    )
    @PostMapping(value = "/analyze-for-creation", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponseDTO<ProductVisionAnalysis>> analyzeForProductCreation(
            @RequestParam("image") MultipartFile imageFile) {

        log.info("Analyzing product image - File: {}, Size: {} bytes",
                imageFile.getOriginalFilename(),
                imageFile.getSize());

        // Validate file
        validateImageFile(imageFile);

        // Gọi service với file
        ProductVisionAnalysis analysis = visionService.analyzeImageFile(imageFile);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Phân tích ảnh quần áo thành công", analysis)
        );
    }

    /**
     * Validate image file
     */
    private void validateImageFile(MultipartFile file) {
        // 1. Check empty
        if (file.isEmpty()) {
            throw new IllegalArgumentException("File ảnh không được để trống");
        }

        // 2. Check size (max 10MB)
        long maxSize = 10 * 1024 * 1024; // 10MB
        if (file.getSize() > maxSize) {
            throw new IllegalArgumentException("File ảnh không được vượt quá 10MB");
        }

        // 3. Check content type
        String contentType = file.getContentType();
        if (contentType == null || !contentType.startsWith("image/")) {
            throw new IllegalArgumentException("File phải là định dạng ảnh (jpg, png, webp, gif)");
        }

        // 4. Check allowed formats
        String[] allowedFormats = {"image/jpeg", "image/jpg", "image/png", "image/webp", "image/gif"};
        boolean isValidFormat = false;
        for (String format : allowedFormats) {
            if (format.equalsIgnoreCase(contentType)) {
                isValidFormat = true;
                break;
            }
        }

        if (!isValidFormat) {
            throw new IllegalArgumentException("Chỉ chấp nhận file: JPG, PNG, WEBP, GIF");
        }

        log.info("Image validation passed - Type: {}, Size: {} KB",
                contentType,
                file.getSize() / 1024);
    }
}
