package com.greenloop.ai.controller;

import com.greenloop.ai.dto.request.AnalyzeImageRequest;
import com.greenloop.ai.dto.response.ApiResponseDTO;
import com.greenloop.ai.dto.response.ProductVisionAnalysis;
import com.greenloop.ai.service.VisionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/vision")
@RequiredArgsConstructor
@Slf4j
public class VisionController {

    private final VisionService visionService; // Inject service thật

    @PostMapping("/analyze")
    public ResponseEntity<ApiResponseDTO<ProductVisionAnalysis>> analyzeImage(
            @Valid @RequestBody AnalyzeImageRequest request) {

        log.info("Received request to analyze image: {}", request.getImageUrl());

        ProductVisionAnalysis analysis = visionService.analyzeImage(request);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Phân tích ảnh thành công", analysis)
        );
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("AI Service is running!");
    }
}
