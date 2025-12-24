package com.greenloop.ai.controller;

import com.greenloop.ai.dto.request.AnalyzeImageRequest;
import com.greenloop.ai.dto.response.ApiResponseDTO;
import com.greenloop.ai.dto.response.ProductVisionAnalysis;
import com.greenloop.ai.service.VisionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/vision")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Vision AI", description = "Google Vision API for product image analysis")
public class VisionController {

    private final VisionService visionService;

    @Operation(
            summary = "Analyze product image",
            description = "Analyze product image using Google Vision API to extract labels, text, brands, and suggest product name & category"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Image analyzed successfully",
                    content = @Content(schema = @Schema(implementation = ApiResponseDTO.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid image URL"
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Vision API error"
            )
    })
    @PostMapping("/analyze")
    public ResponseEntity<ApiResponseDTO<ProductVisionAnalysis>> analyzeImage(
            @Valid @RequestBody AnalyzeImageRequest request) {

        log.info("Received request to analyze image: {}", request.getImageUrl());

        ProductVisionAnalysis analysis = visionService.analyzeImage(request);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Phân tích ảnh thành công", analysis)
        );
    }

    @Operation(
            summary = "Health check",
            description = "Check if AI Service is running"
    )
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("AI Service is running!");
    }
}
