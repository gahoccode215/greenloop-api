package com.greenloop.ai.service.impl;

import com.google.cloud.vision.v1.*;
import com.greenloop.ai.dto.request.AnalyzeImageRequest;
import com.greenloop.ai.dto.response.ProductVisionAnalysis;
import com.greenloop.ai.service.VisionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class VisionServiceImpl implements VisionService {

    private final ImageAnnotatorClient visionClient;

    @Override
    public ProductVisionAnalysis analyzeImage(AnalyzeImageRequest request) {
        try {
            log.info("Analyzing image: {}", request.getImageUrl());

            // Build image từ URL
            Image image = Image.newBuilder()
                    .setSource(ImageSource.newBuilder()
                            .setImageUri(request.getImageUrl())
                            .build())
                    .build();

            // Build features (các tính năng muốn phân tích)
            List<Feature> features = new ArrayList<>();

            // 1. Label Detection - nhận diện đối tượng
            features.add(Feature.newBuilder()
                    .setType(Feature.Type.LABEL_DETECTION)
                    .setMaxResults(10)
                    .build());

            // 2. Text Detection - đọc chữ
            features.add(Feature.newBuilder()
                    .setType(Feature.Type.TEXT_DETECTION)
                    .build());

            // 3. Logo Detection - nhận diện logo/thương hiệu
            features.add(Feature.newBuilder()
                    .setType(Feature.Type.LOGO_DETECTION)
                    .build());

            // 4. Web Detection - tìm ảnh tương tự trên web
            features.add(Feature.newBuilder()
                    .setType(Feature.Type.WEB_DETECTION)
                    .build());

            // Tạo request
            AnnotateImageRequest visionRequest = AnnotateImageRequest.newBuilder()
                    .addAllFeatures(features)
                    .setImage(image)
                    .build();

            // Gọi Vision API
            BatchAnnotateImagesResponse response = visionClient.batchAnnotateImages(
                    Collections.singletonList(visionRequest)
            );

            AnnotateImageResponse imageResponse = response.getResponses(0);

            if (imageResponse.hasError()) {
                log.error("Vision API Error: {}", imageResponse.getError().getMessage());
                throw new RuntimeException("Vision API Error: " + imageResponse.getError().getMessage());
            }

            // Parse kết quả
            return parseResponse(imageResponse);

        } catch (Exception e) {
            log.error("Error analyzing image", e);
            throw new RuntimeException("Failed to analyze image: " + e.getMessage(), e);
        }
    }

    private ProductVisionAnalysis parseResponse(AnnotateImageResponse response) {
        // 1. Extract labels
        List<String> labels = response.getLabelAnnotationsList().stream()
                .filter(label -> label.getScore() > 0.7) // Chỉ lấy độ tin cậy > 70%
                .map(EntityAnnotation::getDescription)
                .collect(Collectors.toList());

        // 2. Extract text
        String detectedText = "";
        if (response.getTextAnnotationsCount() > 0) {
            detectedText = response.getTextAnnotations(0).getDescription();
        }

        // 3. Extract logos/brands
        List<String> brands = response.getLogoAnnotationsList().stream()
                .map(EntityAnnotation::getDescription)
                .collect(Collectors.toList());

        // 4. Extract web entities (gợi ý tên sản phẩm)
        String suggestedName = "";
        if (response.getWebDetection().getWebEntitiesCount() > 0) {
            suggestedName = response.getWebDetection()
                    .getWebEntitiesList()
                    .stream()
                    .filter(entity -> entity.getDescription() != null && !entity.getDescription().isEmpty())
                    .findFirst()
                    .map(WebDetection.WebEntity::getDescription)
                    .orElse("");
        }

        // 5. Gợi ý category dựa trên labels
        String suggestedCategory = inferCategory(labels);

        log.info("Analysis result - Labels: {}, Brands: {}, Category: {}",
                labels.size(), brands.size(), suggestedCategory);

        return ProductVisionAnalysis.builder()
                .labels(labels)
                .detectedText(detectedText)
                .brands(brands)
                .suggestedName(suggestedName.isEmpty() ? (labels.isEmpty() ? "Unknown Product" : labels.get(0)) : suggestedName)
                .suggestedCategory(suggestedCategory)
                .build();
    }

    private String inferCategory(List<String> labels) {
        for (String label : labels) {
            String lower = label.toLowerCase();

            if (lower.contains("clothing") || lower.contains("shirt") ||
                    lower.contains("dress") || lower.contains("pants") ||
                    lower.contains("jacket")) {
                return "CLOTHING";
            }

            if (lower.contains("shoe") || lower.contains("footwear") ||
                    lower.contains("sneaker") || lower.contains("boot")) {
                return "FOOTWEAR";
            }

            if (lower.contains("bag") || lower.contains("purse") ||
                    lower.contains("backpack") || lower.contains("wallet")) {
                return "ACCESSORIES";
            }

            if (lower.contains("electronics") || lower.contains("phone") ||
                    lower.contains("laptop") || lower.contains("gadget")) {
                return "ELECTRONICS";
            }
        }

        return "OTHER";
    }
}
