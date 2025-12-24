package com.greenloop.ai.service;

import com.greenloop.ai.dto.request.AnalyzeImageRequest;
import com.greenloop.ai.dto.response.ProductVisionAnalysis;

public interface VisionService {
    ProductVisionAnalysis analyzeImage(AnalyzeImageRequest request);
}
