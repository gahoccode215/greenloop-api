package com.greenloop.ai.service;

import com.greenloop.ai.dto.response.ProductVisionAnalysis;
import org.springframework.web.multipart.MultipartFile;

public interface VisionService {

    ProductVisionAnalysis analyzeImageFile(MultipartFile imageFile);
}
