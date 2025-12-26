package com.greenloop.ai.config;

import com.google.cloud.vision.v1.ImageAnnotatorClient;
import com.google.cloud.vision.v1.ImageAnnotatorSettings;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;

@Configuration
@Slf4j
public class GoogleCloudConfig {

    @Value("${spring.ai.vertex.ai.gemini.project-id:greenloop-482114}")
    private String projectId;

    @Value("${spring.ai.vertex.ai.gemini.location:us-central1}")
    private String location;

    /**
     * Bean cho Google Cloud Vision API
     * Dùng để phân tích ảnh (labels, text, logo detection)
     */
    @Bean
    public ImageAnnotatorClient imageAnnotatorClient() throws IOException {
        log.info("Initializing ImageAnnotatorClient for project: {}", projectId);

        // Cách 1: Default credentials (khuyến nghị cho production)
        return ImageAnnotatorClient.create();

        // Cách 2: Custom settings (nếu cần cấu hình endpoint, timeout...)
        // ImageAnnotatorSettings settings = ImageAnnotatorSettings.newBuilder()
        //     .build();
        // return ImageAnnotatorClient.create(settings);
    }

    /**
     * KHÔNG CẦN Bean VertexAI nữa!
     * Spring AI tự động tạo VertexAiGeminiChatModel từ application.yml
     *
     * Xem: https://docs.spring.io/spring-ai/reference/api/chat/vertexai-gemini-chat.html
     */
    // @Bean
    // public VertexAI vertexAI() {
    //     return new VertexAI(projectId, location);
    // }
}
