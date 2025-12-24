package com.greenloop.ai.config;

import com.google.cloud.vision.v1.ImageAnnotatorClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;

@Configuration
@Slf4j
public class GoogleVisionConfig {

    @Bean
    public ImageAnnotatorClient imageAnnotatorClient() throws IOException {

        return ImageAnnotatorClient.create();
    }
}
