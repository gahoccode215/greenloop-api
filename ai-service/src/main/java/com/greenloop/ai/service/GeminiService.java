package com.greenloop.ai.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.chat.prompt.PromptTemplate;
import org.springframework.ai.vertexai.gemini.VertexAiGeminiChatModel;
import org.springframework.ai.vertexai.gemini.VertexAiGeminiChatOptions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class GeminiService {

    private final VertexAiGeminiChatModel chatModel;

    @Value("classpath:/promptTemplates/productNameTemplate.st")
    private Resource namePromptTemplate;

    @Value("classpath:/promptTemplates/productDescriptionTemplate.st")
    private Resource descriptionPromptTemplate;

    public String generateClothingName(String structuredData) {
        return generate(structuredData, namePromptTemplate, 0.7, 100, "name");
    }

    public String generateClothingDescription(String structuredData) {
        return generate(structuredData, descriptionPromptTemplate, 0.75, 800, "description");
    }

    private String generate(String structuredData, Resource template, double temperature, int maxTokens, String type) {
        try {
            String templateContent = loadTemplate(template);
            PromptTemplate promptTemplate = new PromptTemplate(templateContent);
            Prompt prompt = promptTemplate.create(Map.of("structuredData", structuredData));

            ChatResponse response = chatModel.call(
                    new Prompt(
                            prompt.getContents(),
                            VertexAiGeminiChatOptions.builder()
                                    .temperature(temperature)
                                    .maxOutputTokens(maxTokens)
                                    .topK(40)
                                    .topP(0.9)
                                    .build()
                    )
            );

            if (response == null || response.getResult() == null || response.getResult().getOutput() == null) {
                log.error("Null response from Gemini API for {}", type);
                return null;
            }

            String text = response.getResult().getOutput().getContent();
            if (text == null || text.isBlank()) {
                log.error("Empty content from Gemini API for {}", type);
                return null;
            }

            String cleaned = type.equals("name") ? cleanProductName(text) : cleanDescription(text);
            log.info("Generated {} successfully", type);
            return cleaned;

        } catch (Exception e) {
            log.error("Error generating {}: {}", type, e.getMessage());
            return null;
        }
    }

    private String loadTemplate(Resource resource) throws IOException {
        return resource.getContentAsString(StandardCharsets.UTF_8);
    }

    private String cleanProductName(String text) {
        if (text == null || text.isBlank()) return null;

        text = text.replace("\n", " ")
                .replaceAll("\\s+", " ")
                .replaceAll("^\\d+\\.\\s*", "")
                .replaceAll("^[-•*]\\s*", "")
                .replaceAll("\\*+", "")
                .replaceAll("\\(.*?\\)", "")
                .replaceAll("^[\"'`]+|[\"'`]+$", "")
                .replaceAll("^TÊN SẢN PHẨM:\\s*", "")
                .replaceAll("^Tên sản phẩm:\\s*", "")
                .replaceAll("[🔥💥❤️✨👕👗🎉]", "")
                .trim();

        if (text.contains(".")) {
            text = text.substring(0, text.indexOf(".")).trim();
        }

        if (text.length() > 80) {
            int lastSpace = text.lastIndexOf(' ', 80);
            text = lastSpace > 50 ? text.substring(0, lastSpace) : text.substring(0, 80);
        }

        return text.isEmpty() ? null : text;
    }

    private String cleanDescription(String text) {
        if (text == null || text.isBlank()) return null;

        text = text.replace("\n", " ")
                .replaceAll("\\s+", " ")
                .replaceAll("\\*+", "")
                .replaceAll("^[\"'`]+|[\"'`]+$", "")
                .replaceAll("^MÔ TẢ SẢN PHẨM:\\s*", "")
                .replaceAll("^Mô tả sản phẩm:\\s*", "")
                .replaceAll("[🔥💥❤️✨👕👗🎉💯⭐🌟]", "")
                .replaceAll("[\\\\/*#~@$%^&]", "")
                .replaceAll("HOT TREND\\s*-\\s*", "")
                .replaceAll("SIÊU HOT\\s*-\\s*", "")
                .trim();

        if (text.length() > 600) {
            int lastPeriod = text.lastIndexOf(".", 600);
            if (lastPeriod > 400) {
                text = text.substring(0, lastPeriod + 1);
            } else {
                int lastSpace = text.lastIndexOf(" ", 600);
                text = (lastSpace > 400 ? text.substring(0, lastSpace) : text.substring(0, 597)) + ".";
            }
        }

        return text.isEmpty() ? null : text;
    }
}
