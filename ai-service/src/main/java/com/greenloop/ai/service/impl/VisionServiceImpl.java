package com.greenloop.ai.service.impl;

import com.google.cloud.vision.v1.*;
import com.google.protobuf.ByteString;
import com.greenloop.ai.dto.response.ProductVisionAnalysis;
import com.greenloop.ai.service.GeminiService;
import com.greenloop.ai.service.VisionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class VisionServiceImpl implements VisionService {

    private final ImageAnnotatorClient visionClient;
    private final GeminiService geminiService;

    @Override
    public ProductVisionAnalysis analyzeImageFile(MultipartFile imageFile) {
        try {
            ByteString imageBytes = ByteString.copyFrom(imageFile.getBytes());

            Image image = Image.newBuilder()
                    .setContent(imageBytes)
                    .build();

            List<Feature> features = Arrays.asList(
                    Feature.newBuilder()
                            .setType(Feature.Type.LABEL_DETECTION)
                            .setMaxResults(20)
                            .build(),
                    Feature.newBuilder()
                            .setType(Feature.Type.TEXT_DETECTION)
                            .build(),
                    Feature.newBuilder()
                            .setType(Feature.Type.LOGO_DETECTION)
                            .build()
            );

            AnnotateImageRequest visionRequest = AnnotateImageRequest.newBuilder()
                    .addAllFeatures(features)
                    .setImage(image)
                    .build();

            BatchAnnotateImagesResponse response = visionClient.batchAnnotateImages(
                    Collections.singletonList(visionRequest)
            );

            AnnotateImageResponse imageResponse = response.getResponses(0);

            if (imageResponse.hasError()) {
                throw new RuntimeException("Vision API Error: " + imageResponse.getError().getMessage());
            }

            return parseResponseWithGemini(imageResponse);

        } catch (Exception e) {
            throw new RuntimeException("Failed to analyze image file: " + e.getMessage(), e);
        }
    }

    private ProductVisionAnalysis parseResponseWithGemini(AnnotateImageResponse response) {
        List<String> labels = response.getLabelAnnotationsList().stream()
                .filter(label -> label.getScore() > 0.55)
                .map(EntityAnnotation::getDescription)
                .collect(Collectors.toList());

        String detectedText = "";
        if (response.getTextAnnotationsCount() > 0) {
            detectedText = response.getTextAnnotations(0).getDescription();
        }

        List<String> brands = response.getLogoAnnotationsList().stream()
                .map(EntityAnnotation::getDescription)
                .collect(Collectors.toList());

        String structuredData = buildStructuredData(response, labels, brands, detectedText);

        log.info("Structured data for Gemini:\n{}", structuredData);

        String suggestedName = geminiService.generateClothingName(structuredData);
        if (suggestedName == null || suggestedName.isEmpty()) {
            suggestedName = generateFallbackName(labels, brands);
        }

        String suggestedDescription = geminiService.generateClothingDescription(structuredData);
        if (suggestedDescription == null || suggestedDescription.isEmpty()) {
            suggestedDescription = generateFallbackDescription(structuredData);
        }

        String suggestedConditionGrade = inferConditionGrade(detectedText, labels);
        Double confidence = calculateConfidence(response);

        return ProductVisionAnalysis.builder()
                .labels(labels)
                .detectedText(detectedText)
                .brands(brands)
                .suggestedName(suggestedName)
                .suggestedDescription(suggestedDescription)
                .suggestedConditionGrade(suggestedConditionGrade)
                .confidence(confidence)
                .build();
    }

    private String buildStructuredData(AnnotateImageResponse response,
                                       List<String> labels,
                                       List<String> brands,
                                       String detectedText) {
        StringBuilder data = new StringBuilder();

        if (!brands.isEmpty()) {
            data.append("Brand: ").append(brands.get(0)).append("\n");
        }

        String clothingType = detectClothingType(labels);
        if (clothingType != null) {
            data.append("Clothing Type: ").append(clothingType).append("\n");
        } else {
            data.append("Clothing Type: Fashion item\n");
        }

        List<String> colors = extractAllColors(labels);
        if (!colors.isEmpty()) {
            data.append("Colors: ").append(String.join(", ", colors)).append("\n");
        } else {
            data.append("Colors: Not clearly visible\n");
        }

        String material = extractMaterial(response);
        if (material != null) {
            data.append("Material: ").append(material).append("\n");
        }

        String pattern = extractPattern(labels);
        if (pattern != null) {
            data.append("Pattern: ").append(pattern).append("\n");
        }

        String style = extractStyle(labels);
        if (style != null) {
            data.append("Style: ").append(style).append("\n");
        }

        String fit = extractFit(labels);
        if (fit != null) {
            data.append("Fit: ").append(fit).append("\n");
        }

        String size = extractSize(response);
        if (size != null) {
            data.append("Size: ").append(size).append("\n");
        }

        List<String> details = extractClothingDetails(labels);
        if (!details.isEmpty()) {
            data.append("Design Details: ").append(String.join(", ", details)).append("\n");
        }

        if (!detectedText.isEmpty()) {
            String cleanedText = cleanDetectedText(detectedText);
            data.append("Text on Label: ").append(cleanedText).append("\n");
        }

        data.append("Visual Features: ").append(
                labels.stream()
                        .filter(label -> !isBasicLabel(label))
                        .limit(10)
                        .collect(Collectors.joining(", "))
        );

        data.append("\nCondition: Secondhand, good condition");

        return data.toString();
    }

    private String generateFallbackName(List<String> labels, List<String> brands) {
        StringBuilder name = new StringBuilder();
        if (!brands.isEmpty()) {
            name.append(brands.get(0)).append(" ");
        }
        String type = detectClothingType(labels);
        if (type != null) {
            name.append(type);
        } else if (!labels.isEmpty()) {
            name.append(labels.get(0));
        } else {
            name.append("Sản phẩm thời trang");
        }
        return name.toString().trim();
    }

    private String generateFallbackDescription(String structuredData) {
        String flat = structuredData.replace("\n", ", ").replaceAll("\\s+", " ").trim();
        return "Sản phẩm thời trang đã qua sử dụng, tình trạng còn tốt, phù hợp cho nhiều dịp khác nhau. Chi tiết: " + flat;
    }

    private String inferConditionGrade(String detectedText, List<String> labels) {
        String textLower = detectedText.toLowerCase();
        String allLabels = String.join(" ", labels).toLowerCase();

        if (containsAny(textLower, Arrays.asList("new", "mới", "brand new")) ||
                containsAny(allLabels, Arrays.asList("new"))) {
            return "NEW";
        }
        if (containsAny(textLower, Arrays.asList("like new", "như mới", "mint", "excellent")) ||
                containsAny(allLabels, Arrays.asList("mint"))) {
            return "LIKE_NEW";
        }
        if (containsAny(textLower, Arrays.asList("good", "tốt", "clean")) ||
                containsAny(allLabels, Arrays.asList("good"))) {
            return "GOOD";
        }
        if (containsAny(textLower, Arrays.asList("used", "fair", "wear")) ||
                containsAny(allLabels, Arrays.asList("worn"))) {
            return "FAIR";
        }
        if (containsAny(textLower, Arrays.asList("poor", "damaged", "torn", "rách")) ||
                containsAny(allLabels, Arrays.asList("damaged"))) {
            return "POOR";
        }
        return "LIKE_NEW";
    }

    private String detectClothingType(List<String> labels) {
        Map<String, String> clothingTypes = new LinkedHashMap<>();
        clothingTypes.put("t-shirt", "T-shirt");
        clothingTypes.put("shirt", "Shirt");
        clothingTypes.put("polo", "Polo");
        clothingTypes.put("blouse", "Blouse");
        clothingTypes.put("sweater", "Sweater");
        clothingTypes.put("hoodie", "Hoodie");
        clothingTypes.put("jacket", "Jacket");
        clothingTypes.put("coat", "Coat");
        clothingTypes.put("blazer", "Blazer");
        clothingTypes.put("cardigan", "Cardigan");
        clothingTypes.put("jeans", "Jeans");
        clothingTypes.put("pants", "Pants");
        clothingTypes.put("trousers", "Trousers");
        clothingTypes.put("shorts", "Shorts");
        clothingTypes.put("skirt", "Skirt");
        clothingTypes.put("leggings", "Leggings");
        clothingTypes.put("dress", "Dress");
        clothingTypes.put("gown", "Gown");

        for (String label : labels) {
            for (Map.Entry<String, String> entry : clothingTypes.entrySet()) {
                if (label.toLowerCase().contains(entry.getKey())) {
                    return entry.getValue();
                }
            }
        }
        return null;
    }

    private List<String> extractAllColors(List<String> labels) {
        Set<String> colors = new LinkedHashSet<>();
        for (String label : labels) {
            if (label.equalsIgnoreCase("Blue") || label.equalsIgnoreCase("Red") ||
                    label.equalsIgnoreCase("Black") || label.equalsIgnoreCase("White") ||
                    label.equalsIgnoreCase("Green") || label.equalsIgnoreCase("Yellow") ||
                    label.equalsIgnoreCase("Pink") || label.equalsIgnoreCase("Gray") ||
                    label.equalsIgnoreCase("Grey") || label.equalsIgnoreCase("Brown") ||
                    label.equalsIgnoreCase("Purple") || label.equalsIgnoreCase("Orange") ||
                    label.equalsIgnoreCase("Beige") || label.equalsIgnoreCase("Navy")) {
                colors.add(label);
            }
        }
        return new ArrayList<>(colors).stream().limit(3).collect(Collectors.toList());
    }

    private String extractMaterial(AnnotateImageResponse response) {
        if (response.getTextAnnotationsCount() == 0) return null;
        String text = response.getTextAnnotations(0).getDescription().toLowerCase();

        List<String> materials = Arrays.asList("cotton", "polyester", "denim", "silk",
                "wool", "linen", "leather", "suede", "nylon", "spandex", "rayon",
                "chiffon", "satin", "velvet");

        for (String material : materials) {
            if (text.contains(material)) {
                return material.substring(0, 1).toUpperCase() + material.substring(1);
            }
        }
        return null;
    }

    private String extractPattern(List<String> labels) {
        Map<String, String> patterns = Map.of(
                "striped", "Striped",
                "plaid", "Plaid",
                "floral", "Floral",
                "polka dot", "Polka dot",
                "solid", "Solid"
        );

        for (String label : labels) {
            for (Map.Entry<String, String> entry : patterns.entrySet()) {
                if (label.toLowerCase().contains(entry.getKey())) {
                    return entry.getValue();
                }
            }
        }
        return null;
    }

    private String extractStyle(List<String> labels) {
        Map<String, String> styles = Map.of(
                "casual", "Casual",
                "formal", "Formal",
                "vintage", "Vintage",
                "sporty", "Sporty",
                "elegant", "Elegant"
        );

        for (String label : labels) {
            for (Map.Entry<String, String> entry : styles.entrySet()) {
                if (label.toLowerCase().contains(entry.getKey())) {
                    return entry.getValue();
                }
            }
        }
        return null;
    }

    private String extractFit(List<String> labels) {
        Map<String, String> fits = Map.of(
                "slim", "Slim",
                "oversized", "Oversized",
                "loose", "Loose",
                "regular", "Regular"
        );

        for (String label : labels) {
            for (Map.Entry<String, String> entry : fits.entrySet()) {
                if (label.toLowerCase().contains(entry.getKey())) {
                    return entry.getValue();
                }
            }
        }
        return null;
    }

    private List<String> extractClothingDetails(List<String> labels) {
        List<String> details = new ArrayList<>();
        Map<String, String> detailsMap = Map.of(
                "sleeve", "Sleeve",
                "collar", "Collar",
                "pocket", "Pocket",
                "button", "Button",
                "zipper", "Zipper"
        );

        for (String label : labels) {
            for (Map.Entry<String, String> entry : detailsMap.entrySet()) {
                if (label.toLowerCase().contains(entry.getKey())) {
                    details.add(entry.getValue());
                }
            }
        }
        return details.stream().distinct().limit(5).collect(Collectors.toList());
    }

    private String cleanDetectedText(String detectedText) {
        if (detectedText == null || detectedText.isBlank()) {
            return "";
        }
        String[] lines = detectedText.split("\n");
        List<String> validLines = new ArrayList<>();
        for (String line : lines) {
            line = line.trim();
            if (!line.isEmpty() && line.length() >= 2 && line.length() < 100 && validLines.size() < 8) {
                validLines.add(line);
            }
        }
        return String.join(", ", validLines);
    }

    private boolean isBasicLabel(String label) {
        List<String> basicLabels = Arrays.asList(
                "Clothing", "Textile", "Fashion", "Wear", "Apparel",
                "Product", "Material", "Design", "Style", "Item"
        );
        return basicLabels.stream().anyMatch(label::equalsIgnoreCase);
    }

    private boolean containsAny(String text, List<String> keywords) {
        return keywords.stream().anyMatch(text::contains);
    }

    private Double calculateConfidence(AnnotateImageResponse response) {
        if (response.getLabelAnnotationsList().isEmpty()) {
            return 0.0;
        }
        return response.getLabelAnnotationsList().stream()
                .limit(10)
                .mapToDouble(EntityAnnotation::getScore)
                .average()
                .orElse(0.0);
    }

    private String extractSize(AnnotateImageResponse response) {
        if (response.getTextAnnotationsCount() == 0) return null;
        String text = response.getTextAnnotations(0).getDescription().toUpperCase();

        Pattern sizePattern = Pattern.compile("SIZE[:=\\s]+(XS|S|M|L|XL|XXL|XXXL|\\d{2,3})");
        Matcher matcher = sizePattern.matcher(text);
        if (matcher.find()) {
            return matcher.group(1);
        }

        Pattern standaloneSize = Pattern.compile("\\b(XS|S|M|L|XL|XXL|XXXL)\\b");
        Matcher matcher2 = standaloneSize.matcher(text);
        if (matcher2.find()) {
            return matcher2.group(1);
        }
        return null;
    }
}
