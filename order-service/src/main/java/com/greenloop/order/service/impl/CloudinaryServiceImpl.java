package com.greenloop.order.service.impl;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import com.greenloop.order.service.CloudinaryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class CloudinaryServiceImpl implements CloudinaryService {

    private final Cloudinary cloudinary;

    @Value("${greenloop.defaultImg}")
    private String defaultImage;

    @Override
    public Map<String, String> uploadImage(byte[] image, String folder) {
        var params = ObjectUtils.asMap(
                "folder", folder,
                "resource_type", "image"
        );

        try {
            var uploadResult = cloudinary.uploader().upload(image, params);

            String assetId = uploadResult.get("asset_id").toString();
            String publicId = uploadResult.get("public_id").toString();

            Map<String, String> result = new HashMap<>();
            result.put("asset_id", assetId);
            result.put("public_id", publicId);

            return result;

        } catch (Exception e) {
            log.error("Failed to upload image to Cloudinary: {}", e.getMessage());
            throw new RuntimeException("Failed to upload image: " + e.getMessage(), e);
        }
    }

    @Override
    public String getImageUrl(String assetKey) {
        try {
            var imageUrl = cloudinary.api().resourceByAssetID(
                    assetKey,
                    ObjectUtils.emptyMap()
            );

            return imageUrl.get("secure_url").toString();

        } catch (Exception e) {
            log.warn("Failed to get image URL for assetKey: {}. Returning default image", assetKey);
            return defaultImage;
        }
    }

    @Override
    public boolean deleteImage(String mediaKey) {
        try {
            var result = cloudinary.api().deleteResources(
                    Collections.singleton(mediaKey),
                    ObjectUtils.emptyMap()
            );

            return "deleted".equals(result.get("deleted"));

        } catch (Exception e) {
            log.error("Failed to delete image from Cloudinary: {}", mediaKey);
            throw new RuntimeException("Failed to delete image: " + mediaKey, e);
        }
    }
}
