package com.greenloop.product.service.impl;


import com.cloudinary.utils.ObjectUtils;
import com.greenloop.product.config.CloudinaryConfig;
import com.greenloop.product.service.CloudinaryService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class CloudinaryServiceImpl implements CloudinaryService {
    private final CloudinaryConfig cloudinaryConfig;

    @Value("${greenloop.defaultImg}")
    private String defaultImage;

    @Override
    public Map<String, String> uploadImage(byte[] image, String folder) {
        var params = ObjectUtils.asMap("folder", folder, "resource_type", "image");
        try {
            var uploadResult = cloudinaryConfig.cloudinary().uploader().upload(image, params);
            String assetId = uploadResult.get("asset_id").toString();
            String publicId = uploadResult.get("public_id").toString();

            Map<String, String> result = new HashMap<>();
            result.put("asset_id", assetId);
            result.put("public_id", publicId);
            return result;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getImageUrl(String assetKey) {
        try {
            var imageUrl =
                    cloudinaryConfig.cloudinary().api().resourceByAssetID(assetKey, ObjectUtils.emptyMap());
            return imageUrl.get("secure_url").toString();
        } catch (Exception e) {
            return defaultImage;
        }
    }

    @Override
    public boolean deleteImage(String mediaKey) {
        try {
            var result =
                    cloudinaryConfig
                            .cloudinary()
                            .api()
                            .deleteResources(Collections.singleton(mediaKey), ObjectUtils.emptyMap());
            return "deleted".equals(result.get("deleted"));
        } catch (Exception e) {
            throw new RuntimeException("Failed to delete image: " + mediaKey, e);
        }
    }
}
