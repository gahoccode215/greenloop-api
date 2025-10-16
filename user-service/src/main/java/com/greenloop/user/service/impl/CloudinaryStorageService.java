package com.greenloop.user.service.impl;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import com.greenloop.user.dto.response.FileUploadResponse;
import com.greenloop.user.enums.FileFolder;
import com.greenloop.user.exception.FileUploadException;
import com.greenloop.user.exception.InvalidFileException;
import com.greenloop.user.service.FileStorageService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class CloudinaryStorageService implements FileStorageService {

    private final Cloudinary cloudinary;

    private static final List<String> ALLOWED_IMAGE_TYPES = Arrays.asList(
            "image/jpeg", "image/png", "image/jpg", "image/webp"
    );

    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

    @Override
    public FileUploadResponse uploadFile(MultipartFile file, FileFolder folder) {
        try {
            isValidFile(file, ALLOWED_IMAGE_TYPES, MAX_FILE_SIZE);

            String originalFilename = file.getOriginalFilename();
            String publicId = UUID.randomUUID().toString();

            Map<String, Object> uploadParams = new HashMap<>();
            uploadParams.put("folder", folder.getPath());
            uploadParams.put("public_id", publicId);
            uploadParams.put("resource_type", "auto");

            Map uploadResult = cloudinary.uploader().upload(file.getBytes(), uploadParams);

            return FileUploadResponse.builder()
                    .fileName(originalFilename)
                    .fileUrl((String) uploadResult.get("secure_url"))
                    .publicId(folder.getPath() + "/" + publicId)
                    .fileSize(file.getSize())
                    .fileType(file.getContentType())
                    .uploadedAt(LocalDateTime.now())
                    .build();

        } catch (IOException e) {
            log.error("Failed to upload file: {}", e.getMessage());
            throw new FileUploadException("Không thể upload file: " + e.getMessage());
        }
    }

    @Override
    public void deleteFile(String publicId) {
        try {
            cloudinary.uploader().destroy(publicId, ObjectUtils.emptyMap());
            log.info("Deleted file with publicId: {}", publicId);
        } catch (IOException e) {
            log.error("Failed to delete file: {}", e.getMessage());
            throw new FileUploadException("Không thể xóa file: " + e.getMessage());
        }
    }

    @Override
    public boolean isValidFile(MultipartFile file, List<String> allowedTypes, long maxSize) {
        if (file == null || file.isEmpty()) {
            throw new InvalidFileException("File không được để trống");
        }

        if (file.getSize() > maxSize) {
            long maxSizeMB = maxSize / 1024 / 1024;
            throw new InvalidFileException("File vượt quá kích thước cho phép: " + maxSizeMB + "MB");
        }

        String contentType = file.getContentType();
        if (contentType == null || !allowedTypes.contains(contentType)) {
            throw new InvalidFileException("Loại file không được hỗ trợ. Chỉ chấp nhận: " + String.join(", ", allowedTypes));
        }

        return true;
    }
}
