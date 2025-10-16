package com.greenloop.user.service;

import com.greenloop.user.dto.response.FileUploadResponse;
import com.greenloop.user.enums.FileFolder;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface FileStorageService {
    FileUploadResponse uploadFile(MultipartFile file, FileFolder folder);
    void deleteFile(String publicId);
    boolean isValidFile(MultipartFile file, List<String> allowedTypes, long maxSize);
}
