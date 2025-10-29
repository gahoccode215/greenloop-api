package com.greenloop.event.service;

import java.util.Map;

public interface CloudinaryService {
  Map<String, String> uploadImage(byte[] image, String folder);

  boolean deleteImage(String mediaKey);

  String getImageUrl(String assetKey);
}
