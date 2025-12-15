package com.greenloop.user.service;

import com.greenloop.user.dto.request.BlogCreateRequest;
import com.greenloop.user.dto.request.BlogUpdateRequest;
import com.greenloop.user.dto.response.BlogResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

public interface BlogService {
  BlogResponse createBlog(BlogCreateRequest request, MultipartFile thumbnail);

  BlogResponse updateBlog(Long id, BlogUpdateRequest request, MultipartFile thumbnail);

  void deleteBlog(Long id);

  BlogResponse publishBlog(Long id);

  BlogResponse hideBlog(Long id);

  BlogResponse getBlogDetail(Long id);

  PageResponseDTO<BlogResponse> getPublishedBlogs(String search, Pageable pageable);

  PageResponseDTO<BlogResponse> getAllBlogs(String search, String status, Pageable pageable);

  PageResponseDTO<BlogResponse> getMyBlogs(String search, Pageable pageable);
}
