package com.greenloop.user.controller;

import com.greenloop.user.dto.request.BlogCreateRequest;
import com.greenloop.user.dto.request.BlogUpdateRequest;
import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.BlogResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import com.greenloop.user.service.BlogService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/blogs")
@RequiredArgsConstructor
@Tag(name = "Blog Management", description = "APIs for managing blogs")
public class BlogController {

  private final BlogService blogService;

  @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  public ResponseEntity<ApiResponseDTO<BlogResponse>> createBlog(
      @Valid @RequestPart("blog") BlogCreateRequest request,
      @RequestPart(value = "thumbnail", required = false) MultipartFile thumbnail) {

    BlogResponse response = blogService.createBlog(request, thumbnail);
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(ApiResponseDTO.success("Tạo blog thành công", response, HttpStatus.CREATED));
  }

  @PutMapping(value = "/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  public ResponseEntity<ApiResponseDTO<BlogResponse>> updateBlog(
      @PathVariable Long id,
      @Valid @RequestPart("blog") BlogUpdateRequest request,
      @RequestPart(value = "thumbnail", required = false) MultipartFile thumbnail) {

    BlogResponse response = blogService.updateBlog(id, request, thumbnail);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Cập nhật blog thành công", response, HttpStatus.OK));
  }

  @DeleteMapping("/{id}")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  public ResponseEntity<ApiResponseDTO<Void>> deleteBlog(@PathVariable Long id) {
    blogService.deleteBlog(id);
    return ResponseEntity.ok(ApiResponseDTO.success("Xóa blog thành công", null, HttpStatus.OK));
  }

  @PatchMapping("/{id}/publish")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  public ResponseEntity<ApiResponseDTO<BlogResponse>> publishBlog(@PathVariable Long id) {
    BlogResponse response = blogService.publishBlog(id);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Công khai blog thành công", response, HttpStatus.OK));
  }

  @PatchMapping("/{id}/hide")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  public ResponseEntity<ApiResponseDTO<BlogResponse>> hideBlog(@PathVariable Long id) {
    BlogResponse response = blogService.hideBlog(id);
    return ResponseEntity.ok(ApiResponseDTO.success("Ẩn blog thành công", response, HttpStatus.OK));
  }

  @GetMapping("/{id}")
  public ResponseEntity<ApiResponseDTO<BlogResponse>> getBlogDetail(@PathVariable Long id) {
    BlogResponse response = blogService.getBlogDetail(id);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy thông tin blog thành công", response, HttpStatus.OK));
  }

  @GetMapping("/published")
  public ResponseEntity<ApiResponseDTO<PageResponseDTO<BlogResponse>>> getPublishedBlogs(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size,
      @RequestParam(required = false) String search,
      @RequestParam(defaultValue = "publishedAt") String sortBy,
      @RequestParam(defaultValue = "DESC") String sortDir) {
    Pageable pageable =
        PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));
    PageResponseDTO<BlogResponse> response = blogService.getPublishedBlogs(search, pageable);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy danh sách blog thành công", response, HttpStatus.OK));
  }

  @GetMapping
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  public ResponseEntity<ApiResponseDTO<PageResponseDTO<BlogResponse>>> getAllBlogs(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size,
      @RequestParam(required = false) String search,
      @RequestParam(required = false) String status,
      @RequestParam(defaultValue = "createdAt") String sortBy,
      @RequestParam(defaultValue = "DESC") String sortDir) {

    Pageable pageable =
        PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));
    PageResponseDTO<BlogResponse> response = blogService.getAllBlogs(search, status, pageable);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy danh sách blog thành công", response, HttpStatus.OK));
  }

  @GetMapping("/my-blogs")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
  public ResponseEntity<ApiResponseDTO<PageResponseDTO<BlogResponse>>> getMyBlogs(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size,
      @RequestParam(required = false) String search,
      @RequestParam(defaultValue = "createdAt") String sortBy,
      @RequestParam(defaultValue = "DESC") String sortDir) {

    Pageable pageable =
        PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));
    PageResponseDTO<BlogResponse> response = blogService.getMyBlogs(search, pageable);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy danh sách blog của tôi thành công", response, HttpStatus.OK));
  }
}
