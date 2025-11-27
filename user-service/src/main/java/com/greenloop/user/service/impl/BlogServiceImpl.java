package com.greenloop.user.service.impl;

import com.greenloop.user.constant.RoleConstants;
import com.greenloop.user.dto.request.BlogCreateRequest;
import com.greenloop.user.dto.request.BlogUpdateRequest;
import com.greenloop.user.dto.response.BlogResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import com.greenloop.user.entity.Blog;
import com.greenloop.user.entity.Role;
import com.greenloop.user.entity.User;
import com.greenloop.user.enums.BlogStatus;
import com.greenloop.user.exception.*;
import com.greenloop.user.repository.BlogRepository;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.service.BlogService;
import com.greenloop.user.service.CloudinaryService;
import com.greenloop.user.util.PageResponseUtil;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class BlogServiceImpl implements BlogService {

    private final BlogRepository blogRepository;
    private final UserRepository userRepository;
    private final CloudinaryService cloudinaryService;

    private static final String BLOG_THUMBNAIL_FOLDER = "GreenLoop/Blogs/Thumbnails";

    @Override
    @Transactional
    public BlogResponse createBlog(BlogCreateRequest request, MultipartFile thumbnail) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = Long.parseLong(auth.getPrincipal().toString());

        User currentUser = userRepository.findById(currentUserId)
                .orElseThrow(() -> new UserNotFoundException(currentUserId));

        boolean isAuthorized = currentUser.getRoles().stream()
                .anyMatch(role -> role.getName().equals(RoleConstants.ADMIN)
                        || role.getName().equals(RoleConstants.MANAGER)
                        || role.getName().equals(RoleConstants.STAFF));

        if (!isAuthorized) {
            throw new UnauthorizedBlogAccessException("Chỉ Admin, Manager hoặc Staff mới có thể tạo blog");
        }

        Blog blog = Blog.builder()
                .title(request.getTitle())
                .content(request.getContent())
                .status(BlogStatus.DRAFT)
                .author(currentUser)
                .build();

        if (thumbnail != null && !thumbnail.isEmpty()) {
            handleThumbnailUpload(blog, thumbnail);
        }

        Blog savedBlog = blogRepository.save(blog);
        return mapBlogToResponse(savedBlog);
    }

    @Override
    @Transactional
    public BlogResponse updateBlog(Long id, BlogUpdateRequest request, MultipartFile thumbnail) {
        Blog blog = blogRepository.findById(id)
                .orElseThrow(() -> new BlogNotFoundException(id));

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = Long.parseLong(auth.getPrincipal().toString());

        User currentUser = userRepository.findById(currentUserId)
                .orElseThrow(() -> new UserNotFoundException(currentUserId));

        if (!canModifyBlog(blog, currentUser)) {
            throw new UnauthorizedBlogAccessException();
        }

        if (request.getTitle() != null && !request.getTitle().isEmpty()) {
            blog.setTitle(request.getTitle());
        }
        if (request.getContent() != null && !request.getContent().isEmpty()) {
            blog.setContent(request.getContent());
        }

        if (thumbnail != null && !thumbnail.isEmpty()) {
            handleThumbnailUpload(blog, thumbnail);
        }

        blog.setUpdatedBy(currentUserId);
        Blog updatedBlog = blogRepository.save(blog);
        return mapBlogToResponse(updatedBlog);
    }

    @Override
    @Transactional
    public void deleteBlog(Long id) {
        Blog blog = blogRepository.findById(id)
                .orElseThrow(() -> new BlogNotFoundException(id));

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = Long.parseLong(auth.getPrincipal().toString());

        User currentUser = userRepository.findById(currentUserId)
                .orElseThrow(() -> new UserNotFoundException(currentUserId));

        if (!canModifyBlog(blog, currentUser)) {
            throw new UnauthorizedBlogAccessException();
        }

        if (blog.getMediaKey() != null) {
            try {
                cloudinaryService.deleteImage(blog.getMediaKey());
            } catch (Exception e) {
                // Silent fail - không block delete operation
            }
        }

        blogRepository.delete(blog);
    }

    @Override
    @Transactional
    public BlogResponse publishBlog(Long id) {
        Blog blog = blogRepository.findById(id)
                .orElseThrow(() -> new BlogNotFoundException(id));

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = Long.parseLong(auth.getPrincipal().toString());

        User currentUser = userRepository.findById(currentUserId)
                .orElseThrow(() -> new UserNotFoundException(currentUserId));

        if (!canModifyBlog(blog, currentUser)) {
            throw new UnauthorizedBlogAccessException();
        }

        if (blog.getStatus() == BlogStatus.PUBLISHED) {
            throw new InvalidBlogOperationException("Blog đã được công khai rồi");
        }

        blog.setStatus(BlogStatus.PUBLISHED);
        blog.setPublishedAt(LocalDateTime.now());
        blog.setUpdatedBy(currentUserId);

        Blog publishedBlog = blogRepository.save(blog);
        return mapBlogToResponse(publishedBlog);
    }

    @Override
    @Transactional
    public BlogResponse hideBlog(Long id) {
        Blog blog = blogRepository.findById(id)
                .orElseThrow(() -> new BlogNotFoundException(id));

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = Long.parseLong(auth.getPrincipal().toString());

        User currentUser = userRepository.findById(currentUserId)
                .orElseThrow(() -> new UserNotFoundException(currentUserId));

        if (!canModifyBlog(blog, currentUser)) {
            throw new UnauthorizedBlogAccessException();
        }

        if (blog.getStatus() == BlogStatus.HIDDEN) {
            throw new InvalidBlogOperationException("Blog đã bị ẩn rồi");
        }

        blog.setStatus(BlogStatus.HIDDEN);
        blog.setUpdatedBy(currentUserId);

        Blog hiddenBlog = blogRepository.save(blog);
        return mapBlogToResponse(hiddenBlog);
    }

    @Override
    @Transactional(readOnly = true)
    public BlogResponse getBlogDetail(Long id) {
        Blog blog = blogRepository.findById(id)
                .orElseThrow(() -> new BlogNotFoundException(id));

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            if (blog.getStatus() != BlogStatus.PUBLISHED) {
                throw new BlogNotFoundException("Blog không tồn tại hoặc chưa được công khai");
            }
            return mapBlogToResponse(blog);
        }

        Long currentUserId = Long.parseLong(auth.getPrincipal().toString());
        User currentUser = userRepository.findById(currentUserId)
                .orElseThrow(() -> new UserNotFoundException(currentUserId));

        boolean isStaffOrManagerOrAdmin = currentUser.getRoles().stream()
                .anyMatch(role -> role.getName().equals(RoleConstants.ADMIN)
                        || role.getName().equals(RoleConstants.MANAGER)
                        || role.getName().equals(RoleConstants.STAFF));

        if (isStaffOrManagerOrAdmin) {
            return mapBlogToResponse(blog);
        }

        if (blog.getStatus() != BlogStatus.PUBLISHED) {
            throw new BlogNotFoundException("Blog không tồn tại hoặc chưa được công khai");
        }

        return mapBlogToResponse(blog);
    }

    @Override
    @Transactional(readOnly = true)
    public PageResponseDTO<BlogResponse> getPublishedBlogs(String search, Pageable pageable) {
        Specification<Blog> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            predicates.add(cb.equal(root.get("status"), BlogStatus.PUBLISHED));

            if (search != null && !search.isEmpty()) {
                String searchPattern = "%" + search.toLowerCase() + "%";
                predicates.add(
                        cb.or(
                                cb.like(cb.lower(root.get("title")), searchPattern),
                                cb.like(cb.lower(root.get("content")), searchPattern)
                        )
                );
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        Page<Blog> page = blogRepository.findAll(spec, pageable);
        Page<BlogResponse> blogPage = page.map(this::mapBlogToResponse);

        return PageResponseUtil.toPageResponse(blogPage);
    }

    @Override
    @Transactional(readOnly = true)
    public PageResponseDTO<BlogResponse> getAllBlogs(String search, String status, Pageable pageable) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = Long.parseLong(auth.getPrincipal().toString());

        User currentUser = userRepository.findById(currentUserId)
                .orElseThrow(() -> new UserNotFoundException(currentUserId));

        boolean isAuthorized = currentUser.getRoles().stream()
                .anyMatch(role -> role.getName().equals(RoleConstants.ADMIN)
                        || role.getName().equals(RoleConstants.MANAGER)
                        || role.getName().equals(RoleConstants.STAFF));

        if (!isAuthorized) {
            throw new UnauthorizedBlogAccessException("Bạn không có quyền xem tất cả blog");
        }

        Specification<Blog> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (search != null && !search.isEmpty()) {
                String searchPattern = "%" + search.toLowerCase() + "%";
                predicates.add(
                        cb.or(
                                cb.like(cb.lower(root.get("title")), searchPattern),
                                cb.like(cb.lower(root.get("content")), searchPattern)
                        )
                );
            }

            if (status != null && !status.isEmpty()) {
                try {
                    BlogStatus blogStatus = BlogStatus.valueOf(status.toUpperCase());
                    predicates.add(cb.equal(root.get("status"), blogStatus));
                } catch (IllegalArgumentException e) {
                    // Invalid status - ignore filter
                }
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        Page<Blog> page = blogRepository.findAll(spec, pageable);
        Page<BlogResponse> blogPage = page.map(this::mapBlogToResponse);

        return PageResponseUtil.toPageResponse(blogPage);
    }

    @Override
    @Transactional(readOnly = true)
    public PageResponseDTO<BlogResponse> getMyBlogs(String search, Pageable pageable) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = Long.parseLong(auth.getPrincipal().toString());

        Specification<Blog> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            predicates.add(cb.equal(root.get("author").get("id"), currentUserId));

            if (search != null && !search.isEmpty()) {
                String searchPattern = "%" + search.toLowerCase() + "%";
                predicates.add(
                        cb.or(
                                cb.like(cb.lower(root.get("title")), searchPattern),
                                cb.like(cb.lower(root.get("content")), searchPattern)
                        )
                );
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        Page<Blog> page = blogRepository.findAll(spec, pageable);
        Page<BlogResponse> blogPage = page.map(this::mapBlogToResponse);

        return PageResponseUtil.toPageResponse(blogPage);
    }

    private void handleThumbnailUpload(Blog blog, MultipartFile file) {
        try {
            if (blog.getMediaKey() != null) {
                cloudinaryService.deleteImage(blog.getMediaKey());
            }

            Map<String, String> uploadResult =
                    cloudinaryService.uploadImage(file.getBytes(), BLOG_THUMBNAIL_FOLDER);

            blog.setThumbnailUrl(cloudinaryService.getImageUrl(uploadResult.get("asset_id")));
            blog.setMediaKey(uploadResult.get("public_id"));

        } catch (Exception e) {
            throw new RuntimeException("Không thể tải lên ảnh thumbnail", e);
        }
    }

    private boolean canModifyBlog(Blog blog, User currentUser) {
        List<String> userRoles = currentUser.getRoles().stream().map(Role::getName).toList();

        if (userRoles.contains(RoleConstants.ADMIN)) {
            return true;
        }

        if (userRoles.contains(RoleConstants.MANAGER)) {
            return true;
        }

        return blog.getAuthor().getId().equals(currentUser.getId());
    }

    private BlogResponse mapBlogToResponse(Blog blog) {
        return BlogResponse.builder()
                .id(blog.getId())
                .title(blog.getTitle())
                .content(blog.getContent())
                .thumbnailUrl(blog.getThumbnailUrl())
                .status(blog.getStatus())
                .publishedAt(blog.getPublishedAt())
                .createdAt(blog.getCreatedAt())
                .updatedAt(blog.getUpdatedAt())
                .authorId(blog.getAuthor().getId())
                .authorName(blog.getAuthor().getFullName())
                .authorEmail(blog.getAuthor().getEmail())
                .authorAvatarUrl(blog.getAuthor().getAvatarUrl())
                .build();
    }
}
