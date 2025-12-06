package com.greenloop.user.config;

import com.greenloop.user.constant.RoleConstants;
import com.greenloop.user.entity.Role;
import com.greenloop.user.entity.User;
import com.greenloop.user.enums.Gender;
import com.greenloop.user.repository.RoleRepository;
import com.greenloop.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;

@Service
@RequiredArgsConstructor
public class DataInit implements CommandLineRunner {
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        initializeRoles();
        initializeUsers();
    }

    private void initializeRoles() {
        createRoleIfNotExists(RoleConstants.CUSTOMER, RoleConstants.CUSTOMER_DESC);
        createRoleIfNotExists(RoleConstants.ADMIN, RoleConstants.ADMIN_DESC);
        createRoleIfNotExists(RoleConstants.MANAGER, RoleConstants.MANAGER_DESC);
        createRoleIfNotExists(RoleConstants.STAFF, RoleConstants.STAFF_DESC);
    }

    private void createRoleIfNotExists(String roleName, String description) {
        if (!roleRepository.existsByName(roleName)) {
            Role role = Role.builder()
                    .name(roleName)
                    .description(description)
                    .build();
            roleRepository.save(role);
        }
    }

    private void initializeUsers() {
        Role customerRole = roleRepository.findByName(RoleConstants.CUSTOMER).orElse(null);
        Role adminRole = roleRepository.findByName(RoleConstants.ADMIN).orElse(null);
        Role managerRole = roleRepository.findByName(RoleConstants.MANAGER).orElse(null);
        Role staffRole = roleRepository.findByName(RoleConstants.STAFF).orElse(null);

        createUser(
                "admin@greenloop.com",
                "Admin@123",
                adminRole,
                "Nguyễn Văn Minh",
                "0901234567",
                LocalDate.of(1985, 5, 15),
                Gender.MALE,
                "https://i.pravatar.cc/300?img=12"
        );

        createUser(
                "manager@greenloop.com",
                "Manager@123",
                managerRole,
                "Trần Thị Hương",
                "0902345678",
                LocalDate.of(1988, 8, 20),
                Gender.FEMALE,
                "https://i.pravatar.cc/300?img=47"
        );

        createUser(
                "nguyenvananh@gmail.com",
                "Customer@123",
                customerRole,
                "Nguyễn Văn Anh",
                "0903456789",
                LocalDate.of(1995, 3, 10),
                Gender.MALE,
                "https://i.pravatar.cc/300?img=33"
        );

        createUser(
                "hothicam@gmail.com",
                "Customer@123",
                customerRole,
                "Hồ Thị Cẩm",
                "0904567890",
                LocalDate.of(1998, 7, 25),
                Gender.FEMALE,
                "https://i.pravatar.cc/300?img=26"
        );

        createUser(
                "levandung@gmail.com",
                "Customer@123",
                customerRole,
                "Lê Văn Dũng",
                "0905678901",
                LocalDate.of(1992, 11, 5),
                Gender.MALE,
                "https://i.pravatar.cc/300?img=68"
        );

        createUser(
                "phamthimai@greenloop.com",
                "Staff@123",
                staffRole,
                "Phạm Thị Mai",
                "0906789012",
                LocalDate.of(1996, 1, 12),
                Gender.FEMALE,
                "https://i.pravatar.cc/300?img=32"
        );

        createUser(
                "hoangvannam@greenloop.com",
                "Staff@123",
                staffRole,
                "Hoàng Văn Nam",
                "0907890123",
                LocalDate.of(1997, 4, 18),
                Gender.MALE,
                "https://i.pravatar.cc/300?img=15"
        );

        createUser(
                "dothilan@greenloop.com",
                "Staff@123",
                staffRole,
                "Đỗ Thị Lan",
                "0908901234",
                LocalDate.of(1994, 6, 22),
                Gender.FEMALE,
                "https://i.pravatar.cc/300?img=43"
        );

        createUser(
                "buivanthanh@greenloop.com",
                "Staff@123",
                staffRole,
                "Bùi Văn Thành",
                "0909012345",
                LocalDate.of(1999, 9, 8),
                Gender.MALE,
                "https://i.pravatar.cc/300?img=51"
        );

        createUser(
                "dangthihuyen@greenloop.com",
                "Staff@123",
                staffRole,
                "Đặng Thị Huyền",
                "0910123456",
                LocalDate.of(1993, 2, 14),
                Gender.FEMALE,
                "https://i.pravatar.cc/300?img=38"
        );

        createUser(
                "ngovanhung@greenloop.com",
                "Staff@123",
                staffRole,
                "Ngô Văn Hùng",
                "0911234567",
                LocalDate.of(2000, 5, 30),
                Gender.MALE,
                "https://i.pravatar.cc/300?img=59"
        );

        createUser(
                "lythilinh@greenloop.com",
                "Staff@123",
                staffRole,
                "Lý Thị Linh",
                "0912345678",
                LocalDate.of(1991, 8, 19),
                Gender.FEMALE,
                "https://i.pravatar.cc/300?img=29"
        );

        createUser(
                "vuongvanquang@greenloop.com",
                "Staff@123",
                staffRole,
                "Vương Văn Quang",
                "0913456789",
                LocalDate.of(1998, 12, 3),
                Gender.MALE,
                "https://i.pravatar.cc/300?img=13"
        );

        createUser(
                "dinhthithu@greenloop.com",
                "Staff@123",
                staffRole,
                "Đinh Thị Thu",
                "0914567890",
                LocalDate.of(1995, 10, 27),
                Gender.FEMALE,
                "https://i.pravatar.cc/300?img=45"
        );

        createUser(
                "duongvanphuc@greenloop.com",
                "Staff@123",
                staffRole,
                "Dương Văn Phúc",
                "0915678901",
                LocalDate.of(1996, 3, 16),
                Gender.MALE,
                "https://i.pravatar.cc/300?img=56"
        );

        createUser(
                "phanthituyet@greenloop.com",
                "Staff@123",
                staffRole,
                "Phan Thị Tuyết",
                "0916789012",
                LocalDate.of(1997, 7, 11),
                Gender.FEMALE,
                "https://i.pravatar.cc/300?img=24"
        );

        createUser(
                "maivantuan@greenloop.com",
                "Staff@123",
                staffRole,
                "Mai Văn Tuấn",
                "0917890123",
                LocalDate.of(1994, 1, 9),
                Gender.MALE,
                "https://i.pravatar.cc/300?img=67"
        );

        createUser(
                "tranthinhung@greenloop.com",
                "Staff@123",
                staffRole,
                "Trần Thị Nhung",
                "0918901234",
                LocalDate.of(1999, 4, 23),
                Gender.FEMALE,
                "https://i.pravatar.cc/300?img=31"
        );

        createUser(
                "nguyenvanhieu@greenloop.com",
                "Staff@123",
                staffRole,
                "Nguyễn Văn Hiếu",
                "0919012345",
                LocalDate.of(1992, 11, 28),
                Gender.MALE,
                "https://i.pravatar.cc/300?img=60"
        );

        createUser(
                "lethihoa@greenloop.com",
                "Staff@123",
                staffRole,
                "Lê Thị Hoa",
                "0920123456",
                LocalDate.of(1998, 6, 7),
                Gender.FEMALE,
                "https://i.pravatar.cc/300?img=48"
        );
    }

    private void createUser(
            String email,
            String password,
            Role role,
            String fullName,
            String phone,
            LocalDate dateOfBirth,
            Gender gender,
            String avatarUrl) {

        if (!userRepository.existsByEmail(email)) {
            User user = User.builder()
                    .email(email)
                    .password(passwordEncoder.encode(password))
                    .fullName(fullName)
                    .phone(phone)
                    .dateOfBirth(dateOfBirth)
                    .gender(gender)
                    .avatarUrl(avatarUrl)
                    .roles(List.of(role))
                    .isEmailVerified(true)
                    .isActive(true)
                    .build();

            userRepository.save(user);
        }
    }
}
