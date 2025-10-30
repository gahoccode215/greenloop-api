CREATE TABLE `event_media`(
                              `id` BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                              `event_id` BIGINT NOT NULL,
                              `media_key` VARCHAR(255) NOT NULL,
                              `image_url` VARCHAR(255) NOT NULL,
                              `is_active` BOOLEAN NOT NULL DEFAULT '1',
                              `version` INT NOT NULL DEFAULT '1',
                              `created_at` DATETIME NOT NULL DEFAULT 'DEFAULT NOW ( )',
                              `updated_at` DATETIME NOT NULL DEFAULT 'DEFAULT NOW ( )',
                              `updated_by` BIGINT NULL,
                              `deleted_by` BIGINT NULL
);
CREATE TABLE `event_reports`(
                                `id` BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                                `event_id` BIGINT NOT NULL,
                                `donations_count` INT NOT NULL,
                                `sales_count` INT NOT NULL,
                                `revenue` DECIMAL(8, 2) NOT NULL,
                                `note` TEXT NOT NULL,
                                `is_active` BOOLEAN NOT NULL DEFAULT '1',
                                `version` INT NOT NULL DEFAULT '1',
                                `created_at` DATETIME NOT NULL DEFAULT 'DEFAULT NOW ( )',
                                `updated_at` DATETIME NOT NULL DEFAULT 'DEFAULT NOW ( )',
                                `updated_by` BIGINT NULL,
                                `deleted_by` BIGINT NULL
);
ALTER TABLE
    `event_reports` ADD UNIQUE `event_reports_donations_count_unique`(`donations_count`);
CREATE TABLE `event_staff_assignments`(
                                          `id` BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                                          `staff_id` BIGINT NOT NULL,
                                          `event_id` BIGINT NOT NULL,
                                          `shift_time` DATETIME NOT NULL,
                                          `is_active` BOOLEAN NOT NULL DEFAULT '1',
                                          `version` INT NOT NULL DEFAULT '1',
                                          `created_at` DATETIME NOT NULL DEFAULT 'DEFAULT NOW ( )',
                                          `updated_at` DATETIME NOT NULL DEFAULT 'DEFAULT NOW ( )',
                                          `updated_by` BIGINT NULL,
                                          `deleted_by` BIGINT NULL
);
CREATE TABLE `events`(
                         `id` BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                         `code` VARCHAR(15) NOT NULL,
                         `name` VARCHAR(255) NOT NULL,
                         `description` TEXT NOT NULL,
                         `start_time` DATETIME NOT NULL,
                         `end_time` DATETIME NOT NULL,
                         `image_url` VARCHAR(255) NULL,
                         `media_key` varchar(255) NULL,
                         `location_detail` VARCHAR(255) NULL,
                         `latitude` VARCHAR(255) NOT NULL,
                         `longitude` VARCHAR(255) NOT NULL,
                         `status` VARCHAR(15) NOT NULL,
                         `google_place_id` JSON NOT NULL ,
                         `note` TEXT NOT NULL,
                         `is_active` BOOLEAN NOT NULL DEFAULT '1',
                         `version` INT NOT NULL DEFAULT '1',
                         `created_at` DATETIME NOT NULL DEFAULT 'DEFAULT NOW ( )',
                         `updated_at` DATETIME NOT NULL DEFAULT 'DEFAULT NOW ( )',
                         `updated_by` BIGINT NULL,
                         `deleted_by` BIGINT NULL
);
ALTER TABLE
    `events` ADD UNIQUE `events_code_unique`(`code`);
CREATE TABLE `event_registrations`(
                                      `id` BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                                      `user_id` BIGINT NOT NULL,
                                      `event_id` BIGINT NOT NULL,
                                      `qr_code` VARCHAR(255) NOT NULL COMMENT 'Check TYPE',
                                      `checkin_time` DATETIME NOT NULL,
                                      `note` VARCHAR(255) NULL ,
                                      `status` VARCHAR(25) NOT NULL COMMENT 'booked/canceled/attended',
                                      `is_active` BOOLEAN NOT NULL DEFAULT '1',
                                      `version` INT NOT NULL DEFAULT '1',
                                      `created_at` DATETIME NOT NULL DEFAULT 'DEFAULT NOW ( )',
                                      `updated_at` DATETIME NOT NULL DEFAULT 'DEFAULT NOW ( )',
                                      `updated_by` BIGINT NULL,
                                      `deleted_by` BIGINT NULL
);
ALTER TABLE
    `event_staff_assignments` ADD CONSTRAINT `event_staff_assignments_event_id_foreign` FOREIGN KEY(`event_id`) REFERENCES `events`(`id`);

ALTER TABLE
    `event_media` ADD CONSTRAINT `event_media_event_id_foreign` FOREIGN KEY(`event_id`) REFERENCES `events`(`id`);
ALTER TABLE
    `event_reports` ADD CONSTRAINT `event_reports_event_id_foreign` FOREIGN KEY(`event_id`) REFERENCES `events`(`id`);
ALTER TABLE
    `event_registrations` ADD CONSTRAINT `event_registrations_event_id_foreign` FOREIGN KEY(`event_id`) REFERENCES `events`(`id`);