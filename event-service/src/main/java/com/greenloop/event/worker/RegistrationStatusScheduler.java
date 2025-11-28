package com.greenloop.event.worker;


import com.greenloop.event.entity.EventRegistration;
import com.greenloop.event.enums.EventStatus;
import com.greenloop.event.enums.RegistrationStatus;
import com.greenloop.event.repository.EventRegistrationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class RegistrationStatusScheduler {

    private final EventRegistrationRepository eventRegistrationRepository;

    @Scheduled(cron = "0 0 * * * *")
    @Transactional
    public void updateNoShowRegistrations() {
        log.info("Starting scheduled registration status update for NO_SHOW");

        try {
            List<EventRegistration> bookedRegistrations =
                    eventRegistrationRepository.findBookedRegistrationsWithClosedEvents(
                            RegistrationStatus.BOOKED,
                            EventStatus.CLOSED,
                            true
                    );

            if (bookedRegistrations.isEmpty()) {
                log.debug("No registrations to update");
                return;
            }

            int updatedCount = 0;
            for (EventRegistration registration : bookedRegistrations) {
                registration.setStatus(RegistrationStatus.NO_SHOW);
                registration.setNote(buildNoShowNote(registration.getNote()));
                updatedCount++;

                log.debug("Registration ID {} changed to NO_SHOW for event: {}",
                        registration.getId(),
                        registration.getEvent().getCode());
            }

            log.info("Registration status update completed - Updated {} registrations to NO_SHOW",
                    updatedCount);

        } catch (Exception e) {
            log.error("Error updating registration statuses: {}", e.getMessage(), e);
        }
    }


    private String buildNoShowNote(String existingNote) {
        String autoNote = "[Auto] Changed to NO_SHOW - Event has ended";

        if (existingNote == null || existingNote.trim().isEmpty()) {
            return autoNote;
        }

        if (existingNote.contains("[Auto] Changed to NO_SHOW")) {
            return existingNote;
        }

        return existingNote + " | " + autoNote;
    }
}
