package com.greenloop.event.repository;

import com.greenloop.event.entity.Event;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface EventRepository
    extends JpaRepository<Event, Long>, JpaSpecificationExecutor<Event> {}
