package com.greenloop.order.config;

import com.greenloop.order.command.interceptor.OrderCommandInterceptor;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.axonframework.config.EventProcessingConfigurer;
import org.axonframework.eventhandling.PropagatingErrorHandler;
import org.axonframework.eventhandling.TrackingEventProcessorConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
public class AxonConfig {

    @Autowired
    public void registerOrderCommandInterceptor(ApplicationContext context,
                                                CommandGateway commandGateway) {
        commandGateway.registerDispatchInterceptor(
                context.getBean(OrderCommandInterceptor.class)
        );
    }

    @Autowired
    public void configureErrorHandler(EventProcessingConfigurer config) {
        config.registerListenerInvocationErrorHandler(
                "order-group",
                conf -> PropagatingErrorHandler.instance()
        );
    }

    @Autowired
    public void configureEventProcessing(EventProcessingConfigurer configurer) {
        configurer.registerTrackingEventProcessorConfiguration(
                config -> TrackingEventProcessorConfiguration
                        .forSingleThreadedProcessing()
                        .andBatchSize(100)
                        .andEventAvailabilityTimeout(20000, TimeUnit.MILLISECONDS)
        );
    }
}
