package com.greenloop.order.config;

import com.greenloop.order.command.interceptor.OrderCommandInterceptor;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.axonframework.config.EventProcessingConfigurer;
import org.axonframework.eventhandling.PropagatingErrorHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AxonConfig {

    @Autowired
    public void registerOrderCommandInterceptor(ApplicationContext context,
                                                CommandGateway commandGateway) {
        commandGateway.registerDispatchInterceptor(
                context.getBean(OrderCommandInterceptor.class));
    }

    @Autowired
    public void configure(EventProcessingConfigurer config) {
        config.registerListenerInvocationErrorHandler("order-group",
                conf -> PropagatingErrorHandler.instance());
    }
}
