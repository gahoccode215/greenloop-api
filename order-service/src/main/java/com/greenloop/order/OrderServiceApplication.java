package com.greenloop.order;

import com.greenloop.order.command.interceptor.OrderCommandInterceptor;
import org.axonframework.commandhandling.gateway.CommandGateway;
import org.axonframework.config.EventProcessingConfigurer;
import org.axonframework.eventhandling.PropagatingErrorHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

@SpringBootApplication
public class OrderServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(OrderServiceApplication.class, args);
	}

}
