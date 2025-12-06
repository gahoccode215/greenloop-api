package com.greenloop.event.config;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitMQConfig {
  @Value("${rabbitmq.exchangeName}")
  private String exchange;

  @Value("${rabbitmq.eco-donation-queue}")
  private String ecoDonationQueue;

  @Value("${rabbitmq.eco-donation-routing-key}")
  private String ecoDonationRoutingKey;

  @Value("${rabbitmq.notification-routing-key}")
  private String notificationRoutingKey;

  @Bean
  public TopicExchange exchange() {
    return new TopicExchange(exchange);
  }

  @Bean
  public Queue ecoDonationQueue() {
    return new Queue(ecoDonationQueue);
  }

  @Bean
  public Binding ecoDonationBinding() {
    return BindingBuilder.bind(ecoDonationQueue()).to(exchange()).with(ecoDonationRoutingKey);
  }



  @Bean
  public MessageConverter converter() {
    return new Jackson2JsonMessageConverter();
  }

  @Bean
  public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
    RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
    rabbitTemplate.setMessageConverter(converter());
    return rabbitTemplate;
  }
}
