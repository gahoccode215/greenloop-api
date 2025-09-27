package com.greenloop.notification.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "rabbitmq")
@Data
@Component
public class RabbitMQProperties {
    private Queue queue = new Queue();
    private Exchange exchange = new Exchange();
    private Routing routing = new Routing();

    @Data
    public static class Queue {
        private String name;
    }

    @Data
    public static class Exchange {
        private String name;
    }

    @Data
    public static class Routing {
        private String key;
    }
}
