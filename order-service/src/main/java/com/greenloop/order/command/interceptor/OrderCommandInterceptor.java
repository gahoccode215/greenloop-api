package com.greenloop.order.command.interceptor;

import com.greenloop.order.command.CreateOrderCommand;
import com.greenloop.order.command.UpdateOrderStatusCommand;
import com.greenloop.order.exception.OrderAlreadyExistsException;
import com.greenloop.order.exception.ResourceNotFoundException;
import com.greenloop.order.repository.OrderRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.commandhandling.CommandMessage;
import org.axonframework.messaging.MessageDispatchInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.function.BiFunction;

@Component
@RequiredArgsConstructor
public class OrderCommandInterceptor implements MessageDispatchInterceptor<CommandMessage<?>> {

    private final OrderRepository orderRepository;

    @Nonnull
    @Override
    public BiFunction<Integer, CommandMessage<?>, CommandMessage<?>> handle(
            @Nonnull List<? extends CommandMessage<?>> messages) {
        return (index, command) -> {

            if (CreateOrderCommand.class.equals(command.getPayloadType())) {
                CreateOrderCommand createOrderCommand = (CreateOrderCommand) command.getPayload();

                // Kiểm tra orderCode có trùng không
                orderRepository.findByOrderCode(createOrderCommand.getOrderCode())
                        .ifPresent(order -> {
                            throw new OrderAlreadyExistsException(
                                    "Order with code " + createOrderCommand.getOrderCode() + " already exists");
                        });

            } else if (UpdateOrderStatusCommand.class.equals(command.getPayloadType())) {
                UpdateOrderStatusCommand updateCommand = (UpdateOrderStatusCommand) command.getPayload();

                // Order phải tồn tại
                orderRepository.findById(updateCommand.getOrderId())
                        .orElseThrow(() -> new ResourceNotFoundException(
                                "Order", "orderId", updateCommand.getOrderId()));
            }

            return command;
        };
    }
}

