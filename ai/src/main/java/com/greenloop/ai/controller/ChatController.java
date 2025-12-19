package com.greenloop.ai.controller;

import org.springframework.ai.chat.memory.ChatMemory;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ChatController {
    @Autowired
    private ChatModel chatModel;

    @Autowired
    private ChatMemory chatMemory;

    @GetMapping("/chat")
    public String getAnswer(@RequestParam String query, @RequestParam String userFullName){
        ChatResponse response = chatModel.call(new Prompt(query));
        return response.getResult().getOutput().getText();
    }
}
