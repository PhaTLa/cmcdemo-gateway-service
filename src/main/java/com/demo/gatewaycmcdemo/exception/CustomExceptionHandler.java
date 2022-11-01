package com.demo.gatewaycmcdemo.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

public class CustomExceptionHandler<E extends Exception> {

    public void exceptionHandler(E e, HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("error", e.getMessage());
        response.setStatus(FORBIDDEN.value());
        Map<String, String> error = new HashMap<>();
        error.put("error_message", e.getMessage());
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }

    public Mono<Void> reactiveExceptionHandler(E e, ServerWebExchange exchange) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().add("error", e.getMessage());
        response.setStatusCode(FORBIDDEN);
        Map<String, String> error = new HashMap<>();
        error.put("error_message", e.getMessage());
        response.getHeaders().setContentType(APPLICATION_JSON);
        String responseBody = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(error);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(responseBody.getBytes(StandardCharsets.UTF_8));
        return response.writeAndFlushWith(Mono.just(Mono.just(buffer)));
    }
}
