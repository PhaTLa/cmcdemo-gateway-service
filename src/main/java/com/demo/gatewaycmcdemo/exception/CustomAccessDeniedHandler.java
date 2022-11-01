package com.demo.gatewaycmcdemo.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
//import org.springframework.security.access.AccessDeniedException;
//import org.springframework.security.web.access.AccessDeniedHandler;
//import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

//@Slf4j
//@Component
public class CustomAccessDeniedHandler
//        implements ServerAccessDeniedHandler
{

//    @Override
//    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
//        log.info("HttpServletRequest ================> {} \n {}",request.getMethod(),request.getQueryString());
//        Map<String,Object> body = new LinkedHashMap<>();
//        ObjectMapper mapper = new ObjectMapper();
//        body.put("Timestamp", LocalDateTime.now().toString());
//        body.put("Status", HttpServletResponse.SC_FORBIDDEN);
//        body.put("Errors", accessDeniedException.getMessage());
//        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
//        OutputStream out = response.getOutputStream();
//        mapper.writerWithDefaultPrettyPrinter().writeValue(out,body);
//        mapper.writeValue(out, body);
//        log.info("Response CustomAccessDeniedHandler ================> {}",out.toString());
//        out.flush();
//    }

//    @SneakyThrows
//    @Override
//    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
//        log.info("ServerWebExchange ================> {} \n {}",exchange.getRequest().getMethodValue(),exchange.getRequest().getQueryParams());
//        Map<String,Object> body = new LinkedHashMap<>();
//        ObjectMapper mapper = new ObjectMapper();
//        body.put("Timestamp", LocalDateTime.now().toString());
//        body.put("Status", HttpStatus.FORBIDDEN.value());
//        body.put("Errors", denied.getMessage());
//        String responseBody = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(body);
//        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
//        exchange.getResponse().getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
//        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(responseBody.getBytes(StandardCharsets.UTF_8));
//        log.info("Response CustomAccessDeniedHandler ================> {}",responseBody);
//        return exchange.getResponse().writeWith(Mono.just(buffer));
//    }
}
