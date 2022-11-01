package com.demo.gatewaycmcdemo.configuration;
//
//import com.fasterxml.jackson.databind.ObjectMapper;
//import lombok.SneakyThrows;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.core.io.buffer.DataBuffer;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.MediaType;
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.web.AuthenticationEntryPoint;
//import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
//import org.springframework.stereotype.Component;
//import org.springframework.web.server.ServerWebExchange;
//import reactor.core.publisher.Mono;
//
//import javax.servlet.ServletException;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import javax.servlet.http.HttpSession;
//import java.io.IOException;
//import java.io.OutputStream;
//import java.nio.charset.StandardCharsets;
//import java.time.LocalDateTime;
//import java.util.LinkedHashMap;
//import java.util.Map;
//
//@Component
public class CustomAuthenticationEntryPoint
//        implements ServerAuthenticationEntryPoint
{
//
//
//    @SneakyThrows
//    @Override
//    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
//        Map<String,Object> body = new LinkedHashMap<>();
//        ObjectMapper mapper = new ObjectMapper();
//        ServerHttpRequest request = exchange.getRequest();
//        if(request.getURI().getPath().equals("/login")
//                || request.getURI().getPath().equals("/user/api/token/refresh")
//                || request.getURI().getPath().equals("/user/api/login")){
//            if (exchange.getRequest().getQueryParams().get("username") == null) {
//                body.put("Timestamp", LocalDateTime.now().toString());
//                body.put("Status", HttpStatus.NOT_FOUND.value());
//                body.put("Message", "Username password incorrect");
//                exchange.getResponse().setStatusCode(HttpStatus.NOT_FOUND);
//                exchange.getResponse().getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
//                String responseBody = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(body);
//                DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(responseBody.getBytes(StandardCharsets.UTF_8));
//                return exchange.getResponse().writeWith(Mono.just(buffer));
//            } else {
//                body.put("Timestamp", LocalDateTime.now().toString());
//                body.put("Status", HttpStatus.UNAUTHORIZED.value());
//                body.put("Message", "Unauthorized access");
//                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
//                exchange.getResponse().getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
//                String responseBody = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(body);
//                DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(responseBody.getBytes(StandardCharsets.UTF_8));
//                return exchange.getResponse().writeWith(Mono.just(buffer));
//            }
//        }else{
//            body.put("Timestamp", LocalDateTime.now().toString());
//            body.put("Status", HttpStatus.UNAUTHORIZED.value());
//            body.put("Message", "Unauthorized access");
//            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
//            exchange.getResponse().getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
//            String responseBody = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(body);
//            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(responseBody.getBytes(StandardCharsets.UTF_8));
//            return exchange.getResponse().writeWith(Mono.just(buffer));
//        }
////        if (exchange.getRequest().getQueryParams().get("username") == null) {
////            body.put("Timestamp", LocalDateTime.now().toString());
////            body.put("Status", HttpStatus.NOT_FOUND.value());
////            body.put("Message", "Username password incorrect");
////            exchange.getResponse().setStatusCode(HttpStatus.NOT_FOUND);
////            exchange.getResponse().getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
////            String responseBody = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(body);
////            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(responseBody.getBytes(StandardCharsets.UTF_8));
////            return exchange.getResponse().writeWith(Mono.just(buffer));
////        } else {
////            body.put("Timestamp", LocalDateTime.now().toString());
////            body.put("Status", HttpStatus.UNAUTHORIZED.value());
////            body.put("Message", "Unauthorized access");
////            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
////            exchange.getResponse().getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
////            String responseBody = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(body);
////            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(responseBody.getBytes(StandardCharsets.UTF_8));
////            return exchange.getResponse().writeWith(Mono.just(buffer));
////        }
//    }
}
