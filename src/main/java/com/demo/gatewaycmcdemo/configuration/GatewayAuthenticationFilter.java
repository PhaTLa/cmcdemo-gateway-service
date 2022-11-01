package com.demo.gatewaycmcdemo.configuration;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@RefreshScope
@Component
public class GatewayAuthenticationFilter implements GatewayFilter {

    @Autowired
    private RouteValidator routeValidator;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if(routeValidator.isSecured(request)){
            if(this.authHeaderMissing(request)){
                return this.onError(exchange,"Unauthorized access",HttpStatus.UNAUTHORIZED);
            }
            String token = this.getAuthHeader(request).substring("Bearer ".length());
            try {
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(token);
                String username = decodedJWT.getSubject();
                String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

                if(!Arrays.asList(roles).contains("ADMIN")){
                    return this.onError(exchange,"Unauthorized access",HttpStatus.UNAUTHORIZED);
                }

                this.populateRequestWithHeader(exchange, username, roles);
            }catch (Exception e){
                return this.onError(exchange,"Unauthorized access",HttpStatus.UNAUTHORIZED);
            }
        }
        return chain.filter(exchange);
    }

    @SneakyThrows
    private Mono<Void> onError(ServerWebExchange exchange, String error, HttpStatus status){
        ServerHttpResponse response = exchange.getResponse();
        Map<String,Object> body = new LinkedHashMap<>();
        ObjectMapper mapper = new ObjectMapper();
        body.put("Timestamp", LocalDateTime.now().toString());
        body.put("Status", status.value());
        body.put("Errors", error);
        String responseBody = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(body);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(responseBody.getBytes(StandardCharsets.UTF_8));
        log.info("Response ================> {}",responseBody);
        response.setStatusCode(status);
        return response.writeWith(Mono.just(buffer));
//        return response.setComplete();
    }

    private String getAuthHeader(ServerHttpRequest request){
        return request.getHeaders().getOrEmpty(HttpHeaders.AUTHORIZATION).get(0);
    }

    private boolean authHeaderMissing(ServerHttpRequest request){
        return !request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION);
    }

    private void populateRequestWithHeader(ServerWebExchange exchange, String username, String[] roles){
        exchange.getRequest().mutate()
                .header("username",username)
                .header("roles",String.join(",",roles))
                .build();
    }
}
