package com.demo.gatewaycmcdemo.configuration;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
@Slf4j
@Component
public class CustomGlobalFilterFactory extends AbstractGatewayFilterFactory<CustomGlobalFilterFactory.Config> {

    @Autowired
    GatewayAuthenticationFilter filter;

    public CustomGlobalFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            log.info("==========> Gateway request: {} - {}", request.getMethod(), request.getURI().getPath());

            return filter.filter(exchange, chain);
        });
    }

    public static class Config{

    }

}
