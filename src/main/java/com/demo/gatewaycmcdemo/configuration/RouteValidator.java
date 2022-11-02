package com.demo.gatewaycmcdemo.configuration;

import lombok.Getter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Component
@Getter
public class RouteValidator {
    private List<String> noAuthEndpoint;
    private AntPathMatcher matcher;

    public RouteValidator() {
        this.noAuthEndpoint = new ArrayList<>();
        String[] enpoints = {
                "user/api/token/refresh/**",
                "/product/api/products",
                "/product/api/product/**",
                "/v3/**","/product/api/categories",
                "/blog/api/blog/**",
                "/blog/api/blogs/**",
                "/product/api/image/**",
                "/user/api/login",
                "/user/api/register"
        };
        this.noAuthEndpoint.addAll(Arrays.asList(enpoints));
        this.matcher = new AntPathMatcher();
    }

    public boolean isSecured(ServerHttpRequest request){
        return this.noAuthEndpoint.stream().noneMatch(uri -> matcher.match(uri,request.getURI().getPath()));
    }
}
