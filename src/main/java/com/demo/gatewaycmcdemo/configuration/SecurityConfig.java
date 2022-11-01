package com.demo.gatewaycmcdemo.configuration;

//import com.demo.gatewaycmcdemo.exception.CustomAccessDeniedHandler;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.HttpMethod;
//import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager;
//import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
//import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
//import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
//import org.springframework.security.config.web.server.ServerHttpSecurity;
//import org.springframework.security.web.server.SecurityWebFilterChain;
//import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
//import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
//import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

//@Slf4j
//@EnableWebFluxSecurity
//@Configuration
public class SecurityConfig {
//
//    @Value("${security.enable-csrf}")
//    private boolean csrfEnabled;
//
////    @Bean
////    public AccessDeniedHandler accessDeniedHandler() {
////        return new CustomAccessDeniedHandler();
////    }
//
//    @Bean
//    public ServerAccessDeniedHandler accessDeniedHandler() {
//        return new CustomAccessDeniedHandler();
//    }
//
////    @Bean
////    public AuthenticationEntryPoint authenticationEntryPoint() {
////        return new CustomAuthenticationEntryPoint();
////    }
//    @Bean
//    public ServerAuthenticationEntryPoint authenticationEntryPoint() {
//        return new CustomAuthenticationEntryPoint();
//    }
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
//        if(!csrfEnabled)
//        {
//            httpSecurity.csrf().disable();
//        }
//        log.info("disable scrf");
//        httpSecurity
//                .authorizeRequests()
//                .antMatchers("/login/**", "/api/login", "/api/user/register", "/api/token/refresh/**",
//                        "/api/products", "/api/product/**", "/swagger-ui/**", "/v3/**", "/swagger-ui.html",
//                        "/api/blog/**", "/api/blogs", "/api/image/**")
//                .permitAll()
//                .antMatchers("**/admin/**").hasAnyAuthority("ADMIN")
//                .anyRequest()
//                .authenticated()
//                .and()
//                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
//                .accessDeniedHandler(accessDeniedHandler())
//                .and()
//                .httpBasic()
//                .and()
//                .addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
//                .sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//        return httpSecurity.build();
//    }

    /*@Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity httpSecurity, JwtAuthenticationManager authenticationManager) {
        return httpSecurity
                .authorizeExchange()
                .pathMatchers("user/api/token/refresh/**",
                        "/product/api/products", "/product/api/product/**", "/v3/**","/product/api/categories",
                        "/blog/api/blog/**", "/blog/api/blogs/**", "/product/api/image/**", "/user/api/login", "/user/api/register").permitAll()
                .pathMatchers(HttpMethod.GET, "/user/api/admin/**").hasAnyAuthority("ADMIN")
                .pathMatchers(HttpMethod.POST, "/user/api/admin/**").hasAnyAuthority("ADMIN")
                .pathMatchers(HttpMethod.GET, "/product/api/admin/**").hasAnyAuthority("ADMIN")
                .pathMatchers(HttpMethod.POST, "/product/api/admin/**").hasAnyAuthority("ADMIN")
                .anyExchange().authenticated()
                .and()
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
                .accessDeniedHandler(accessDeniedHandler())
                .and()
                .addFilterAt(new CustomAuthorizationFilter(authenticationManager),SecurityWebFiltersOrder.AUTHENTICATION)
                .httpBasic().disable()
                .formLogin().disable()
                .csrf().disable()
                .build();
    }*/
}
