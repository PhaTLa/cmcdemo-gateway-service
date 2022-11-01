package com.demo.gatewaycmcdemo.configuration;

//import com.auth0.jwt.JWT;
//import com.auth0.jwt.JWTVerifier;
//import com.auth0.jwt.algorithms.Algorithm;
//import com.auth0.jwt.exceptions.TokenExpiredException;
//import com.auth0.jwt.interfaces.DecodedJWT;
//import com.demo.gatewaycmcdemo.exception.CustomExceptionHandler;
//import lombok.SneakyThrows;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.security.authentication.ReactiveAuthenticationManager;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.context.ReactiveSecurityContextHolder;
//import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
//import org.springframework.web.server.ServerWebExchange;
//import org.springframework.web.server.WebFilter;
//import org.springframework.web.server.WebFilterChain;
//import reactor.core.publisher.Mono;
//
//import java.util.ArrayList;
//import java.util.Collection;
//
//import static java.util.Arrays.stream;
//import static org.springframework.http.HttpHeaders.AUTHORIZATION;

//@Slf4j
public class CustomAuthorizationFilter
//        extends AuthenticationWebFilter
{
//    public CustomAuthorizationFilter(ReactiveAuthenticationManager authenticationManager) {
//        super(authenticationManager);
//    }
//
////    @Override
////    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
////        if (request.getServletPath().equals("/login") || request.getServletPath().equals("/api/token/refresh") || request.getServletPath().equals("/api/login")) {
////            filterChain.doFilter(request, response);
////        } else {
////            String authorizationHeader = request.getHeader(AUTHORIZATION);
////            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
////                try {
////                    String token = authorizationHeader.substring("Bearer ".length());
////                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
////                    JWTVerifier verifier = JWT.require(algorithm).build();
////                    DecodedJWT decodedJWT = verifier.verify(token);
////                    String username = decodedJWT.getSubject();
////                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
////                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
////                    stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
////                    UsernamePasswordAuthenticationToken authenticationToken =
////                            new UsernamePasswordAuthenticationToken(username, null, authorities);
////                    log.info("User :{} have authorities: {}",username, String.join(",", roles));
////                    request.getSession().setAttribute("userName", username);
////                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
////                    filterChain.doFilter(request, response);
////                }catch (TokenExpiredException e) {
////                    log.error("Error logging in: {}", e.getMessage());
////                    CustomExceptionHandler<TokenExpiredException> handler = new CustomExceptionHandler<>();
////                    handler.exceptionHandler(e, request, response);
////                } catch (RuntimeException e) {
////                    log.error("Error valid in: {}", e.getMessage());
////                    CustomExceptionHandler<RuntimeException> handler = new CustomExceptionHandler<>();
////                    handler.exceptionHandler(e, request, response);
////                }catch (Exception e) {
////                    log.error("Error logging in: {}", e.getMessage());
////                    CustomExceptionHandler<Exception> handler = new CustomExceptionHandler<>();
////                    handler.exceptionHandler(e, request, response);
////                }
////            }else {
////                filterChain.doFilter(request, response);
////            }
////        }
////    }
//
//    @SneakyThrows
//    @Override
//    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
//
//        ServerHttpRequest request = exchange.getRequest();
////        ServerHttpResponse response = exchange.getResponse();
//
//        if (request.getURI().getPath().equals("/login")
//                || request.getURI().getPath().equals("/user/api/token/refresh")
//                || request.getURI().getPath().equals("/user/api/login")) {
//            return chain.filter(exchange);
//        } else {
//            String authorizationHeader = request.getHeaders().getFirst(AUTHORIZATION);
//            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
//                try {
//                    String token = authorizationHeader.substring("Bearer ".length());
//                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
//                    JWTVerifier verifier = JWT.require(algorithm).build();
//                    DecodedJWT decodedJWT = verifier.verify(token);
//                    String username = decodedJWT.getSubject();
//                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
//                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
//                    stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
////                    UsernamePasswordAuthenticationToken authenticationToken =
////                            new UsernamePasswordAuthenticationToken(username, "", authorities);
//                    CustomAuthenticationToken authenticationToken = new CustomAuthenticationToken(username,authorities);
//                    log.info("User :{} have authorities: {}",username, String.join(",", roles));
////                    WebSessionServerSecurityContextRepository.
//                    ReactiveSecurityContextHolder.withAuthentication(authenticationToken);
//                    return exchange.getSession().doOnNext(
//                            webSession -> webSession.getAttributes().put("username",username)
//                    ).then(chain.filter(exchange));
////                    return chain.filter(exchange);
//                }catch (TokenExpiredException e) {
//                    log.error("Error logging in: {}", e.getMessage());
//                    CustomExceptionHandler<TokenExpiredException> handler = new CustomExceptionHandler<>();
//                    return handler.reactiveExceptionHandler(e, exchange);
//                } catch (RuntimeException e) {
//                    log.error("Error valid in: {}", e.getMessage());
//                    CustomExceptionHandler<RuntimeException> handler = new CustomExceptionHandler<>();
//                    return handler.reactiveExceptionHandler(e, exchange);
//                }catch (Exception e) {
//                    log.error("Error logging in: {}", e.getMessage());
//                    CustomExceptionHandler<Exception> handler = new CustomExceptionHandler<>();
//                    return handler.reactiveExceptionHandler(e, exchange);
//                }
//            }else {
//                return chain.filter(exchange);
//            }
//        }
//    }
}
