package com.example.apigateway.filter;

import com.example.apigateway.dto.AuthUserDto;
import com.example.apigateway.enums.UserRole;
import com.example.apigateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter implements WebFilter {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String bearerJwt = exchange.getRequest().getHeaders().getFirst("Authorization");

        if (bearerJwt == null || bearerJwt.isEmpty()) {
            return chain.filter(exchange);
        }

        String jwt = jwtUtil.substringToken(bearerJwt);

        try {
            Claims claims = jwtUtil.extractClaims(jwt);
            if (claims == null) {
                exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
                return exchange.getResponse().setComplete();
            }

            Long userId = jwtUtil.getUserId(jwt);
            UserRole userRole = jwtUtil.getUserRole(jwt);
            String email = jwtUtil.getEmail(jwt);

            AuthUserDto authUser = new AuthUserDto(userId, email, userRole);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    authUser, "", List.of(new SimpleGrantedAuthority("ROLE_" + userRole.name()))
            );

            return chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authenticationToken));
        } catch (Exception e) {
            log.error("예상치 못한 예외 발생", e);
            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            return exchange.getResponse().setComplete();
        }
    }
}
