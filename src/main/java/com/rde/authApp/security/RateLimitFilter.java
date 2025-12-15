package com.rde.authApp.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitService rateLimitService;

    public RateLimitFilter(RateLimitService rateLimitService) {
        this.rateLimitService = rateLimitService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        // ---- LOGIN RATE LIMIT (IP based) ----
        if (path.equals("/auth/login")) {
            String ip = getClientIp(request);
            String key = "rate:login:" + ip;

            if (!rateLimitService.isAllowed(key, 5, 60)) {
                reject(response, "Too many login attempts. Try again in 1 minute.");
                return;
            }
        }

        // ---- REFRESH RATE LIMIT (token based) ----
        if (path.equals("/auth/refresh")) {
            String refreshToken = request.getParameter("refreshToken");

            if (refreshToken != null) {
                String key = "rate:refresh:" + refreshToken;

                if (!rateLimitService.isAllowed(key, 10, 60)) {
                    reject(response, "Too many refresh attempts.");
                    return;
                }
            }
        }



        // ---- REGISTER RATE LIMIT (IP based) ----
        if (path.equals("/auth/register")) {
            String ip = getClientIp(request);
            String key = "rate:register:" + ip;

            if (!rateLimitService.isAllowed(key, 3, 3600)) {
                reject(response, "Too many registrations. Try later.");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response, String msg)
            throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType("application/json");
        response.getWriter().write(
                "{ \"error\": \"" + msg + "\" }"
        );
    }

    private String getClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return forwarded != null ? forwarded.split(",")[0]
                : request.getRemoteAddr();
    }
}
