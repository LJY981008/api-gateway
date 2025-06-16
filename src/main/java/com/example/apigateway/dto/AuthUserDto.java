package com.example.apigateway.dto;

import com.example.taskgatway.enums.UserRole;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class AuthUserDto {
    private final Long userId;
    private final String email;
    private final UserRole userRole;
} 