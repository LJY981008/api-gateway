package com.example.apigateway.enums;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum CustomErrorCode {
    EMAIL_INVALID_FORMAT(HttpStatus.BAD_REQUEST, "이메일 형식이 잘못되었습니다."), // (회원가입, 로그인) 이메일 형식 틀림
    PASSWORD_INVALID_FORMAT(HttpStatus.BAD_REQUEST, "비밀번호 형식이 잘못되었습니다."), // (회원가입, 로그인) 비번 형식 틀림
    USERNAME_INVALID_FORMAT(HttpStatus.BAD_REQUEST, "유저네임 형식이 잘못되었습니다."), // (회원가입, 로그인) 유저네임 형식 틀림
    ROLE_INVALID_FORMAT(HttpStatus.BAD_REQUEST, "유효하지 않은 UserRole"),
    SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "이상해씨"),
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "잘못된 요청입니다."),;

    private final HttpStatus httpStatus;
    private final String message;

    CustomErrorCode(HttpStatus httpStatus, String message){
        this.httpStatus = httpStatus;
        this.message = message;
    }
}