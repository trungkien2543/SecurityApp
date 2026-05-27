package com.app.security_scanner.common;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    SUCCESS(
            1000,
            "Success",
            HttpStatus.OK
    ),

    VALIDATION_ERROR(
            1400,
            "Validation error",
            HttpStatus.BAD_REQUEST
    ),

    CONSTRAINT_VIOLATION(
            1400,
            "Constraint violation",
            HttpStatus.BAD_REQUEST
    ),

    RESOURCE_NOT_FOUND(
            1404,
            "Resource not found",
            HttpStatus.NOT_FOUND
    ),

    INTERNAL_SERVER_ERROR(
            1500,
            "Internal server error",
            HttpStatus.INTERNAL_SERVER_ERROR);

    private final int code;
    private final String message;
    private final HttpStatus status;
}