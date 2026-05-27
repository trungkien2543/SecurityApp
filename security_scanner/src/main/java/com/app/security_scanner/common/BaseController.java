package com.app.security_scanner.common;

import com.app.security_scanner.dto.response.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public abstract class BaseController {

    protected <T> ResponseEntity<ApiResponse<T>> success(T result) {

        return ResponseEntity.ok(
                ApiResponse.success(result)
        );
    }

    protected <T> ResponseEntity<ApiResponse<T>> created(T result) {

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(
                        ApiResponse.success(result)
                );
    }

    protected ResponseEntity<ApiResponse<Object>> error(
            int code,
            String message
    ) {

        return ResponseEntity
                .badRequest()
                .body(
                        ApiResponse.error(code, message)
                );
    }

    protected <T> ResponseEntity<ApiResponse<T>> custom(
            HttpStatus status,
            int code,
            String message,
            T result
    ) {

        return ResponseEntity
                .status(status)
                .body(
                        new ApiResponse<>(code, message, result)
                );
    }
}