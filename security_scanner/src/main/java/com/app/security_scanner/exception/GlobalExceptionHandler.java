package com.app.security_scanner.exception;

import com.app.security_scanner.common.ErrorCode;
import com.app.security_scanner.dto.response.ApiResponse;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Object>> handleException(
            Exception ex
    ) {

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(
                        ApiResponse.error(
                                ErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                                ex.getMessage()
                        )
                );
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Object>> handleValidation(
            MethodArgumentNotValidException ex
    ) {

        Map<String, List<String>> errors = new HashMap<>();

        ex.getBindingResult()
                .getFieldErrors()
                .forEach(error -> {

                    errors.computeIfAbsent(
                            error.getField(),
                            key -> new ArrayList<>()
                    ).add(error.getDefaultMessage());

                });

        return ResponseEntity
                .badRequest()
                .body(
                        ApiResponse.errorListDataMessage(
                                1400,
                                "Validation error",
                                errors
                        )
                );
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiResponse<Object>> handleConstraint(
            ConstraintViolationException ex
    ) {

        return ResponseEntity
                .badRequest()
                .body(
                        ApiResponse.error(
                                ErrorCode.CONSTRAINT_VIOLATION.getCode(),
                                ex.getMessage()
                        )
                );
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Object>> handleNotFound(
            ResourceNotFoundException ex
    ) {

        return ResponseEntity
                .status(
                        ErrorCode.RESOURCE_NOT_FOUND.getStatus()
                )
                .body(
                        ApiResponse.error(
                                ErrorCode.RESOURCE_NOT_FOUND.getCode(),
                                ex.getMessage()
                        )
                );
    }
}