package com.app.security_scanner.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;


@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
        int code,
        String message,
        T result) {

    public static <T> ApiResponse<T> success(T result) {
        return new ApiResponse<>(1000, "success", result);
    }

    public static <T> ApiResponse<T> error(int code, String message) {
        return new ApiResponse<>(code, message, null);
    }

    public static <T> ApiResponse<T> errorListDataMessage(int code, String message, T result) {
        return new ApiResponse<>(code, message, result);
    }
}