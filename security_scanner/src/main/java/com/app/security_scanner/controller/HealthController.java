package com.app.security_scanner.controller;

import com.app.security_scanner.dto.response.ApiResponse;
import com.app.security_scanner.util.ApiConstants;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(ApiConstants.API_PREFIX)
public class HealthController {

    @GetMapping("/health")
    public ApiResponse<String> health() {

        return ApiResponse.<String>builder()
                .success(true)
                .message("API running")
                .data("OK")
                .build();
    }
}
