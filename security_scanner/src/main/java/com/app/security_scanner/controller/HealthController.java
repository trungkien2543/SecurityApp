package com.app.security_scanner.controller;

import com.app.security_scanner.common.BaseController;
import com.app.security_scanner.dto.response.ApiResponse;
import com.app.security_scanner.util.ApiConstants;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(ApiConstants.API_PREFIX)
public class HealthController extends BaseController {

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<String>> health() {

        return success("Hello my app");
    }
}
