package com.app.security_scanner.controller;

import com.app.security_scanner.common.BaseController;
import com.app.security_scanner.dto.request.ExecuteRequest;
import com.app.security_scanner.dto.response.ApiResponse;
import com.app.security_scanner.dto.response.ExecuteResponse;
import com.app.security_scanner.service.RequestExecutorService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/execute")
@RequiredArgsConstructor
public class ExecuteController
        extends BaseController {

    private final RequestExecutorService
            requestExecutorService;

    @PostMapping
    public ResponseEntity<ApiResponse<ExecuteResponse>>
    execute(
            @Valid @RequestBody
            ExecuteRequest request
    ) {

        return success(
                requestExecutorService.execute(request)
        );
    }
}