package com.app.security_scanner.controller;

import com.app.security_scanner.common.BaseController;
import com.app.security_scanner.dto.request.CreateScanRequest;
import com.app.security_scanner.dto.response.ApiResponse;
import com.app.security_scanner.dto.response.ScanResponse;
import com.app.security_scanner.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;



@RestController
@RequestMapping("/api/scans")
@RequiredArgsConstructor
public class ScanController extends BaseController {

    private final ScanService scanService;

    @PostMapping
    public ResponseEntity<ApiResponse<ScanResponse>> createScan(
            @Valid @RequestBody CreateScanRequest request
    ) {

        return created(
                scanService.createScan(request)
        );
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<ScanResponse>> getScan(
            @PathVariable UUID id
    ) {

        return success(
                scanService.getScan(id)
        );
    }

    @GetMapping
    public ResponseEntity<ApiResponse<Page<ScanResponse>>> getScans(
            Pageable pageable
    ) {

        return success(
                scanService.getScans(pageable)
        );
    }
}