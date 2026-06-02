package com.app.security_scanner.service.scanner;

import com.app.security_scanner.dto.response.ExecuteResponse;
import com.app.security_scanner.entity.Finding;

import java.util.List;

public interface SecurityScanner {

    /**
     * Phân tích response và trả về danh sách security findings.
     * Không được throw exception — nếu lỗi thì return empty list.
     */
    List<Finding> scan(ExecuteResponse response);
}