package com.app.security_scanner.mapper;

import com.app.security_scanner.dto.response.ScanIssueResponse;
import com.app.security_scanner.entity.ScanIssue;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface ScanIssueMapper {

    ScanIssueResponse toResponse(ScanIssue issue);
}