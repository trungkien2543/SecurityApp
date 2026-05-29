package com.app.security_scanner.mapper;

import com.app.security_scanner.dto.response.ScanResponse;
import com.app.security_scanner.entity.Scan;
import org.mapstruct.Mapper;

@Mapper(
        componentModel = "spring",
        uses = ScanIssueMapper.class
)
public interface ScanMapper {

    ScanResponse toResponse(Scan scan);
}