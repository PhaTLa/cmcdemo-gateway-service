package com.demo.gatewaycmcdemo.common;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class ResponseVo {
    public ResponseVo(String message) {
        this.message = message;
    }
    private String message;
    private int total;
    private List<Object> voList;
}
