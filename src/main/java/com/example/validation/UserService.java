package com.example.validation;

import jakarta.validation.constraints.Min;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

@Slf4j
@Service
@Validated
public class UserService {
    public void printAge(
            @Min(19)
            Integer age
    ) {
        log.info(age.toString());
    }
}
