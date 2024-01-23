package com.example.validation;

import com.example.validation.dto.UserDto;
import com.example.validation.dto.UserPartialDto;
import com.example.validation.groups.MandatoryStep;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.validation.FieldError;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Slf4j
@Validated
@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService service;
    // @Validated가 붙은 클래스의 메서드 파라미터는 검증이 가능하다.
    // /validate-params?age=14
    @GetMapping("/validate-params")
    public String validateParams(
            @Min(14)
            @RequestParam("age")
            Integer age
    ) {
        log.info(age.toString());
        service.printAge(age);
        return "done";
    }

    @PostMapping("/validate-dto")
    public String validateDto(
            // 이 데이터는 입력을 검증해야 한다
            @Valid
            @RequestBody
            UserDto dto
    ) {
        log.info(dto.toString());
        return "done";
    }

    // /validate-man으로 요청할때는
    // username과 password에 대한 검증만 진행하고 싶다.
    @PostMapping("/validate-man")
    public String validateMan(
            @Validated(MandatoryStep.class)
            @RequestBody
            UserPartialDto dto
    ) {
        log.info(dto.toString());
        return "done";
    }


    // 검증 실패시 응답하기 1.
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleValidationException(
            final MethodArgumentNotValidException exception
    ) {
        Map<String, Object> errors = new HashMap<>();
        // 예외가 가진 데이터를 불러오기
        List<FieldError> fieldErrors
                = exception.getBindingResult().getFieldErrors();
        // 각각의 에러에 대해서 순회하며
        for (FieldError error: fieldErrors) {
            String fieldName = error.getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        }
        return errors;
    }

    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleConstraintException(
            final ConstraintViolationException exception
    ) {
        Map<String, Object> errors = new HashMap<>();
        Set<ConstraintViolation<?>> violations
                = exception.getConstraintViolations();
        for (ConstraintViolation<?> violation: violations) {
            String property = violation.getPropertyPath().toString();
            String message = violation.getMessage();
            errors.put(property, message);
        }
        return errors;
    }

}
