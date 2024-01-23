package com.example.validation.dto;

import jakarta.validation.constraints.*;
import lombok.*;

import java.time.LocalDate;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {
    private Long id;
    // 사용자가 입력하는 데이터 중 검증하고 싶은 데이터
    // 사용자 계정은 8글자 이상
    @NotNull
    @Size(min = 8, message = "8자는 넣어주세요.")
    private String username;
    // message를 기록하면 예외에 기록되는 문구를 바꿀 수 있다.
    @Email(message = "Email을 넣어주세요.")
    private String email;
    // 14세 이상만 받아준다.
    @Min(value = 14, message = "만 14세 이하는 부모님 동의가 필요합니다.")
    private Integer age;
    // 날짜를 나타내는 Java 클래스 ('YYYY-MM-DD')
    @Future
    private LocalDate validUntil;

    // NotNull vs NotEmpty vs NotBlank
    @NotNull
    private String notNullString;
    @NotEmpty
    private String notEmptyString;
    @NotBlank
    private String notBlankString;
}
