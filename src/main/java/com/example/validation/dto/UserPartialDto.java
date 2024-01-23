package com.example.validation.dto;

import com.example.validation.groups.MandatoryStep;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class UserPartialDto {
    // 두가지는 회원가입 단계에서 반드시 첨부해야 하는 데이터
    // 단 회원 정보 업데이트 단계에서는 반드시는 아님
    @Size(min = 8, groups = MandatoryStep.class)
    @NotNull(groups = MandatoryStep.class)
    private String username;
    @Size(min = 10, groups = MandatoryStep.class)
    @NotNull(groups = MandatoryStep.class)
    private String password;

    // 두가지는 회원가입 완료 후 추가 정보 기입 단계에서 첨부하는 데이터
    // 단, 추가정보 기입시에는 반드시 포함해야 한다.
    @NotNull
    @Email
    private String email;
    @NotNull
    private String phone;
}
