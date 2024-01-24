package com.example.validation.constraints;

import com.example.validation.constraints.annotations.EmailWhiteList;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.HashSet;
import java.util.Set;

public class EmailWhitelistValidator
        implements ConstraintValidator<EmailWhiteList, String> {

    private final Set<String> whiteList;
    public EmailWhitelistValidator() {
        this.whiteList = new HashSet<>();
        this.whiteList.add("gmail.com");
        this.whiteList.add("naver.com");
        this.whiteList.add("kakao.com");
    }

    // EmailWhiteList 어노테이션이 붙은 대상의 데이터가
    // 검사를 통과하면 true를
    // 검사에 실패하면 false를
    // 반환하도록 만들면 됩니다.
    @Override
    public boolean isValid(
            // value: 실제로 사용자가 입력한 내용이 여기 들어온다.
            String value,
            ConstraintValidatorContext context
    ) {
        // value가 null인지 체크하고, (null이면 false)
        if (value == null) return false;
        // value에 @가 포함되어 있는지 확인하고, (아니면 false)
        if (!value.contains("@")) return false;
        // value를 @ 기준으로 자른 뒤, 제일 뒤가 `this.whiteList`에
        // 담긴 값 중 하나인지 확인을 한다.
        String[] split = value.split("@");
        String domain = split[split.length - 1];
        return whiteList.contains(domain);
    }
}
