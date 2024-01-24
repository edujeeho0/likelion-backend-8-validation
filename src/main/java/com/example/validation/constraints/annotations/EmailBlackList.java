package com.example.validation.constraints.annotations;

import com.example.validation.constraints.EmailBlacklistValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = EmailBlacklistValidator.class)
public @interface EmailBlackList {
    String message() default "Email in blacklist";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
    String[] blacklist() default {};
}
