# 유효성 검증

사용자가 데이터를 입력할 수 있을 때, 입력하는 데이터의 형식이 서비스에서 받아들일 수 있는
데이터의 형식과 일치하는지 확인하고, 일치하지 않는 입력을 허용하지 않는 작업을
유효성 검증(Validation)이라고 부른다.

Spring Boot를 사용하면 `spring-boot-starter-validation` 의존성을 이용해
유효성 검증을 쉽게 진행할 수 있게 해준다.

## `@Valid`

먼저 어떤 DTO를 기준으로, 해당하는 DTO의 데이터가 허용할 수 있는 형식의 데이터를 정의한다.
해당하는 형식을 나타내는 어노테이션을 해당 속성에 적용한다.

```java
public class UserDto {
    private Long id;

    @NotBlank(message = "username is required")
    private String username;

    private String email;
}
```

- `@NotBlank`: 빈 문자열을 허용하지 않는 어노테이션이다.

이후 이 DTO를 `@RequestBody`로 받을 때 `@Valid`를 붙이면 해당하는 조건을 
만족하는 데이터만 허용하며, 그 외에는 400 Bad Request 응답을 돌려준다.

```java
@RestController
public class UserController {
    @PostMapping("/users")
    ResponseEntity<Map<String, String>> addUser(
        @Valid @RequestBody UserDto user) {
        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("message", "success!");

        return ResponseEntity.ok(responseBody);
    }
}
```

사용 가능한 어노테이션은 [Jakarta Bean Validation Specification](https://beanvalidation.org/2.0/spec/#builtinconstraints) 문서를 살펴보자.

### `@NotNull`, `@NotEmpty`, `@NotBlank`

- `@NotNull` : 데이터가 `null` 이 아님을 검증. 대부분의 `null`이 할당될 수 있는 타입에 사용 가능.
- `@NotEmpty` : 데이터가 비어있지 않음을 검증. `String` , `List` , 배열 등 여러 데이터를 가지고 있는 자료형에서 사용가능하며, `String`의 경우 길이가 0이 아님을, `List` 등의 Collection은 아이템이 하나 이상 존재하는지를 검증.
- `@NotBlank` : 문자열에 대하여, 공백이 아님을 검증. 이때 공백의 기준은 문자열의 길이가 아닌, 공백문자, 탭, 개행문자 등 공백으로 나타나는 문자들을 제외한 문자열을 의미한다.

## `@Validated`

`@Validated` 어노테이션도 있다. `@Valid`와는 용도가 조금 다르다.

### 메서드 파라미터 검증

클래스에 어노테이션을 첨부하면 해당 클래스 메서드의 파라미터를 검증하는데 활용 가능하다.
`@RequstParam` 등에 활용이 가능하다.

```java
@Validated
@RestController
public class UserController {
    // ...
    @GetMapping("/validate-params")
    public Map<String, String> validateParams(
            @RequestParam("age")
            @Min(19)
            Integer age
    ) {
        // ...
    }
}
```

### 객체 부분 검증

만약 특정 객체의 일부분만 검증하고 싶을때 활용 가능하다. (단계적 회원가입 등)

먼저 각 단계를 나타내는 `interface`를 만든다.

```java
public interface MandatoryStep {}
```

그 다음 DTO의 속성 어노테이션에 `groups`의 인자로 추가한다.

```java
public class UserPartialDto {
    @Size(min = 8, groups = MandatoryStep.class)
    private String username;

    @Size(min = 10, groups = MandatoryStep.class)
    private String password;

    @NotNull
    @Email
    private String email;

    @NotNull
    private String phone;

}
```

이후 `@Valid` 대신 `@Validated`를 사용하고, 어떤 그룹을 검증할지를
인자로 전달하면 된다.

```java
@PostMapping("/user-man")
public ResponseEntity<Map<String, String>> validateMan(
        @Validated(MandatoryStep.class)
        @RequestBody
        UserPartialDto dto
) {
    log.info(dto.toString());
    Map<String, String> responseBody = new HashMap<>();
    responseBody.put("message", "success!");

    return ResponseEntity.ok(responseBody);
}
```

## 검증 실패시 응답

기본적으로 검증에 실패하면 `MethodArgumentNotValidException` 예외가 발생하며,
400 응답이 사용자에게 돌아간다. 만약 이 응답을 원하는데로 바꾸고 싶다면, `@ExceptionHandler`를 이용해
예외처리를 적용할 수 있다.

```java
@ExceptionHandler(MethodArgumentNotValidException.class)
@ResponseStatus(HttpStatus.BAD_REQUEST)
public Map<String, Object> handleValidationException(
        MethodArgumentNotValidException exception
) {
    Map<String, Object> errors = new HashMap<>();
    exception.getBindingResult().getFieldErrors().forEach(error -> {
        String fieldName = error.getField();
        String errorMessage = error.getDefaultMessage();
        errors.put(fieldName, errorMessage);
    });

    return errors;
}
```

`@Validated`를 이용한 파라미터 검증을 할 경우 `ConstraintViolationException`이 발생한다.
이는 응답이 보내질때 500 Internal Server Error로 응답이 보내지게 된다.

```java
@ExceptionHandler(ConstraintViolationException.class)
@ResponseStatus(HttpStatus.BAD_REQUEST)
public Map<String, String> handleConstraintException(
        ConstraintViolationException exception
) {
    Map<String, String> errors = new HashMap<>();

    for (ConstraintViolation<?> violation:
            exception.getConstraintViolations()) {
        errors.put(violation.getPropertyPath().toString(), violation.getMessage());
    }
    return errors;
}
```

## 사용자 지정 유효성 검사

먼저 어노테이션을 만든다.

```java
@Target({ ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
public @interface EmailWhitelist {}
```

- `@Target()` : 이 어노테이션이 어디에 덧붙일 수 있는지를 정의하는 용도.
- `@Retention()` : 이 어노테이션이 어느시점까지 유지될지를 정의하는 용도.

그리고 유효성 검증을 위해서 필요한 어노테이션 Element를 정의한다.

```java
@Target({ ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
public @interface EmailWhitelist {
    String message() default "Email not in whitelist";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
```

다음 이 어노테이션이 붙은 필드를 검증하는 클래스를 만든다. 이는 `ConstraintValidator` 인터페이스를 구현하는
방식으로 만든다.

```java
public class EmailWhitelistValidator
        implements ConstraintValidator<EmailWhitelist, String> {
    private final Set<String> whiteList;

    public EmailWhitelistValidator() {
        this.whiteList = new HashSet<>();
        this.whiteList.add("gmail.com");
        this.whiteList.add("naver.com");
        this.whiteList.add("kakao.com");
    }
    
    @Override
    public boolean isValid(String value,
                           ConstraintValidatorContext context) {
        String[] split = value.split("@");
        String domain = split[split.length - 1];
        return whiteList.contains(domain);
    }
}
```

그리고 마지막으로 앞서 만든 어노테이션에 검증을 진행하는 클래스를 전달해준다.

```java
@Target({ ElementType.METHOD, ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = EmailWhitelistValidator.class)
public @interface EmailWhitelist {
    String message() default "Email not in whitelist";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
```

### 설정 전달

만약 `@Min`이나 `@Size` 같이 특정 값을 바탕으로 검증을 진행하고 싶다면, 값을 전달받을
Element를 먼저 정의한다.

```java
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = EmailBlacklistValidator.class)
public @interface EmailBlacklist {
    String message() default "Email in blacklist";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    String[] blacklist() default {};
}
```

이 값은 `ContstraintValidtor` 구현체의 `initialize` 메서드에서
회수해서 활용할 수 있다.

```java
public class EmailBlacklistValidator 
        implements ConstraintValidator<EmailBlacklist, String> {
    Set<String> blacklist;

    @Override
    public void initialize(EmailBlacklist annotation) {
        this.blacklist = new HashSet<>();
        this.blacklist.addAll(Arrays.asList(annotation.blacklist()));
    }
    ...
}
```



