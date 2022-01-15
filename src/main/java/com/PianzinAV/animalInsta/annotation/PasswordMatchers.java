package com.PianzinAV.animalInsta.annotation;


import com.PianzinAV.animalInsta.validation.PasswordMatchesValidator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.*;

@Target({ElementType.TYPE, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PasswordMatchesValidator.class)
@Documented
public @interface PasswordMatchers {
    String message() default "Password do not match";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
