package com.PianzinAV.animalInsta.validation;

import com.PianzinAV.animalInsta.annotation.PasswordMatchers;
import com.PianzinAV.animalInsta.payload.request.SignupRequest;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class PasswordMatchesValidator implements ConstraintValidator<PasswordMatchers,Object> {
    @Override
    public void initialize(PasswordMatchers constraintAnnotation) {

    }

    @Override
    public boolean isValid(Object obj, ConstraintValidatorContext constraintValidatorContext) {
        SignupRequest userSignupRequest=(SignupRequest) obj;
        return userSignupRequest.getPassword().equals(userSignupRequest.getConfirmPassword());
    }
}
