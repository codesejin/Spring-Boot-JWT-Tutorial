package me.silvernine.tutorial.controller;

import me.silvernine.tutorial.dto.UserDto;
import me.silvernine.tutorial.entity.User;
import me.silvernine.tutorial.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;

@RestController
@RequestMapping("/api")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/test-redirect")
    public void testRedirect(HttpServletResponse response) throws IOException {
        response.sendRedirect("/api/user");
    }
    //회원가입
    @PostMapping("/signup")
    public ResponseEntity<UserDto> signup(
            //UserDto를 파라미터로 받아서 userService의 signup메소드 수행
            @Valid @RequestBody UserDto userDto
    ) {
        return ResponseEntity.ok(userService.signup(userDto));
    }

    @GetMapping("/user")
    //@PreAuthorize에서는 ROLE_ 접두사를 붙여도 되고 안붙여도 정상 동작한다
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    //getMyUserInfo메소드는  @PreAuthorize를 통해
    //'USER','ADMIN' 2가지 권한 모두 허용했고,
    public ResponseEntity<UserDto> getMyUserInfo(HttpServletRequest request) {
        return ResponseEntity.ok(userService.getMyUserWithAuthorities());
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    //getUserInfo메소드는 'ADMIN'권한만 호출 할 수 있도록 설정
    public ResponseEntity<UserDto> getUserInfo(@PathVariable String username) {
        return ResponseEntity.ok(userService.getUserWithAuthorities(username));
    }
}
