package me.silvernine.tutorial.service;

import java.util.Collections;

import me.silvernine.tutorial.dto.UserDto;
import me.silvernine.tutorial.entity.Authority;
import me.silvernine.tutorial.entity.User;
import me.silvernine.tutorial.exception.DuplicateMemberException;
import me.silvernine.tutorial.exception.NotFoundMemberException;
import me.silvernine.tutorial.repository.UserRepository;
import me.silvernine.tutorial.utils.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {//회원가입, 유저정보조회 등의 메소드를 만들기 위한 클래스
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    //UserService는 userRepository와 passwordEncoder를 주입받는다
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    //회원가입 로직을 수행하는 메소드
    //파라미터로 받은 UserDto안에 getUsername()을 기준으로 해서
    //33번라인 findOneWithAuthoritiesByUsername 이미 DataBase에 이 유저네임으로 정해져 있는 정보가 있는지 먼지 찾아보고
    public UserDto signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new DuplicateMemberException("이미 가입되어 있는 유저입니다.");
        }
        //해당 유저네임이 없으면 권한정보를 만들고
        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();
        //위에 있는 권한정보를 가지고 유저정보도 만들어서
        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();
        //유저 레포지토리에 save메소드를 통해 DB에 저장
        //여기서 중요한 점은 signup메소드를 통해 가입한 회원은
        // 37번라인에 ROLE_USER를 가지고 있고
        //data.sql에서 자동 생성되는 admin계정은 USER, ADMIN ROLE을 가지고 있다
        //이 차이는 권한 검증부분에서 테스트한다
        return UserDto.from(userRepository.save(user));
    }
    //유저와 권한 정보를 가져오는 메소드 2개
    //2개의 메소드를 허용권한을 다르게해서 권한검증에 대한 부분 테스트할 것임
    @Transactional(readOnly = true)
    //getUserWithAuthorities는 username을 파라미터로 받아서
    //어떠한 유저네임이든 username에 해당하는
    // 유저객체와 권한정보를 가져올 수 있는 메소드 findOneWithAuthoritiesByUsername
    public UserDto getUserWithAuthorities(String username) {
        return UserDto.from(userRepository.findOneWithAuthoritiesByUsername(username).orElse(null));
    }

    @Transactional(readOnly = true)
    //getMyUserWithAuthorities는
    // 현재 SecurityContext에 저장이 되어있는 유저네임getCurrentUsername에 해당하는
    //findOneWithAuthoritiesByUsername 유저네임과 권한정보만 반환할 수 있다
    public UserDto getMyUserWithAuthorities() {
        return UserDto.from(SecurityUtil.getCurrentUsername()
                        .flatMap(userRepository::findOneWithAuthoritiesByUsername)
                        .orElseThrow(() -> new NotFoundMemberException("Member not found"))
        );
    }
}
