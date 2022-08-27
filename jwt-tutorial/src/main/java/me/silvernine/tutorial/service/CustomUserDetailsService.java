package me.silvernine.tutorial.service;

import me.silvernine.tutorial.entity.User;
import me.silvernine.tutorial.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Component("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {
    //UserDetailsService를 implements하고 23번라인 userRepository를 주입받는다
    //29번 라인 UserDetailsService의 loadUserByUsername메소드를 오버라이드해서
    //로그인 시에 30번라인 findOneWithAuthoritiesByUsername(username) DB에서 유저정보와 권한정보를 가져오게 된다
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(final String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username)
                //36번라인 createUser 데이터베이스에서 가져온 정보를 기준으로
                .map(user -> createUser(username, user))
                .orElseThrow(() -> new UsernameNotFoundException(username + " -> 데이터베이스에서 찾을 수 없습니다."));
    }

    private org.springframework.security.core.userdetails.User createUser(String username, User user) {
        if (!user.isActivated()) {
            //36~37번라인 그 유저가 활성화 상태라면
            // 53번라인 권한정보들과, 48번라인 유저네임, 패스워드를 가지고
            //51번라인 User객체를 리턴한다
            //User(user.getUsername(),
            //                user.getPassword(),
            //                grantedAuthorities);
            throw new RuntimeException(username + " -> 활성화되어 있지 않습니다.");
        }

        List<GrantedAuthority> grantedAuthorities = user.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
                .collect(Collectors.toList());

        return new org.springframework.security.core.userdetails.User(user.getUsername(),
                user.getPassword(),
                grantedAuthorities);
    }
}
