package me.silvernine.tutorial.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component //토큰의 생성, 토큰의 유효성 검증등을 담당
public class TokenProvider implements InitializingBean {
    //InitializingBean을 implements 해서 afterPropertiesSet를 @Override한 이유는
    //@Component로 빈이 생성되고, 35번 라인 TokenProvider로 의존성 주입까지 받은 이후에
    // 36번라인 주입받은 Secret값을 44번라인 Base64 Decode해서 45번라인 Key 변수에 할당하기 위함

    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);
    private static final String AUTHORITIES_KEY = "auth";
    private final String secret;
    private final long tokenValidityInMilliseconds;
    private Key key;

    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
        this.secret = secret;
        this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
    }

    @Override
    public void afterPropertiesSet() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }


    //Authentication객체에 포함되어있는 권한정보를 이용해서 토큰을 생성하는 createToken 메소드 추가
    //Authentication 파라미터를 받아서
    public String createToken(Authentication authentication) {
        //권한들...
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        //application.yml파일에서 설정했던 만료시간을 설정하고 (tokenValidityInMilliseconds)
        Date validity = new Date(now + this.tokenValidityInMilliseconds);

        //jwt토큰생성
        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }

    //토큰을 파라미터로 받아서 토큰에 담겨있는 권한 정보들을 이용해서
    //authentication객체를 리턴하는 Authentication 메소드
    public Authentication getAuthentication(String token) {
        //72번라인 토큰을 파라미터로 받아서 82번라인 토큰을 이용해서 78번라인 claims을 만들고
        //86번라인 claims에서 85번라인 authorities 권한정보들을 빼내서
        //90번 라인 authorities 권한정보들을 이용해서 User principal 유저객체를 만들어서
        //92번 라인 유저객체와 토큰, 권한정보들을 이용해서 최종적으로 Authentication객체를 리턴(UsernamePasswordAuthenticationToken)

        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    //토큰을 파라미터로 받아서 유효성 검증을 수행하는 validateToken 메소드
    public boolean validateToken(String token) {
        try {
            //96번라인 토큰을 파라미터로 받아서 100번라인 파싱을 해보고
            //나오는 익셉션들을 캐치 (102~109라인), 111번라인 문제가 있으면 false, 101번 라인 정상이면 true
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            logger.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            logger.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            logger.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            logger.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }
}
