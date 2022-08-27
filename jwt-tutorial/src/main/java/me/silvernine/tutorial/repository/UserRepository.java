package me.silvernine.tutorial.repository;

import me.silvernine.tutorial.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

//User엔티티에 매핑되는 UserRepository인터페이스를 만듬
//JpaRepository를 extends하고 (findAll) 타고 들어가면
//PagingAndSortingRepository를 extends함 (save)
public interface UserRepository extends JpaRepository<User, Long> {
    //@EntityGraph는 쿼리가 수행될때 Lazy조회가 아니고,Eager조회로 authorities정보를 같이 가져옴
    @EntityGraph(attributePaths = "authorities")
    //username을 기준으로 User정보를 가져올때 권한 정보도 같이 가져옴
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}
