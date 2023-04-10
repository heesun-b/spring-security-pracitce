package shop.mtcoding.security_app.model;

import java.time.LocalDateTime;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor // hibernate는 디폴트 생성자 필요
@Entity // Hibernate가 관리 (영속/비영속/준영속)
@Table(name = "user_tb")
@Getter
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private String email;
    private String role;
    private Boolean status; // 휴면 계정 유무

    // LocalDateTime을 사용하면 hibernate가 timestamp로 바꿔줌
    private LocalDateTime createdAt;
    private LocalDateTime updateAt;

    @Builder
    public User(Long id, String username, String password, String email, String role, Boolean status,
            LocalDateTime createdAt, LocalDateTime updateAt) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
        this.status = status;
        this.createdAt = createdAt;
        this.updateAt = updateAt;
    }

    @PrePersist // insert 시에 동작
    public void onCreate() {
        this.createdAt = LocalDateTime.now();
    }

    @PreUpdate // update 시에 동작
    public void onUpdate() {
        this.updateAt = LocalDateTime.now();
    }

}
