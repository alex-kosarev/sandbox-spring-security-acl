package pro.akosarev.sandbox;

import lombok.AllArgsConstructor;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.CumulativePermission;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@AllArgsConstructor
public class PostService {

    private final JdbcClient jdbcClient;

    private final MutableAclService mutableAclService;

    private static final RowMapper<Post> POST_ROW_MAPPER = (rs, i) -> new Post(rs.getObject("id", UUID.class), rs.getString("c_text"));

    public Optional<Post> findPost(UUID id) {
        return this.jdbcClient.sql("select * from t_post where id = ?")
                .param(id)
                .query(POST_ROW_MAPPER)
                .optional();
    }

    // Мы хотим из полученных публикаций удалить те, к которым пользователь не имеет доступа
    @PostFilter("hasPermission(filterObject, 'READ')")
    public List<Post> findPosts() {
        return this.jdbcClient.sql("select * from t_post")
                .query(POST_ROW_MAPPER)
                .list();
    }

    // Изменение ACL требует наличия транзакции!
    @Transactional
    public Post createPost(String text, Authentication authentication) {
        var id = UUID.randomUUID();
        this.jdbcClient.sql("insert into t_post(id, c_text) values (?, ?)")
                .params(id, text)
                .update();

        Post post = new Post(id, text);

        // После создания объекта нужно создать ACL для него
        var acl = this.mutableAclService.createAcl(new ObjectIdentityImpl(post));

        // Разрешим чтение, удаление и администрирование
        acl.insertAce(0, new CumulativePermission()
                        .set(BasePermission.READ)
                        .set(BasePermission.DELETE)
                        .set(BasePermission.ADMINISTRATION),
                new PrincipalSid(authentication), true);

        // Обновим ACL
        this.mutableAclService.updateAcl(acl);

        return post;
    }
}
