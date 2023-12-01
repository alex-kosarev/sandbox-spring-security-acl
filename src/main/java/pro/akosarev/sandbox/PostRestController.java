package pro.akosarev.sandbox;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/posts")
public class PostRestController {

    private final PostService postService;

    public PostRestController(PostService postService) {
        this.postService = postService;
    }

    @GetMapping
    public List<Post> findPosts() {
        return this.postService.findPosts();
    }

    @GetMapping("{id}")
    public Optional<Post> findPost(@PathVariable("id") UUID id) {
        return this.postService.findPost(id);
    }

    @PostMapping
    public ResponseEntity<Post> createPost(@RequestBody NewPostPayload payload, Authentication authentication) {
        var post = this.postService.createPost(payload.text(), authentication);
        return ResponseEntity
                .created(URI.create("http://localhost:8080/api/posts/%s".formatted(post.getId().toString())))
                .body(post);
    }
}
