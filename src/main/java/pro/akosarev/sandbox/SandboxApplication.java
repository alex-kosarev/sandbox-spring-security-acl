package pro.akosarev.sandbox;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

import javax.sql.DataSource;

// Включить кэширование, требуется для ACL
@EnableCaching
// Включить безопасность методов для поддержки аннотаций @PreAuthorize, @PostAuthorize, @PreFilter, @PostFilter
@EnableMethodSecurity
@SpringBootApplication
public class SandboxApplication {

    public static void main(String[] args) {
        SpringApplication.run(SandboxApplication.class, args);
    }

    @Bean
    DefaultPermissionFactory permissionFactory() {
        // Использование собственных разрешений
        return new DefaultPermissionFactory(FlipTablePermission.class);
    }

    @Bean
    MutableAclService mutableAclService(DataSource dataSource, CacheManager cacheManager,
                                        DefaultPermissionFactory permissionFactory) {
        // Стратегия авторизации в ACL определяет, кто и как может изменять ACL глобально
        // В данной ситуации полные права предоставляются пользователям с правом ROLE_ADMIN
        var aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_ADMIN"));

        // Логгер аудита (да, System.out)
        var auditLogger = new ConsoleAuditLogger();

        // Стратегия авторизации, позволяющая использовать кумулятивные разрешения, агрегирующие в себе несколько обычных
        var permissionGrantingStrategy = new CumulativePermissionGrantingStrategy(auditLogger);

        // Кэш ACL
        var aclCache = new SpringCacheBasedAclCache(cacheManager.getCache("security/acl"),
                permissionGrantingStrategy, aclAuthorizationStrategy);

        // Стратегия поиска ACL
        var lookupStrategy = new BasicLookupStrategy(dataSource, aclCache, aclAuthorizationStrategy,
                permissionGrantingStrategy);
        // Принудительное использование информации о типе идентификаторов сущностей из БД
        lookupStrategy.setAclClassIdSupported(true);
        lookupStrategy.setPermissionFactory(permissionFactory);

        // Собственно ACL-сервис
        var mutableAclService = new JdbcMutableAclService(dataSource, lookupStrategy, aclCache);

        // Запрос на получение идентификатора созданной записи в acl_class
        mutableAclService.setClassIdentityQuery("select currval('acl_class_id_seq')");
        // Запрос на получение идентификатора созданной записи в acl_sid
        mutableAclService.setSidIdentityQuery("select currval('acl_sid_id_seq')");
        // Принудительное использование информации о типе идентификаторов сущностей из БД
        mutableAclService.setAclClassIdSupported(true);

        return mutableAclService;
    }

    @Bean
    AclPermissionEvaluator permissionEvaluator(MutableAclService aclService,
                                               DefaultPermissionFactory permissionFactory) {
        // Компонент для определения прав в SPEL взамен стандартному DenyAppPermissionEvaluator
        AclPermissionEvaluator aclPermissionEvaluator = new AclPermissionEvaluator(aclService);
        aclPermissionEvaluator.setPermissionFactory(permissionFactory);
        return aclPermissionEvaluator;
    }

    @Bean
    DefaultHttpSecurityExpressionHandler httpSecurityExpressionHandler(AclPermissionEvaluator permissionEvaluator,
                                                                       ApplicationContext applicationContext) {
        // Компонент для обработки SPEL-выражений для HTTP-безопасности
        var defaultHttpSecurityExpressionHandler = new DefaultHttpSecurityExpressionHandler();
        defaultHttpSecurityExpressionHandler.setPermissionEvaluator(permissionEvaluator);
        defaultHttpSecurityExpressionHandler.setApplicationContext(applicationContext);
        return defaultHttpSecurityExpressionHandler;
    }

    @Bean
    DefaultMethodSecurityExpressionHandler methodSecurityExpressionHandler(AclPermissionEvaluator permissionEvaluator,
                                                                           ApplicationContext applicationContext) {
        // Компонент для обработки SPEL-выражений для безопасности методов
        // В отличие от DefaultHttpSecurityExpressionHandler он внедряется сам в зависимые объекты
        var defaultHttpSecurityExpressionHandler = new DefaultMethodSecurityExpressionHandler();
        defaultHttpSecurityExpressionHandler.setPermissionEvaluator(permissionEvaluator);
        defaultHttpSecurityExpressionHandler.setApplicationContext(applicationContext);
        return defaultHttpSecurityExpressionHandler;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, DefaultHttpSecurityExpressionHandler expressionHandler) throws Exception {
        // Менеджер авторизации, определяющий доступ на основе SPEL-выражения
        WebExpressionAuthorizationManager manager = new WebExpressionAuthorizationManager(
                // Проверяем, что текущий пользователь имеет право FLIP_TABLE на экземпляр класса pro.akosarev.sandbox.Post с идентификатором #id
                // T(java.util.UUID) позволяет обращаться к статическим свойствам и методам класса java.util.UUID
                // Тип идентификатора у pro.akosarev.sandbox.Post - java.util.UUID, а здесь #id - экземпляр java.lang.String,
                // нам необходимо преобразовать его при помощи T(java.util.UUID).fromString(#id), в противном случае мы
                // получим ошибку доступа
                "hasPermission(T(java.util.UUID).fromString(#id), 'pro.akosarev.sandbox.Post', 'FLIP_TABLE')");
        manager.setExpressionHandler(expressionHandler);

        return http
                .httpBasic(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                        .requestMatchers("/api/posts/{id}").access(manager)
                        .anyRequest().authenticated())
                .build();
    }
}
