# 6. Java配置

Spring 3.1在Spring Framework中添加了对[Java Configuration的](https://docs.spring.io/spring/docs/3.1.x/spring-framework-reference/html/beans.html#beans-java)一般支持。自Spring Security 3.2以来，Spring Security Java Configuration支持使用户无需使用任何XML即可轻松配置Spring Security。

如果您熟悉[第7章*安全命名空间配置，*](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#ns-config)那么您应该发现它与安全Java配置支持之间有很多相似之处。

![[注意]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/note.png) | Spring Security提供了[许多示例应用程序](https://github.com/spring-projects/spring-security/tree/master/samples/javaconfig)，用于演示Spring Security Java Configuration的使用。

## 6.1 Hello Web Security Java配置

第一步是创建Spring Security Java配置。该配置创建一个Servlet过滤器，称为`springSecurityFilterChain`负责应用程序内的所有安全性（保护应用程序URL，验证提交的用户名和密码，重定向到登录表单等）。您可以在下面找到Spring Security Java配置的最基本示例：

```java
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.authentication.builders.*;
import org.springframework.security.config.annotation.web.configuration.*;

@EnableWebSecurity
public class WebSecurityConfig implements WebMvcConfigurer {

    @Bean
    public UserDetailsService userDetailsService() throws Exception {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build());
        return manager;
    }
}
```

这种配置确实没什么用，但它做了很多。您可以在下面找到以下功能的摘要：

- 要求对应用程序中的每个URL进行身份验证

- 为您生成登录表单

- 允许具有**Username** *用户*和**密码** *密码*的用户使用基于表单的身份验证进行身份验证

- 允许用户注销

- [CSRF攻击](https://en.wikipedia.org/wiki/Cross-site_request_forgery)预防

- [会话固定](https://en.wikipedia.org/wiki/Session_fixation)保护

- 安全标头集成

  - 用于安全请求的 [HTTP严格传输安全性](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)
  - [X-Content-Type-Options](https://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx)集成
  - 缓存控制（稍后可由应用程序覆盖以允许缓存静态资源）
  - [X-XSS-Protection](https://msdn.microsoft.com/en-us/library/dd565647(v=vs.85).aspx)集成
  - X-Frame-Options集成有助于防止[Clickjacking](https://en.wikipedia.org/wiki/Clickjacking)

- 与以下Servlet API方法集成

  - [HttpServletRequest#getRemoteUser()](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#getRemoteUser())
  - [HttpServletRequest.html#getUserPrincipal()](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#getUserPrincipal())
  - [HttpServletRequest.html#isUserInRole(java.lang.String)](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#isUserInRole(java.lang.String))
  - [HttpServletRequest.html#login(java.lang.String, java.lang.String)](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#login(java.lang.String,%20java.lang.String))
  - [HttpServletRequest.html#logout()](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#logout())

  

### 6.1.1 AbstractSecurityWebApplicationInitializer

  下一步是注册`springSecurityFilterChain`战争。这可以在Java配置中使用[Spring的WebApplicationInitializer支持](https://docs.spring.io/spring/docs/3.2.x/spring-framework-reference/html/mvc.html#mvc-container-config)在Servlet 3.0+环境中完成。并不令人惊讶的是，Spring Security提供了一个基类`AbstractSecurityWebApplicationInitializer`，可以确保`springSecurityFilterChain`为您注册。我们使用的方式`AbstractSecurityWebApplicationInitializer`取决于我们是否已经使用Spring，或者Spring Security是否是我们应用程序中唯一的Spring组件。

  - [第6.1.2节“没有现有Spring的AbstractSecurityWebApplicationInitializer”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#abstractsecuritywebapplicationinitializer-without-existing-spring) - 如果您还没有使用Spring，请使用这些说明
  - [第6.1.3节“使用Spring MVC的AbstractSecurityWebApplicationInitializer”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#abstractsecuritywebapplicationinitializer-with-spring-mvc) - 如果您已经使用Spring，请使用这些说明

### 6.1.2没有现有Spring的AbstractSecurityWebApplicationInitializer

  如果您不使用Spring或Spring MVC，则需要将其`WebSecurityConfig`传入超类以确保获取配置。你可以在下面找到一个例子：

  ```java
  import org.springframework.security.web.context.*;
  
  public class SecurityWebApplicationInitializer
      extends AbstractSecurityWebApplicationInitializer {
  
  }
  ```

  这`SecurityWebApplicationInitializer`将做以下事情：

  - 自动为应用程序中的每个URL注册springSecurityFilterChain过滤器
  - 添加一个加载[WebSecurityConfig](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#jc-hello-wsca)的ContextLoaderListener。
### 6.1.3使用Spring MVC的AbstractSecurityWebApplicationInitializer

  如果我们在应用程序的其他地方使用Spring，我们可能已经有了`WebApplicationInitializer`加载Spring配置的东西。如果我们使用以前的配置，我们会收到错误。相反，我们应该使用现有的注册Spring Security `ApplicationContext`。例如，如果我们使用Spring MVC，我们`SecurityWebApplicationInitializer`将看起来如下所示：

```java
import org.springframework.security.web.context.*;

public class SecurityWebApplicationInitializer
    extends AbstractSecurityWebApplicationInitializer {

}
```

这只是为应用程序中的每个URL注册springSecurityFilterChain过滤器。之后，我们将确保`WebSecurityConfig`在现有的ApplicationInitializer中加载。例如，如果我们使用Spring MVC，它将被添加到`getRootConfigClasses()`

```java
public class MvcWebApplicationInitializer extends
        AbstractAnnotationConfigDispatcherServletInitializer {

    @Override
    protected Class<?>[] getRootConfigClasses() {
        return new Class[] { WebSecurityConfig.class };
    }

    // ... other overrides ...
}
```

## 6.2 HttpSecurity

到目前为止，我们的[WebSecurityConfig](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#jc-hello-wsca)仅包含有关如何验证用户身份的信息。Spring Security如何知道我们要求所有用户都经过身份验证？Spring Security如何知道我们想要支持基于表单的身份验证？这样做的原因是`WebSecurityConfigurerAdapter`在`configure(HttpSecurity http)`方法中提供了一个默认配置，如下所示：

```java
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
            .anyRequest().authenticated()
            .and()
        .formLogin()
            .and()
        .httpBasic();
}
```

上面的默认配置：

- 确保对我们的应用程序的任何请求都要求用户进行身份验证
- 允许用户使用基于表单的登录进行身份验证
- 允许用户使用HTTP基本身份验证进行身份验证

您会注意到此配置与XML命名空间配置非常相似：

```xml
<http>
    <intercept-url pattern="/**" access="authenticated"/>
    <form-login />
    <http-basic />
</http>
```

使用`and()`允许我们继续配置父标记的方法表示关闭XML标记的Java配置等效项。如果您阅读代码，它也是有道理的。我想配置授权请求*并*配置表单登录*并*配置HTTP基本身份验证。

## 6.3 Java配置和表单登录

当您被提示登录时，您可能想知道登录表单的来源，因为我们没有提及任何HTML文件或JSP。由于Spring Security的默认配置未明确设置登录页面的URL，因此Spring Security会根据启用的功能自动生成一个URL，并使用处理提交的登录的URL的标准值，用户将使用的默认目标URL登录后发送给等等。

虽然自动生成的登录页面便于快速启动和运行，但大多数应用程序都希望提供自己的登录页面。为此，我们可以更新我们的配置，如下所示：

```java
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
            .anyRequest().authenticated()
            .and()
        .formLogin()
            .loginPage("/login") //1
            .permitAll();        //2
}
```

- `//1`更新的配置指定登录页面的位置。
- `//2`我们必须授予所有用户（即未经身份验证的用户）访问我们的登录页面的权限。该`formLogin().permitAll()`方法允许为与基于表单的登录相关联的所有URL授予对所有用户的访问权限

使用JSP实现当前配置的示例登录页面如下所示：

 ![[注意]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/note.png) | 下面的登录页面代表我们当前的配置。如果某些默认设置不符合我们的需求，我们可以轻松更新配置。 



```java
<c:url value="/login" var="loginUrl"/>
<form action="${loginUrl}" method="post">       //1
    <c:if test="${param.error != null}">        //2
        <p>
            Invalid username and password.
        </p>
    </c:if>
    <c:if test="${param.logout != null}">       //3
        <p>
            You have been logged out.
        </p>
    </c:if>
    <p>
        <label for="username">Username</label>
        <input type="text" id="username" name="username"/>  //4
    </p>
    <p>
        <label for="password">Password</label>
        <input type="password" id="password" name="password"/>  //5
    </p>
    <input type="hidden"                        //6
        name="${_csrf.parameterName}"
        value="${_csrf.token}"/>
    <button type="submit" class="btn">Log in</button>
</form>
```



- `//1`对`/login`URL 的POST 将尝试对用户进行身份验证
- `//2`如果查询参数`error`存在，则尝试进行身份验证并失败

- `//3`如果查询参数`logout`存在，则用户已成功注销


- `//4`用户名必须作为名为*username*的HTTP参数出现

- `//5`密码必须作为名为*password*的HTTP参数出现


- `//6`我们必须[在“包含CSRF令牌”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#csrf-include-csrf-token)一[节中](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#csrf)了解更多信息，请参阅[第10.6节“跨站点请求伪造（CSRF）”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#csrf)部分的参考

## 6.4授权请求

我们的示例仅要求用户进行身份验证，并且已针对应用程序中的每个URL进行了身份验证。我们可以通过向`http.authorizeRequests()`方法添加多个子项来指定URL的自定义要求。例如：



```java
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()            // 1
            .antMatchers("/resources/**", "/signup", "/about").permitAll()    //2         
            .antMatchers("/admin/**").hasRole("ADMIN")    //3               
            .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')") //4
            .anyRequest().authenticated()      //5                             
            .and() 
        // ...
        .formLogin();
}
```

| 1                                                            | `http.authorizeRequests()`方法有多个子节点，每个匹配器按其声明的顺序进行考虑。 |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| 2 | 我们指定了任何用户都可以访问的多种URL模式。具体来说，如果URL以“/ resources /”开头，等于“/ signup”或等于“/ about”，则任何用户都可以访问请求。 |
| 3 | 任何以“/ admin /”开头的URL都将仅限于具有“ROLE_ADMIN”角色的用户。您会注意到，由于我们正在调用该`hasRole`方法，因此我们不需要指定“ROLE_”前缀。 |
| 4| 任何以“/ db /”开头的URL都要求用户同时拥有“ROLE_ADMIN”和“ROLE_DBA”。您会注意到，由于我们使用的是`hasRole`表达式，因此我们不需要指定“ROLE_”前缀。 |
| 5 | 任何尚未匹配的URL只需要对用户进行身份验证                    |

## 6.5处理注销

使用时`WebSecurityConfigurerAdapter`，会自动应用注销功能。默认情况下，访问URL `/logout`将通过以下方式记录用户：

- 使HTTP会话无效
- 清理已配置的任何RememberMe身份验证
- 清除 `SecurityContextHolder`
- 重定向到 `/login?logout`

但是，与配置登录功能类似，您还可以使用各种选项来进一步自定义注销要求：

```java
protected void configure(HttpSecurity http) throws Exception {
    http
        .logout()                                                               // 1
            .logoutUrl("/my/logout")                                            //     2
            .logoutSuccessUrl("/my/index")                                      //     3
            .logoutSuccessHandler(logoutSuccessHandler)                         //     4
            .invalidateHttpSession(true)                                        //     5
            .addLogoutHandler(logoutHandler)                                    //     6
            .deleteCookies(cookieNamesToClear)                                   //    7
            .and()
        ...
}
```



| 1 | 提供注销支持。使用时会自动应用此选项`WebSecurityConfigurerAdapter`。 |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| 2 | 触发注销的URL（默认为`/logout`）。如果启用了CSRF保护（默认），则该请求也必须是POST。有关更多信息，请参阅[JavaDoc](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/annotation/web/configurers/LogoutConfigurer.html#logoutUrl-java.lang.String-)。 |
| 3| 注销后重定向到的URL。默认是`/login?logout`。有关更多信息，请参阅[JavaDoc](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/annotation/web/configurers/LogoutConfigurer.html#logoutSuccessUrl-java.lang.String-)。 |
| 4 | 我们指定一个自定义`LogoutSuccessHandler`。如果指定了，`logoutSuccessUrl()`则忽略。有关更多信息，请参阅[JavaDoc](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/annotation/web/configurers/LogoutConfigurer.html#logoutSuccessHandler-org.springframework.security.web.authentication.logout.LogoutSuccessHandler-)。 |
| 5 | 指定`HttpSession`在注销时是否使其无效。默认情况下这是**真的**。配置`SecurityContextLogoutHandler`封面。有关更多信息，请参阅[JavaDoc](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/annotation/web/configurers/LogoutConfigurer.html#invalidateHttpSession-boolean-)。 |
| 6| 添加一个`LogoutHandler`。 默认情况下`SecurityContextLogoutHandler`添加为最后一个`LogoutHandler`。 |
| 7| 允许指定在注销成功时删除的cookie的名称。这是`CookieClearingLogoutHandler`显式添加的快捷方式。 |

 ![[注意]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/note.png) | ===当然也可以使用XML Namespace表示法配置注销。有关更多详细信息，请参阅Spring Security XML Namespace部分中[logout元素](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#nsa-logout)的文档。=== 

通常，为了自定义注销功能，您可以添加 `LogoutHandler` 和/或 `LogoutSuccessHandler` 实现。对于许多常见场景，使用流畅的API时，这些处理程序将在幕后应用。

### 6.5.1 LogoutHandler

通常，`LogoutHandler` 实现指示能够参与注销处理的类。预计将调用它们以进行必要的清理。因此，他们不应该抛出异常。提供了各种实现：

- [对PersistentTokenBasedRememberMeServices](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/authentication/rememberme/PersistentTokenBasedRememberMeServices.html)
- [TokenBasedRememberMeServices](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/authentication/rememberme/TokenBasedRememberMeServices.html)
- [CookieClearingLogoutHandler](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/authentication/logout/CookieClearingLogoutHandler.html)
- [CsrfLogoutHandler](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/csrf/CsrfLogoutHandler.html)
- [SecurityContextLogoutHandler](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/authentication/logout/SecurityContextLogoutHandler.html)
- [HeaderWriterLogoutHandler](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/authentication/logout/HeaderWriterLogoutHandler.html)

有关详细信息[，](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#remember-me-impls)请参见[第10.5.4节“记住我的接口和实现”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#remember-me-impls)。

而不是`LogoutHandler`直接提供实现，流畅的API还提供了快捷方式，提供了各自的`LogoutHandler`实现。例如，`deleteCookies()`允许指定在注销成功时要删除的一个或多个cookie的名称。与添加a相比，这是一个捷径`CookieClearingLogoutHandler`。

### 6.5.2 LogoutSuccessHandler

该`LogoutSuccessHandler`被成功注销后调用`LogoutFilter`，来处理如重定向或转发到相应的目的地。请注意，界面几乎与该界面相同，`LogoutHandler`但可能引发异常。

提供以下实现：

- [SimpleUrlLogoutSuccessHandler](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/authentication/logout/SimpleUrlLogoutSuccessHandler.html)
- HttpStatusReturningLogoutSuccessHandler

如上所述，您无需`SimpleUrlLogoutSuccessHandler`直接指定。相反，流畅的API通过设置提供快捷方式`logoutSuccessUrl()`。这将设置`SimpleUrlLogoutSuccessHandler`封底。发生注销后，提供的URL将重定向到。默认是`/login?logout`。

本`HttpStatusReturningLogoutSuccessHandler`可以在REST API类型场景有趣。成功注销后，`LogoutSuccessHandler`不允许重定向到URL，而是允许您提供要返回的纯HTTP状态代码。如果未配置，则默认情况下将返回状态代码200。

### 6.5.3进一步注销相关参考

- [注销处理](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#ns-logout)
- [测试注销](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#test-logout)
- [HttpServletRequest.logout（）](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#servletapi-logout)
- [第10.5.4节“记住我的接口和实现”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#remember-me-impls)
- [登录](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#csrf-logout) CSRF警告部分
- 部分[单点注销](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#cas-singlelogout)（CAS协议）
- Spring Security XML Namespace部分中 [logout元素的](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#nsa-logout) 文档

## 6.6 OAuth 2.0客户端

OAuth 2.0客户端功能为[OAuth 2.0授权框架中](https://tools.ietf.org/html/rfc6749#section-1.1)定义的客户端角色提供支持。

可以使用以下主要功能：

- [授权代码授予](https://tools.ietf.org/html/rfc6749#section-1.3.1)
- [客户凭证授权](https://tools.ietf.org/html/rfc6749#section-1.3.4)
- [`WebClient`Servlet环境的扩展](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#servlet-webclient)（用于创建受保护的资源请求）

`HttpSecurity.oauth2Client()`提供了许多用于自定义OAuth 2.0 Client的配置选项。以下代码显示了可用于`oauth2Client()`DSL 的完整配置选项：

```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .oauth2Client()
                .clientRegistrationRepository(this.clientRegistrationRepository())
                .authorizedClientRepository(this.authorizedClientRepository())
                .authorizedClientService(this.authorizedClientService())
                .authorizationCodeGrant()
                    .authorizationRequestRepository(this.authorizationRequestRepository())
                    .authorizationRequestResolver(this.authorizationRequestResolver())
                    .accessTokenResponseClient(this.accessTokenResponseClient());
    }
}
```

以下部分详细介绍了每个可用的配置选项：

- [第6.6.1节“ClientRegistration”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-client-registration)
- [第6.6.2节“ClientRegistrationRepository”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-client-registration-repo)
- [第6.6.3节“OAuth2AuthorizedClient”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-authorized-client)
- [第6.6.4节“OAuth2AuthorizedClientRepository / OAuth2AuthorizedClientService”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-authorized-repo-service)
- [第6.6.5节“RegisteredOAuth2AuthorizedClient”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-registered-authorized-client)
- [第6.6.6节“AuthorizationRequestRepository”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-authorization-request-repository)
- [第6.6.7节“OAuth2AuthorizationRequestResolver”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-authorization-request-resolver)
- [第6.6.8节“OAuth2AccessTokenResponseClient”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-access-token-client)

### 6.6.1 ClientRegistration

`ClientRegistration` 表示在OAuth 2.0或OpenID Connect 1.0提供程序中注册的客户端。

客户端注册保存信息，例如客户端ID，客户端密钥，授权授权类型，重定向URI，范围，授权URI，令牌URI和其他详细信息。

`ClientRegistration` 其属性定义如下：



```java
public final class ClientRegistration {
    private String registrationId;  //1
    private String clientId;    //2
    private String clientSecret;   // 3
    private ClientAuthenticationMethod clientAuthenticationMethod;  //4
    private AuthorizationGrantType authorizationGrantType; // 5
    private String redirectUriTemplate;// 6
    private Set<String> scopes; //7
    private ProviderDetails providerDetails;
    private String clientName; // 8

    public class ProviderDetails {
        private String authorizationUri;   // 9
        private String tokenUri;   // 10
        private UserInfoEndpoint userInfoEndpoint;
        private String jwkSetUri;  // 11
        private Map<String, Object> configurationMetadata; // 12

        public class UserInfoEndpoint {
            private String uri;// 13
            private AuthenticationMethod authenticationMethod;//  14
            private String userNameAttributeName; //  15

        }
    }
}
```

| 1| `registrationId`：唯一标识的ID `ClientRegistration`。        |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| 2 | `clientId`：客户端标识符。                                   |
| 3 | `clientSecret`：客户的秘密。                                 |
|4 | `clientAuthenticationMethod`：用于使用Provider对客户端进行身份验证的方法。支持的值是**基本**和**后期**。 |
| 5| `authorizationGrantType`：OAuth 2.0授权框架定义了四种[授权授权](https://tools.ietf.org/html/rfc6749#section-1.3)类型。支持的值是authorization_code，implicit和client_credentials。 |
| 6 | `redirectUriTemplate`：客户端的注册重定向URI，*授权服务器*将最终用户的用户代理重定向到最终用户对客户端进行身份验证和授权访问之后。 |
| 7| `scopes`：客户端在授权请求流程中请求的范围，例如openid，电子邮件或配置文件。 |
| 8 | `clientName`：用于客户端的描述性名称。该名称可能在某些情况下使用，例如在自动生成的登录页面中显示客户端的名称时。 |
|9 | `authorizationUri`：授权服务器的授权端点URI。                |
| 10| `tokenUri`：授权服务器的令牌端点URI。                        |
| 11 | `jwkSetUri`：用于从授权服务器检索[JSON Web密钥（JWK）](https://tools.ietf.org/html/rfc7517)集的URI ，其包含用于验证ID令牌的[JSON Web签名（JWS）](https://tools.ietf.org/html/rfc7515)以及可选的UserInfo响应的加密密钥。 |
| 12 | `configurationMetadata`：[OpenID提供程序配置信息](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig)。仅当`spring.security.oauth2.client.provider.[providerId].issuerUri`配置了Spring Boot 2.x属性时，才能使用此信息。 |
|13| `(userInfoEndpoint)uri`：UserInfo端点URI，用于访问经过身份验证的最终用户的声明/属性。 |
| 14| `(userInfoEndpoint)authenticationMethod`：将访问令牌发送到UserInfo端点时使用的身份验证方法。支持的值是**标题**，**表单**和**查询**。 |
| 15 | `userNameAttributeName`：UserInfo响应中返回的属性的名称，该属性引用最终用户的名称或标识符。 |

### 6.6.2 ClientRegistrationRepository

它`ClientRegistrationRepository`充当OAuth 2.0 / OpenID Connect 1.0的存储库`ClientRegistration`。

 ![[注意]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/note.png) | 客户端注册信息最终由关联的授权服务器存储和拥有。此存储库提供检索主客户端注册信息的子集的功能，该子集与授权服务器一起存储。 

Spring Boot 2.x自动配置将每个属性绑定到一个实例，然后组成一个实例中的每个实例。`spring.security.oauth2.client.registration.*[registrationId]*``ClientRegistration``ClientRegistration``ClientRegistrationRepository`

 ![[注意]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/note.png) | 默认实现`ClientRegistrationRepository`是`InMemoryClientRegistrationRepository`。 

如果应用程序需要，自动配置还会将其注册`ClientRegistrationRepository`为a `@Bean`，`ApplicationContext`以便可用于依赖注入。

以下清单显示了一个示例：

```java
@Controller
public class OAuth2ClientController {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @RequestMapping("/")
    public String index() {
        ClientRegistration googleRegistration =
            this.clientRegistrationRepository.findByRegistrationId("google");

        ...

        return "index";
    }
}
```

### 6.6.3 OAuth2AuthorizedClient

`OAuth2AuthorizedClient`是授权客户的代表。当最终用户（资源所有者）已授权客户端访问其受保护资源时，将认为客户端已获得授权。

`OAuth2AuthorizedClient`用于将`OAuth2AccessToken`（和可选的`OAuth2RefreshToken`）关联到`ClientRegistration`（客户端）和资源所有者，该`Principal`用户是授予授权的最终用户。

### 6.6.4 OAuth2AuthorizedClientRepository / OAuth2AuthorizedClientService

`OAuth2AuthorizedClientRepository`负责`OAuth2AuthorizedClient`在Web请求之间保持持久性。然而，主要作用`OAuth2AuthorizedClientService`是`OAuth2AuthorizedClient`在应用程序级别进行管理。

从开发人员的角度来看，`OAuth2AuthorizedClientRepository`或`OAuth2AuthorizedClientService`提供查找`OAuth2AccessToken`与客户端关联的功能，以便可以使用它来启动受保护的资源请求。



 ![[注意]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/note.png)| Spring Boot2.X自动配置寄存器的`OAuth2AuthorizedClientRepository`和/或`OAuth2AuthorizedClientService` `@Bean`在`ApplicationContext`。



开发者还可注册一个`OAuth2AuthorizedClientRepository`或`OAuth2AuthorizedClientService` `@Bean`在`ApplicationContext`（覆盖弹簧引导2.x的自动配置）以便具有查找一个的能力`OAuth2AccessToken`与特定关联`ClientRegistration`（客户端）。

以下清单显示了一个示例：

```java
@Controller
public class OAuth2LoginController {

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @RequestMapping("/userinfo")
    public String userinfo(OAuth2AuthenticationToken authentication) {
        // authentication.getAuthorizedClientRegistrationId() returns the
        // registrationId of the Client that was authorized during the oauth2Login() flow
        OAuth2AuthorizedClient authorizedClient =
            this.authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName());

        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();

        ...

        return "userinfo";
    }
}
```

### 6.6.5 RegisteredOAuth2AuthorizedClient

所述`@RegisteredOAuth2AuthorizedClient`注释提供解决方法参数，以类型的参数值的能力`OAuth2AuthorizedClient`。与通过查找`OAuth2AuthorizedClient`通道相比，这是一种方便的替代方案`OAuth2AuthorizedClientService`。

```java
@Controller
public class OAuth2LoginController {

    @RequestMapping("/userinfo")
    public String userinfo(@RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient authorizedClient) {
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();

        ...

        return "userinfo";
    }
}
```

该`@RegisteredOAuth2AuthorizedClient`注释被处理`OAuth2AuthorizedClientArgumentResolver`，并提供以下功能：

- 一个`OAuth2AccessToken`如果客户尚未授权将自动请求。
  - 因为`authorization_code`，这涉及触发授权请求重定向以启动流程
  - 因为`client_credentials`，使用令牌端点直接获取访问令牌`DefaultClientCredentialsTokenResponseClient`

### 6.6.6 AuthorizationRequestRepository

`AuthorizationRequestRepository`负责`OAuth2AuthorizationRequest`从启动授权请求到收到授权响应（回调）的持续时间。

 ![[小费]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/tip.png) | 将`OAuth2AuthorizationRequest`被用来关联和验证授权响应。

默认实现`AuthorizationRequestRepository`是`HttpSessionOAuth2AuthorizationRequestRepository`，它存储`OAuth2AuthorizationRequest`在`HttpSession`。

如果你想提供一个自定义实现`AuthorizationRequestRepository`存储的属性`OAuth2AuthorizationRequest`中`Cookie`，你可以配置它，如下面的例子：



```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .oauth2Client()
                .authorizationCodeGrant()
                    .authorizationRequestRepository(this.cookieAuthorizationRequestRepository())
                    ...
    }

    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> cookieAuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }
}
```

### 6.6.7 OAuth2AuthorizationRequestResolver

该主要角色`OAuth2AuthorizationRequestResolver`是`OAuth2AuthorizationRequest`从提供的Web请求中解析一个。默认实现`DefaultOAuth2AuthorizationRequestResolver`匹配（默认）路径`/oauth2/authorization/{registrationId}`提取`registrationId`并使用它来构建`OAuth2AuthorizationRequest`关联的路径`ClientRegistration`。

`OAuth2AuthorizationRequestResolver`可以实现的主要用例之一是能够使用超出OAuth 2.0授权框架中定义的标准参数的附加参数来定制授权请求。

例如，OpenID Connect为[授权代码流](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)定义了额外的OAuth 2.0请求参数，这些参数扩展自[OAuth 2.0授权框架中](https://tools.ietf.org/html/rfc6749#section-4.1.1)定义的标准参数。其中一个扩展参数是`prompt`参数。

![[注意]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/note.png) | 可选的。空格分隔，区分大小写的ASCII字符串值列表，指定授权服务器是否提示最终用户进行重新认证和同意。定义的值为：none，login，consent，select_account

以下示例显示如何通过包含请求参数来实现`OAuth2AuthorizationRequestResolver`自定义授权请求的方法。`oauth2Login()``prompt=consent`



```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .oauth2Login()
                .authorizationEndpoint()
                    .authorizationRequestResolver(
                            new CustomAuthorizationRequestResolver(
                                    this.clientRegistrationRepository));    //1
    }
}

public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
    private final OAuth2AuthorizationRequestResolver defaultAuthorizationRequestResolver;

    public CustomAuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        this.defaultAuthorizationRequestResolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository, "/oauth2/authorization");
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest authorizationRequest =
                this.defaultAuthorizationRequestResolver.resolve(request); // 2

        return authorizationRequest != null ? //  3
                customAuthorizationRequest(authorizationRequest) :
                null;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(
            HttpServletRequest request, String clientRegistrationId) {

        OAuth2AuthorizationRequest authorizationRequest =
                this.defaultAuthorizationRequestResolver.resolve(
                    request, clientRegistrationId);  //  4

        return authorizationRequest != null ?  // 5
                customAuthorizationRequest(authorizationRequest) :
                null;
    }

    private OAuth2AuthorizationRequest customAuthorizationRequest(
            OAuth2AuthorizationRequest authorizationRequest) {

        Map<String, Object> additionalParameters =
                new LinkedHashMap<>(authorizationRequest.getAdditionalParameters());
        additionalParameters.put("prompt", "consent"); // 6

        return OAuth2AuthorizationRequest.from(authorizationRequest)  //  7
                .additionalParameters(additionalParameters)// 8
                .build();
    }
}
```

| [![1](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/callouts/1.png)](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#CO6-1) | 配置自定义 `OAuth2AuthorizationRequestResolver`              |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| [![2](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/callouts/2.png)](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#CO6-2) [![4](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/callouts/4.png)](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#CO6-4) | 尝试解决`OAuth2AuthorizationRequest`使用问题`DefaultOAuth2AuthorizationRequestResolver` |
| [![3](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/callouts/3.png)](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#CO6-3) [![五](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/callouts/5.png)](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#CO6-5) | 如果`OAuth2AuthorizationRequest`已解决而不是返回自定义版本，则返回`null` |
| [![6](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/callouts/6.png)](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#CO6-6) | 将自定义参数添加到现有参数 `OAuth2AuthorizationRequest.additionalParameters` |
| [![7](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/callouts/7.png)](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#CO6-7) | 创建默认值的副本，该副本`OAuth2AuthorizationRequest`返回以`OAuth2AuthorizationRequest.Builder`进行进一步修改 |
| [![8](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/callouts/8.png)](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#CO6-8) | 覆盖默认值 `additionalParameters`                            |



![[小费]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/tip.png)| `OAuth2AuthorizationRequest.Builder.build()`构造`OAuth2AuthorizationRequest.authorizationRequestUri`，表示完整的授权请求URI，包括使用该`application/x-www-form-urlencoded`格式的所有查询参数。

上面的示例显示了在标准参数之上添加自定义参数的常见用例。但是，如果您需要删除或更改标准参数或者您的要求更高级，则可以通过简单地覆盖`OAuth2AuthorizationRequest.authorizationRequestUri`属性来完全控制构建授权请求URI 。

以下示例显示了`customAuthorizationRequest()`前一示例中方法的变体，而是覆盖了该`OAuth2AuthorizationRequest.authorizationRequestUri`属性。

```java
private OAuth2AuthorizationRequest customAuthorizationRequest(
        OAuth2AuthorizationRequest authorizationRequest) {

    String customAuthorizationRequestUri = UriComponentsBuilder
            .fromUriString(authorizationRequest.getAuthorizationRequestUri())
            .queryParam("prompt", "consent")
            .build(true)
            .toUriString();

    return OAuth2AuthorizationRequest.from(authorizationRequest)
            .authorizationRequestUri(customAuthorizationRequestUri)
            .build();
}
```

### 6.6.8 OAuth2AccessTokenResponseClient

主要角色`OAuth2AccessTokenResponseClient`是在授权服务器的令牌端点处为访问令牌凭证交换授权授予凭证。

默认实现`OAuth2AccessTokenResponseClient`的`authorization_code`补助`DefaultAuthorizationCodeTokenResponseClient`，它采用`RestOperations`了在令牌端点访问令牌交换一个授权码。

的`DefaultAuthorizationCodeTokenResponseClient`，因为它允许您自定义的令牌响应的令牌请求和/或装卸后的前处理非常灵活。

如果您需要自定义令牌请求的预处理，则可以提供`DefaultAuthorizationCodeTokenResponseClient.setRequestEntityConverter()`自定义`Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>>`。默认实现`OAuth2AuthorizationCodeGrantRequestEntityConverter`构建`RequestEntity`标准[OAuth 2.0访问令牌请求的表示](https://tools.ietf.org/html/rfc6749#section-4.1.3)。但是，提供自定义`Converter`将允许您扩展标准令牌请求并添加自定义参数。

![[重要]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/important.png) | 重要 | 自定义`Converter`必须返回`RequestEntity`预期OAuth 2.0提供程序可以理解的OAuth 2.0访问令牌请求的有效表示。

另一方面，如果您需要自定义令牌响应的后处理，则需要提供`DefaultAuthorizationCodeTokenResponseClient.setRestOperations()`自定义配置`RestOperations`。默认`RestOperations`配置如下：



```java
RestTemplate restTemplate = new RestTemplate(Arrays.asList(
        new FormHttpMessageConverter(),
        new OAuth2AccessTokenResponseHttpMessageConverter()));

restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
```

![[小费]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/tip.png) | `FormHttpMessageConverter`在发送OAuth 2.0访问令牌请求时使用Spring MVC 是必需的。

```
OAuth2AccessTokenResponseHttpMessageConverter`是一个`HttpMessageConverter`OAuth 2.0访问令牌响应。您可以提供用于将OAuth 2.0访问令牌响应参数转换为`OAuth2AccessTokenResponseHttpMessageConverter.setTokenResponseConverter()`的自定义。`Converter<Map<String, String>, OAuth2AccessTokenResponse>``OAuth2AccessTokenResponse
```

`OAuth2ErrorResponseErrorHandler`是一个`ResponseErrorHandler`可以处理OAuth 2.0错误（400错误请求）。它`OAuth2ErrorHttpMessageConverter`用于将OAuth 2.0 Error参数转换为`OAuth2Error`。

无论您是自定义`DefaultAuthorizationCodeTokenResponseClient`还是提供自己的实现`OAuth2AccessTokenResponseClient`，都需要对其进行配置，如以下示例所示：

```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .oauth2Client()
                .authorizationCodeGrant()
                    .accessTokenResponseClient(this.customAccessTokenResponseClient())
                    ...
    }

    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> customAccessTokenResponseClient() {
        ...
    }
}
```

## 6.7 OAuth 2.0登录

OAuth 2.0登录功能为应用程序提供了使用OAuth 2.0提供程序（例如GitHub）或OpenID Connect 1.0提供程序（例如Google）上的现有帐户登录应用程序的功能。OAuth 2.0 Login实现了用例：“使用Google登录”或“使用GitHub登录”。

 ![[注意]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/note.png) | OAuth 2.0登录是使用**授权代码授予实现的**，如[OAuth 2.0授权框架](https://tools.ietf.org/html/rfc6749#section-4.1)和[OpenID Connect Core 1.0中所指定](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)。

### 6.7.1 Spring Boot 2.x示例

Spring Boot 2.x为OAuth 2.0登录带来了完整的自动配置功能。

本部分介绍如何使用*Google*作为*身份验证提供程序*配置[**OAuth 2.0登录示例，**](https://github.com/spring-projects/spring-security/tree/master/samples/boot/oauth2login)并介绍以下主题：

- [初始设置](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2login-sample-initial-setup)
- [设置重定向URI](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2login-sample-redirect-uri)
- [配置application.yml](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2login-sample-application-config)
- [启动应用程序](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2login-sample-boot-application)

#### 初始设置

要使用Google的OAuth 2.0身份验证系统进行登录，您必须在Google API控制台中设置项目以获取OAuth 2.0凭据。

![[注意]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/note.png) | [Google的OAuth 2.0](https://developers.google.com/identity/protocols/OpenIDConnect)身份验证[实施](https://developers.google.com/identity/protocols/OpenIDConnect)符合[OpenID Connect 1.0](https://openid.net/connect/)规范，并通过[OpenID认证](https://openid.net/certification/)。

按照[OpenID Connect](https://developers.google.com/identity/protocols/OpenIDConnect)页面上的说明操作，从“设置OAuth 2.0”部分开始。

完成“获取OAuth 2.0凭据”说明后，您应该拥有一个新的OAuth客户端，其凭据包含客户端ID和客户端密钥。

#### 设置重定向URI

重定向URI是应用程序中的路径，最终用户的用户代理在通过Google进行身份验证并在“同意”页面上授予了对OAuth客户端*（在上一步中创建）的*访问权限后重定向回的路径。

在“设置重定向URI”子部分中，确保将“ **授权重定向URI”**字段设置为`http://localhost:8080/login/oauth2/code/google`。

![[小费]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/tip.png)| 默认的重定向URI模板是`{baseUrl}/login/oauth2/code/{registrationId}`。该**registrationId**是用于唯一标识符[ClientRegistration](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-client-registration)。

#### 配置application.yml

既然您有一个新的OAuth客户端与Google，您需要配置应用程序以使用OAuth客户端进行*身份验证流程*。为此：

1. 转到`application.yml`并设置以下配置：

```java
spring:
  security:
    oauth2:
      client:
        registration:  // 1
          google:  // 2
            client-id: google-client-id
            client-secret: google-client-secret
```

**例6.1。OAuth客户端属性**

| [![1](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/callouts/1.png)](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#CO7-1) | `spring.security.oauth2.client.registration` 是OAuth客户端属性的基本属性前缀。 |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| [![2](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/callouts/2.png)](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#CO7-2) | 基本属性前缀后面是[ClientRegistration](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-client-registration)的ID ，例如google。 |

1. 使用您之前创建的OAuth 2.0凭据替换`client-id`and `client-secret`属性中的值。

#### 启动应用程序

启动Spring Boot 2.x示例并转到`http://localhost:8080`。然后，您将被重定向到默认的*自动生成的*登录页面，该页面显示Google的链接。

点击Google链接，然后您将重定向到Google进行身份验证。

使用您的Google帐户凭据进行身份验证后，显示给您的下一页是“同意”屏幕。“同意”屏幕会要求您允许或拒绝访问您之前创建的OAuth客户端。单击“ **允许”**以授权OAuth客户端访问您的电子邮件地址和基本配置文件信息。

此时，OAuth客户端从[UserInfo端点](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)检索您的电子邮件地址和基本配置文件信息，并建立经过身份验证的会话。

### 6.7.2 Spring Boot 2.x属性映射

下表概述了Spring Boot 2.x OAuth客户端属性到[ClientRegistration](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-client-registration)属性的映射。

| Spring Boot 2.x                                              | ClientRegistration                                       |
| ------------------------------------------------------------ | -------------------------------------------------------- |
| `spring.security.oauth2.client.registration.*[registrationId]*` | `registrationId`                                         |
| `spring.security.oauth2.client.registration.*[registrationId]*.client-id` | `clientId`                                               |
| `spring.security.oauth2.client.registration.*[registrationId]*.client-secret` | `clientSecret`                                           |
| `spring.security.oauth2.client.registration.*[registrationId]*.client-authentication-method` | `clientAuthenticationMethod`                             |
| `spring.security.oauth2.client.registration.*[registrationId]*.authorization-grant-type` | `authorizationGrantType`                                 |
| `spring.security.oauth2.client.registration.*[registrationId]*.redirect-uri` | `redirectUriTemplate`                                    |
| `spring.security.oauth2.client.registration.*[registrationId]*.scope` | `scopes`                                                 |
| `spring.security.oauth2.client.registration.*[registrationId]*.client-name` | `clientName`                                             |
| `spring.security.oauth2.client.provider.*[providerId]*.authorization-uri` | `providerDetails.authorizationUri`                       |
| `spring.security.oauth2.client.provider.*[providerId]*.token-uri` | `providerDetails.tokenUri`                               |
| `spring.security.oauth2.client.provider.*[providerId]*.jwk-set-uri` | `providerDetails.jwkSetUri`                              |
| `spring.security.oauth2.client.provider.*[providerId]*.user-info-uri` | `providerDetails.userInfoEndpoint.uri`                   |
| `spring.security.oauth2.client.provider.*[providerId]*.user-info-authentication-method` | `providerDetails.userInfoEndpoint.authenticationMethod`  |
| `spring.security.oauth2.client.provider.*[providerId]*.userNameAttribute` | `providerDetails.userInfoEndpoint.userNameAttributeName` |

### 6.7.3 CommonOAuth2Provider

`CommonOAuth2Provider` 为许多知名提供商预定义一组默认客户端属性：Google，GitHub，Facebook和Okta。

例如，`authorization-uri`，`token-uri`，和`user-info-uri`不经常对供应商变更。因此，提供默认值以减少所需配置是有意义的。

如前所述，当我们[配置Google客户端时](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2login-sample-application-config)，只需要`client-id`和`client-secret`属性。

以下清单显示了一个示例：

```yml
spring：
   security：
     oauth2：
       client：
         registration：
           google：
             client-id：google-client-id
             client-secret：google-client-secret
```

![[小费]](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/tip.png) | 客户端属性的自动默认无缝地在这里工作，因为`registrationId`（`google`）匹配`GOOGLE` `enum`（不区分大小写）in `CommonOAuth2Provider`。

对于您可能希望指定其他内容的情况`registrationId`，例如`google-login`，您仍然可以通过配置属性来利用客户端属性的自动默认`provider`。

以下清单显示了一个示例：

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google-login: //1
            provider: google   // 2
            client-id: google-client-id
            client-secret: google-client-secret
```

| [![1](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/callouts/1.png)](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#CO8-1) | 该`registrationId`设置为`google-login`。                     |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| [![2](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/images/callouts/2.png)](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#CO8-2) | 该`provider`属性设置为`google`，将利用设置的客户端属性的自动默认值`CommonOAuth2Provider.GOOGLE.getBuilder()`。 |

