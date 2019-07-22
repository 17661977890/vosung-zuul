package com.vosung.zuul.apifilter;

import com.vosung.zuul.constants.RedisUtil;
import com.vosung.zuul.constants.SecurityConstants;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.vosung.zuul.properties.PermitAllUrlProperties;
import com.vosung.zuul.vo.RoleVo;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.netflix.zuul.filters.Route;
import org.springframework.cloud.netflix.zuul.filters.SimpleRouteLocator;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import javax.servlet.http.HttpServletRequest;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Zuul 请求过滤(配置过滤器)
 * 它实现了在请求路由之前检查
 * @author 彬
 */
@Slf4j
public class AccessFilter extends ZuulFilter {

    @Autowired
    public SimpleRouteLocator simpleRouteLocator;
    @Autowired
    private PermitAllUrlProperties permitAllUrlProperties;
    @Autowired
    private RedisUtil redisUtil;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    private static final String ANONYMOUS_USER_ID = "d4a65d04-a5a3-465c-8408-405971ac3346";

    private static final String USER_HOLDER = "UserHolder";
    //系统管理员角色code
    private static final String SYS_ADMIN ="SYS_ADMIN";

    /**
     * 过滤器类型:决定过滤器在请求的那个生命周期执行，这里定义为pre 代表请求会在路由之前执行
     * @return
     */
    @Override
    public String filterType() {
        return "pre";
    }

    /**
     * 过滤器的执行顺序（存在多个过滤器时，需要根据该方法的返回值来依次执行）
     * 注意设置顺序时不要设置Ordered.HIGHEST_PRECEDENCE ----会报控制指针异常
     * （其余数值没有试过，在截取路径的时候，貌似有其他过滤器会根据配置文件配置的路由转发的path来截取，如果让那个过滤器滞后，会按照/zuul来截取就会报错，打断点调试）
     * @return
     */
    @Override
    public int filterOrder() {
        return 0;
    }

    /**
     * 判断过滤器是否需要被执行，这里直接返回true，即会过滤所有请求。可以通过方法来指定有效过滤器的范围
     *
     * 比如：登录请求不需要过滤
     * 请求要加请求头Authorization：Basic ZnJvbnRlbmQ6ZnJvbnRlbmQ=  存放的clientId和clientSecret经过编码的字符串。
     * 首先执行获取授权的endpoint
     * @return
     */
    @Override
    public boolean shouldFilter() {

        RequestContext requestContext = RequestContext.getCurrentContext();
        HttpServletRequest request = requestContext.getRequest();
        //请求路径
        String actualPath = getUri(request.getRequestURI());
        //转发目标地址
        String targetLocation = getTargetLocation(request.getRequestURI());
        log.info("actualPath: {}",actualPath);
        log.info("targetLocation: {}",targetLocation);
        //登录请求和转发到授权认证服务的不需要过滤
        if(targetLocation.equals("vosung-auth-server") && (actualPath.equals("/oauth/token"))){
            return false;
        }
        //配置不需要走资源服务认证的------但是如果有authorization请求头，会先调check_token,所以配置的请求不要携带该请求头
        if(isPermitAllUrl(request.getRequestURI())){
            return false;
        }
        return true;
    }

    /**
     * 操作请求从客户端
     * （1）会先去我们CustomRemoteTokenServices重写的loadAuthentication，实现token的校验以及用户信息转换，
     * （2）而后在执行此过滤器。
     * 过滤器的具体逻辑----过滤之后就会根据路由转发具体的服务（授权认证/请求资源）
     * @return
     * @throws ZuulException
     */
    @Override
    public Object run() throws ZuulException {
        //通过请求上下文获取请求信息
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        log.info("send {} request to {}",request.getMethod(),request.getRequestURL().toString());
        String authorization = request.getHeader("Authorization");
        String url = request.getRequestURI();
        if (StringUtils.isNotEmpty(authorization)) {
            // 判断是否是jwt token，是的话就会请求对应服务，业务服务调对应拦截器（这里对用户信息封装，便于拦截器获取）
            if (isJwtBearerToken(authorization)) {
                try {
                    authorization = StringUtils.substringBetween(authorization, ".");
                    String decoded = new String(Base64.decodeBase64(authorization));
                    Map properties = new ObjectMapper().readValue(decoded, Map.class);
                    String userId = (String) properties.get(SecurityConstants.USER_ID_IN_HEADER);
                    String userName = (String)properties.get("user_name");
                    String roles = (String)properties.get("roles");
                    String isSuperAdmin = "false";
                    NamedParameterJdbcTemplate namedParameterJdbcTemplate = new NamedParameterJdbcTemplate(jdbcTemplate);
                    String sql = "select * from T_AU_ROLE where id in (:roles)";
                    Map<String,Object> paramMap = new HashMap<String, Object>();
                    paramMap.put("roles", Arrays.asList(roles.split(",")));
                    List<RoleVo> roleVoList = namedParameterJdbcTemplate.query(sql,paramMap,new RoleRowMapper());
                    for (RoleVo roleVo: roleVoList) {
                        //如果用户角色是系统管理员
                        if(roleVo.getRoleCode().equalsIgnoreCase(SYS_ADMIN)){
                            isSuperAdmin = "true";
                        }
                    }
                    if(userId != redisUtil.hget(USER_HOLDER,"userId")){
                        Map<String, Object> map = new HashMap<>();
                        map.put("userId",userId);
                        map.put("userName",userName);
                        map.put("roles",roles);
                        map.put("isSuperAdmin",isSuperAdmin);
                        redisUtil.hmset(USER_HOLDER,map);
                    }
                    //将用户信息封装到请求头中，后面可以在request中获取部分用户信息
                    ctx.addZuulRequestHeader("userId", userId);
                    ctx.addZuulRequestHeader("username", userName);
                    ctx.addZuulRequestHeader("roles", roles);
                } catch (Exception e) {
                    e.printStackTrace();
                    log.error("Failed to customize header for the request, but still release it as the it would be regarded without any user details.", e);
                }
            }
        } else {
            //错误的请求，塞一个假的用户信息id
            log.info("Regard this request as anonymous request, so set anonymous user_id in the header.");
            RequestContext.getCurrentContext().addZuulRequestHeader(SecurityConstants.USER_ID_IN_HEADER, ANONYMOUS_USER_ID);
            //过滤该请求，不进行路由
            ctx.setSendZuulResponse(false);
            //设置状态返回码
            ctx.setResponseStatusCode(401);
            ctx.getResponse().setCharacterEncoding("utf-8");
            ctx.setResponseBody("您无权访问！");
        }
        log.info("access is ok");
        return null;
    }

    /**
     * 验证token需要修改（缓存验证）----check_token 那边会调用我们实现的方法，做相关的redis缓存校验
     * @param token
     * @return
     */
    private boolean isJwtBearerToken(String token) {
        return StringUtils.countMatches(token, ".") == 2 && (token.startsWith("Bearer") || token.startsWith("bearer"));
    }

    //获取请求转发路径path
    private String getUri(String requestUri) {
        Route route = simpleRouteLocator.getMatchingRoute(requestUri);
        return route.getPath();
    }
    //获取路由转发对应的服务名
    private String getTargetLocation(String requestUri) {
        Route route = simpleRouteLocator.getMatchingRoute(requestUri);
        return route.getLocation();
    }

    private boolean isPermitAllUrl(String url) {
        return permitAllUrlProperties.isPermitAllUrl(url);
    }

    /**
     * 点位表字段和值对象映射关系
     */
    public class RoleRowMapper implements RowMapper<RoleVo> {
        @Override
        public RoleVo mapRow(ResultSet resultSet, int i) throws SQLException {
            RoleVo roleVo = new RoleVo();
            roleVo.setId(resultSet.getInt("id"));
            roleVo.setRoleCode(resultSet.getString("role_code"));
            roleVo.setRoleName(resultSet.getString("role_name"));
            return roleVo;
        }
    }
}
