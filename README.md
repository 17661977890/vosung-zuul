# vosung-zuul

网关：（spring cloud zuul）

已实现网关功能：
    过滤 转发（根据服务） 重试机制  熔断处理 负载均衡 回退处理
待实现：
   高可用（注册到eureka，部署多个zuul服务节点） 限流 

其中鉴权中心是和zuul整合在一起充当门面设计，zuul判断哪些服务需要token哪些不需要。
此项目为业务网关同时也是资源服务器，通过配置AuthorizeConfigProvider实现具体鉴权或放权功能。

配置网关过滤器：filter，过滤请求
配置资源服务器：用户请求资源，进行拦截->token校验->组装用户信息返回