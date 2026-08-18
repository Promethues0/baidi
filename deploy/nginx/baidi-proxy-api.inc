# 管理 API 反代的公共片段（回环；保留 /api 前缀；透传 Bearer）。
#
# ★抽成 include 是因为登录端点要单独挂 limit_req，而 nginx 的 location 不继承
# 兄弟 location 的 proxy_* 指令——三条登录 location 各抄一遍 proxy 配置的话，
# 迟早出现「改了 /api/ 的超时、登录那条还是旧值」这种只在登录路径上出现的偏差。
proxy_pass http://127.0.0.1:@CONTROL_PORT@;
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header Authorization $http_authorization;
proxy_set_header Connection "";
proxy_read_timeout 3600s;
