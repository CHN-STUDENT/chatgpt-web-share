import re
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import json
from fastapi import APIRouter, Depends, Response, Request

from api.conf import Config, Credentials
from api.exceptions import ResourceNotFoundException, ArkoseForwardException, InvalidRequestException
from api.models.db import User
from api.response import handle_arkose_forward_exception
from api.sources import OpenaiWebChatManager
from api.users import current_active_user

config = Config()
router = APIRouter()
openai_web_manager = OpenaiWebChatManager()
credentials = Credentials()
blob_data = None
blob_object = None


def extract_origin(referer):
    parsed_url = urlparse(referer)

    scheme = parsed_url.scheme
    hostname = parsed_url.hostname
    port = parsed_url.port

    if port is None or port == 80 or port == 443:
        origin = f"{scheme}://{hostname}"
    else:
        origin = f"{scheme}://{hostname}:{port}"

    return origin


def modify_challenge_url_cdn(content: bytes):
    global blob_data
    global blob_object
    try:
        data = json.loads(content)
        # 检查是否同时存在object和data字段
        if "object" in data and "data" in data:
            blob_data = None
            blob_data = data["data"]  # 提取data字段的值
            blob_object = None
            blob_object = data["object"]  
        if "challenge_url_cdn" in data:
            data["challenge_url_cdn"] = "/api/arkose/p" + data["challenge_url_cdn"]
            modified_content = json.dumps(data).encode()  # 更新content
        else:
            modified_content = content  # 保持content不变
    except json.JSONDecodeError:
        modified_content = content  # 如果解析失败，保持content不变

    # 返回修改后的content和提取的data值
    return modified_content


def modify_fc_gt2_url(content: bytes):
    """
    这会导致 enforcement.x.html 中 script 标签的 integrity 校验失败
    """
    text = content.decode()
    if '"/fc/gt2/public_key/"' in text:
        text = text.replace('"/fc/gt2/public_key/"', '"/api/arkose/p/fc/gt2/public_key/"')
        return text.encode()
    return content


async def forward_arkose_request(request: Request, path: str):
    """
    将 /arkose/p/ 和 /api/arkose/p/ 请求转发至 ninja
    """
    global blob_data
    global blob_object
    method = request.method
    # 复制原请求headers，排除掉一些不应该透传的headers
    headers = {key: value for key, value in request.headers.items() if key.lower() not in ['host', 'content-length']}

    referer = request.headers.get("referer")
    origin = request.headers.get("origin")

    # if referer and "/arkose/p/" in referer:
    #     referer_path = referer.split("/arkose/p/", maxsplit=1)[1]
    #     referer = f"{config.openai_web.arkose_endpoint_base}{referer_path}"
    #     origin = extract_origin(referer)
    if not referer:
        referer = f"{config.openai_web.arkose_endpoint_base}"

    # 检查是否有cookie，如果有，则处理并添加到headers中
    cookie = request.headers.get("cookie")
    if cookie:
        # 将cookie字符串分解为一个cookie字典
        cookies = dict(item.split("=", 1) for item in cookie.split("; "))
        # 移除名为 cws_user_auth 的cookie
        cookies.pop("cws_user_auth", None)
        # 重新构建cookie字符串
        modified_cookie = "; ".join([f"{key}={value}" for key, value in cookies.items()])
        # 如果修改后的cookie字符串不为空，则添加到headers中
        if modified_cookie:
            headers["cookie"] = modified_cookie

    headers["referer"] = referer
    if origin:
        headers["origin"] = origin

    headers = {k: v for k, v in headers.items() if v is not None}
    data_bytes = await request.body()
    modified_data_bytes = data_bytes
    if re.match(r'fc/gt2/public_key/.*', path) and blob_data is not None:
        # 解析原始请求体
        body_data = parse_qs(data_bytes.decode('utf-8'))
        # 在原始数据中添加data值
        body_data['data[blob]'] = blob_data.encode('utf-8')
        # 将修改后的数据编码回x-www-form-urlencoded格式
        modified_data_bytes = urlencode(body_data, doseq=True).encode('utf-8')
        headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
        blob_data = None
        blob_object = None
    try:
        request_to_send = httpx.Request(method, f"{config.openai_web.arkose_endpoint_base}{path}", headers=headers,
                                        content=modified_data_bytes, params=dict(request.query_params))
        async with httpx.AsyncClient() as client:
            resp = await client.send(request_to_send)
        resp.raise_for_status()
        headers = dict(resp.headers)
        headers.pop("content-encoding", None)
        headers.pop("transfer-encoding", None)
        headers.pop("content-length", None)

        resp_content_type = resp.headers.get("content-type")
        content = resp.content
        if resp_content_type and resp_content_type == "application/json":
            content = modify_challenge_url_cdn(resp.content)
        # 处理 /fc/a/?callback=, /fc/a/?callback 的 jsonp 不需要包装, 下面这部分就不要了
        # elif resp_content_type and resp_content_type == "application/javascript":
            # callback_name = request.query_params.get('callback')
            # if callback_name:
                # content = f'{callback_name}({content.decode("utf-8")});'.encode('utf-8')
                # 设置正确的内容类型
            #    headers['Content-Type'] = 'application/javascript'
            # 这部分应该不需要了，由前端加载 fc_gc2_url，不需要重写
            # content = modify_fc_gt2_url(resp.content)
        return Response(content=content, headers=headers, status_code=200)
    except httpx.HTTPStatusError as e:
        e = ArkoseForwardException(code=e.response.status_code, message=e.response.text)
        return handle_arkose_forward_exception(e)

# 由于无法代理全部路径，后端代理 ninja 方案作废，必须 ninja 进行公网映射。
# router.add_api_route("/arkose/p/{path:path}", forward_arkose_request, methods=["GET", "POST"])
# router.add_api_route("/api/arkose/p/{path:path}", forward_arkose_request, methods=["GET", "POST"])


@router.get("/arkose/info", tags=["arkose"])
async def get_arkose_info(request: Request, _user: User = Depends(current_active_user)):
    global blob_data
    global blob_object
    # 复制原请求headers，排除掉一些不应该透传的headers
    headers = {key: value for key, value in request.headers.items() if key.lower() not in ['host', 'content-length']}
    referer = request.headers.get("referer")
    origin = request.headers.get("origin")

    headers["referer"] = referer
    if origin:
        headers["origin"] = origin
    headers["Authorization"] = f"Bearer {credentials.openai_web_access_token}"

    # 删除不必要的头部信息
    headers.pop('accept-encoding', None)
    headers.pop('content-length', None)

    headers = {k: v for k, v in headers.items() if v is not None}

    async with httpx.AsyncClient() as client:
        {config.openai_web.chatgpt_base_url}
        response = await client.post(f"{config.openai_web.chatgpt_base_url}sentinel/arkose/dx", headers=headers)
    # print(response.json())
    # 检查请求是否成功
    if response.status_code == 200:
        response_data = response.json()
        # 尝试获取data和object，如果不存在则保持为空字符串
        blob_data = response_data.get("data", "")
        blob_object = response_data.get("object", "")

    # 返回包含data和object的信息
    return {
        "enabled": config.openai_web.enable_arkose_endpoint,
        "url": f"{config.openai_web.arkose_endpoint_base}v2/35536E1E-65B4-4D96-9D97-6ADB7EFF8147/api.js",
        "data": blob_data,
        "object": blob_object
    }
