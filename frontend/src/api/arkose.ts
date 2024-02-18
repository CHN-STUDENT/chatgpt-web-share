import axios from 'axios';

import ApiUrl from './url';

export function getArkoseInfo() {
  return axios.get<{ enabled: boolean, url: string, data: string, object: string }>(ApiUrl.ArkoseInfo);
}
export function getCurrentUrlWithApiPath(): string {
  // 获取当前URL的组成部分
  const protocol = window.location.protocol; // 协议 (例如, 'http:' 或 'https:')
  const hostname = window.location.hostname; // 主机名
  const port = window.location.port; // 端口号
  const pathname = "/api"; // 设定的API路径

  // 判断是否需要包含端口号
  let url = `${protocol}//${hostname}`;
  if (port) {
    url += `:${port}`;
  }
  url += pathname;

  return url;
}